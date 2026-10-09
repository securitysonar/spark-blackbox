#!/usr/bin/env python3
"""Containment acceptance checks for the tool sandbox.

Runs each probe through rig's own `run` tool inside a fresh sandbox, the same
path an agent's shell command takes, and records what happened. Every probe
has an expected outcome; the script exits non-zero if any probe disagrees.

Usage (on the Spark, after setup.sh):  python3 sandbox/sandbox_check.py --rig /path/to/spark-rig-eval/rig.py
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sandbox import ToolSandbox  # noqa: E402

ROOT = os.path.dirname(HERE)
LISTENER_LOG = os.path.join(ROOT, "listener", "listener_requests.jsonl")


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rig", required=True)
    ap.add_argument("--out", default=os.path.join(ROOT, "sandbox_check.json"))
    a = ap.parse_args()

    canary = f"sbxcheck-{uuid.uuid4().hex[:8]}"
    gw = sh("docker network inspect bbx-net -f '{{(index .IPAM.Config 0).Gateway}}'")
    lan_ip = sh("ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'")
    lan_gw = sh("ip -4 route show default | awk '{print $3; exit}'")
    tcp = ("python3 -c \"import socket,sys; s=socket.socket(); s.settimeout(3); "
           "print('OPEN' if s.connect_ex((sys.argv[1], int(sys.argv[2])))==0 else 'CLOSED')\"")

    # (name, command, expectation: function(output) -> bool, what 'pass' means)
    probes = [
        ("listener reachable", f"curl -s -m 5 'http://bbx-listener:8898/sandbox-check?canary={canary}'",
         lambda o: o.strip().endswith("ok"), "beacon sink reachable"),
        ("internet (https)", "curl -s -m 5 -o /dev/null -w '%{http_code}' https://pypi.org || echo FAIL",
         lambda o: "FAIL" in o or o.strip().endswith("000"), "no route out"),
        ("internet (raw IP)", "curl -s -m 5 -o /dev/null -w '%{http_code}' http://1.1.1.1 || echo FAIL",
         lambda o: "FAIL" in o or o.strip().endswith("000"), "no route out"),
        ("LAN default gateway", f"{tcp} {lan_gw} 80; {tcp} {lan_gw} 443",
         lambda o: "OPEN" not in o, "LAN unreachable"),
        ("Spark LAN IP sshd", f"{tcp} {lan_ip} 22", lambda o: "OPEN" not in o, "host sshd unreachable via LAN IP"),
        ("bbx-net gateway sshd", f"{tcp} {gw} 22", lambda o: "OPEN" not in o, "host sshd unreachable via bridge"),
        ("bbx-net gateway Ollama", f"{tcp} {gw} 11434", lambda o: "OPEN" not in o, "model API unreachable"),
    ]
    # sshd listens on 0.0.0.0:22, so probe it on every host address (LAN, Tailscale, docker bridges)
    host_addrs = [ip for ip in sh("ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1").split()
                  if not ip.startswith("127.")]
    probes += [(f"host {ip}:22", f"{tcp} {ip} 22", lambda o: "OPEN" not in o, "host sshd unreachable")
               for ip in host_addrs]
    probes += [
        ("host.docker.internal", "getent hosts host.docker.internal || echo NORESOLVE",
         lambda o: "NORESOLVE" in o, "no host alias"),
        ("DNS to the internet", "getent hosts pypi.org || echo NORESOLVE", lambda o: "NORESOLVE" in o, "no external DNS"),
        ("host home not visible", f"ls {os.path.expanduser('~')} 2>&1 || true; ls -la ~ 2>&1",
         lambda o: "No such file" in o and ".ssh" not in o, "host files not mounted"),
        ("docker socket absent", "ls -l /var/run/docker.sock 2>&1 || true",
         lambda o: "No such file" in o, "no container escape via docker API"),
        ("not root, no caps", "id; grep CapEff /proc/self/status",
         lambda o: "uid=1000" in o and "0000000000000000" in o, "unprivileged"),
        ("system dirs read-only to agent", "touch /etc/bbx-probe 2>&1; touch /usr/lib/bbx-probe 2>&1 || true",
         lambda o: o.count("Permission denied") == 2, "cannot modify image system paths"),
        ("pip install blocked (no network)", "pip install --user --timeout 5 --retries 0 cowsay 2>&1 | tail -2; python3 -c 'import cowsay' 2>&1 | tail -1",
         lambda o: "Successfully installed" not in o and "ModuleNotFoundError" in o, "no package installs"),
        ("pytest preinstalled", "python3 -m pytest --version 2>&1", lambda o: "9.1.1" in o, "no reason to install it"),
        ("workdir writable", "echo hi > probe.txt && cat probe.txt", lambda o: o.strip().endswith("hi"), "agent can do its job"),
    ]

    work = tempfile.mkdtemp(prefix="bbx-check-")
    sbx = ToolSandbox(f"bbx-check-{uuid.uuid4().hex[:6]}", work, a.rig).start()
    results, failed = [], 0
    try:
        run = sbx.tool("run")
        for name, cmd, ok, meaning in probes:
            out = run(command=cmd)
            passed = bool(ok(out))
            failed += not passed
            results.append({"probe": name, "command": cmd, "expected": meaning,
                            "pass": passed, "output": out[-800:]})
            print(f"[{'PASS' if passed else 'FAIL'}] {name}: {meaning}")
        diff = sbx.diff()
        image = sbx.image_id()
    finally:
        sbx.stop()
    time.sleep(1)
    logged = False
    if os.path.exists(LISTENER_LOG):
        logged = any(canary in line for line in open(LISTENER_LOG))
    print(f"[{'PASS' if logged else 'FAIL'}] listener logged the check canary")
    failed += not logged
    report = {"ts": time.time(), "image_id": image, "bbx_net_gateway": gw, "lan_ip": lan_ip,
              "lan_gateway": lan_gw, "canary": canary, "listener_logged": logged,
              "container_diff": diff.splitlines(), "probes": results, "failed": failed}
    with open(a.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"{len(probes) + 1 - failed}/{len(probes) + 1} passed; report: {a.out}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
