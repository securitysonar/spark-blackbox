#!/usr/bin/env python3
"""Per-session preflight (lab checklist step 5). Exits non-zero if any check fails.

Run before every session, baseline or instrumented. Needs no root: each check
looks for the effect, not the configuration where it can.

  1. sandbox_check.py passes every probe (containment, listener reachable,
     host sshd and Ollama unreachable from bbx-net).
  2. Ollama listens on loopback only.
  3. No tool containers left over from earlier sessions (each trial starts fresh).
  4. auditd is recording the tool UID: sandbox_check's own probes, which exec
     and connect as uid 2000, appear in the audit log under the bbx-tools and
     bbx-connect keys during the check.
  5. (--instrumented) the campaign collector is running and answers, and the
     evidence is append-only.
  6. (--instrumented) tcpdump is capturing udp port 9999 on lo, with at least
     --min-capture-minutes left before its timeout.

The fresh workdir, fresh container, and docker diff baseline are taken by the
trial runner itself for each session (meta.json: workdir, sandbox).

Usage (on the Spark):
  python3 preflight.py --rig ~/code/rig-harness-eval/rig.py --instrumented --out campaign/preflight
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in (os.path.join(HERE, "..", "..", "collector"), os.path.join(HERE, "collector")):
    if os.path.exists(os.path.join(_d, "fgat_client.py")):
        sys.path.insert(0, os.path.abspath(_d))
        break

AUDIT_LOG = "/var/log/audit/audit.log"
AUDIT_TS = re.compile(r"msg=audit\((\d+\.\d+):\d+\).*key=\"?([\w-]+)")


def sh(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def audit_keys_between(t0, t1):
    seen = {}
    try:
        with open(AUDIT_LOG, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = AUDIT_TS.search(line)
                if m and t0 <= float(m.group(1)) <= t1:
                    seen[m.group(2)] = seen.get(m.group(2), 0) + 1
    except OSError as e:
        return None, str(e)
    return seen, None


def duration_s(spec):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", spec)
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)] if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rig", required=True)
    ap.add_argument("--instrumented", action="store_true")
    ap.add_argument("--campaign", default=os.path.join(HERE, "campaign"))
    ap.add_argument("--min-capture-minutes", type=float, default=30)
    ap.add_argument("--out", required=True, help="directory for the report")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    checks = []

    def check(name, ok, detail):
        checks.append({"check": name, "pass": bool(ok), "detail": detail})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    # 1 + 4: sandbox_check, timed so its uid-2000 activity can be found in the audit log
    t0 = time.time()
    sc_out = os.path.join(a.out, f"sandbox_check-{stamp}.json")
    rc, out, err = sh(f"{sys.executable} {os.path.join(HERE, 'sandbox', 'sandbox_check.py')} "
                      f"--rig {a.rig} --out {sc_out}")
    t1 = time.time()
    summary = out.splitlines()[-1] if out else err[-200:]
    check("sandbox_check", rc == 0, summary)

    time.sleep(1)  # let auditd flush
    seen, aerr = audit_keys_between(t0, t1 + 1)
    if seen is None:
        check("auditd recording uid 2000", False, f"cannot read {AUDIT_LOG}: {aerr}")
    else:
        for key in ("bbx-tools", "bbx-connect"):
            check(f"auditd key {key}", seen.get(key, 0) > 0,
                  f"{seen.get(key, 0)} events during sandbox_check")

    # 2: Ollama on loopback only
    rc, out, _ = sh("ss -ltnH 'sport = :11434'")
    addrs = [l.split()[3].rsplit(":", 1)[0] for l in out.splitlines() if l.strip()]
    check("Ollama loopback only", addrs and all(x in ("127.0.0.1", "[::1]") for x in addrs),
          f"listening on {addrs or 'nothing'}")

    # 3: no leftover tool containers
    rc, out, _ = sh("docker ps -a --filter name=bbx-tools- --filter name=bbx-check- --format '{{.Names}}'")
    left = [n for n in out.splitlines() if n]
    check("no leftover tool containers", not left, ", ".join(left) or "none")

    if a.instrumented:
        # 5: collector up, answering, evidence sealed
        run, ev = os.path.join(a.campaign, "run"), os.path.join(a.campaign, "evidence")
        try:
            from fgat_client import FgatClient
            c = FgatClient(os.path.join(run, "events.sock"))
            c.put("")
            c.close()
            check("campaign collector answers", True, f"blob socket in {run}")
        except Exception as e:
            check("campaign collector answers", False, str(e))
        paths = [os.path.join(ev, p) for p in ("audit_journal.jsonl", "operational.jsonl", "rejected.jsonl", "store")]
        rc, out, err = sh("lsattr -d " + " ".join(paths))
        flags = {l.split()[1]: l.split()[0] for l in out.splitlines() if l.strip()}
        unsealed = [os.path.basename(p) for p in paths if "a" not in flags.get(p, "")]
        check("evidence append-only", rc == 0 and not unsealed, "all sealed" if not unsealed else f"not sealed: {unsealed}")

        # 6: tcpdump capturing the mirror, with time left
        # Match the tcpdump process itself (by name), not a sudo/timeout wrapper
        # whose command line also mentions tcpdump.
        rc, out, _ = sh("ps -C tcpdump -o pid=,ppid=,etimes=,args=")
        cap_ok, detail = False, "no tcpdump capturing udp port 9999 on lo"
        for line in out.splitlines():
            pid, ppid, _, args = line.split(None, 3)
            if " -i lo " not in args or "udp port 9999" not in args or " -w " not in args:
                continue
            rc2, parent, _ = sh(f"ps -o etimes=,args= -p {ppid}")
            m = re.search(r"timeout\s+(?:-\S+\s+)*(\S+)\s+tcpdump", parent)
            if not m:
                cap_ok, detail = True, f"pid {pid}, no timeout"
                break
            total = duration_s(m.group(1))
            left_min = (total - float(parent.split()[0])) / 60 if total else 0
            cap_ok = left_min >= a.min_capture_minutes
            detail = f"pid {pid}, {left_min:.0f} min left (need {a.min_capture_minutes:.0f})"
            break
        check("tcpdump capturing udp 9999", cap_ok, detail)

    failed = [c["check"] for c in checks if not c["pass"]]
    report = {"ts": time.time(), "instrumented": a.instrumented, "checks": checks,
              "sandbox_check_report": sc_out, "failed": failed}
    path = os.path.join(a.out, f"preflight-{stamp}.json")
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"{len(checks) - len(failed)}/{len(checks)} passed; report: {path}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
