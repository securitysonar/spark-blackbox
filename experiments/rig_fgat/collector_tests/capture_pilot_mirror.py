#!/usr/bin/env python3
"""Capture the operational mirror for the pilot journals with real tcpdump.

Replays both pilot journals (event schema) through the collector with
--udp-mirror 127.0.0.1:9999 while tcpdump captures loopback. The pcap is the
dissector's Volume 2 test fixture (wireshark/fgat_pilot_operational.pcap):
real frames, real headers, payloads byte-identical to the operational file.

tcpdump needs root: run from a shell where sudo is authenticated (sudo -v).

Usage (on the Spark):
  sudo -v && python3 capture_pilot_mirror.py --collector DIR/collector_daemon.py --runs runs --out results/
"""
import argparse
import getpass
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

SESSIONS = ["bbx-smoke-V2A-781a4c", "bbx-V2A-af0fa0"]
PORT = 9999
CAPTURE_SECONDS = 15


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    out = os.path.join(os.path.abspath(a.out), "pilot-mirror")
    os.makedirs(out, exist_ok=False)
    pcap = os.path.join(out, "fgat_pilot_operational.pcap")
    log = open(os.path.join(out, "transcript.txt"), "w", encoding="utf-8")

    def say(*parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        log.write(line + "\n")
        log.flush()

    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        sys.exit("sudo is not authenticated; run sudo -v first")
    sys.path.insert(0, os.path.dirname(os.path.abspath(a.collector)))
    from collector_daemon import content_refs  # noqa: E402
    from fgat_client import FgatClient  # noqa: E402

    sha = subprocess.run(["sha256sum", a.collector], capture_output=True, text=True).stdout
    say(f"# Pilot mirror capture — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say("collector:", sha.strip())

    cap = subprocess.Popen(["sudo", "-n", "timeout", "-s", "INT", str(CAPTURE_SECONDS),
                            "tcpdump", "-i", "lo", "-nn", "-s0", "-U", "-Z", getpass.getuser(),
                            "-w", pcap, "udp", "port", str(PORT)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1.5)

    work = tempfile.mkdtemp(prefix="bbx-mirror-")
    sock = os.path.join(work, "events.sock")
    worm = os.path.join(work, "worm", "audit_journal.jsonl")
    oper = os.path.join(work, "operational.jsonl")
    coll = subprocess.Popen([sys.executable, a.collector, "--socket", sock, "--worm", worm,
                             "--operational", oper, "--udp-mirror", f"127.0.0.1:{PORT}"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    time.sleep(0.3)
    c = FgatClient(sock, os.path.join(work, "blobs.sock"))
    for sid in SESSIONS:
        d = os.path.join(a.runs, sid)
        with open(os.path.join(d, "journal.jsonl"), encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        for r in recs:
            for _, h in content_refs(r):
                with open(os.path.join(d, "store", h), "rb") as bf:
                    c.put(bf.read())
            c.emit(r)
            time.sleep(0.01)
        say(f"{sid}: {len(recs)} records replayed")
    c.close()
    time.sleep(1.0)
    coll.send_signal(signal.SIGTERM)
    coll.communicate(timeout=10)
    _, cerr = cap.communicate(timeout=CAPTURE_SECONDS + 10)
    say("tcpdump:", " | ".join(l for l in cerr.strip().splitlines() if l))

    shutil.copy(oper, os.path.join(out, "operational.jsonl"))
    with open(oper, encoding="utf-8") as f:
        n_ops = sum(1 for l in f if l.strip())
    say("operational events:", n_ops)
    say("pcap:", pcap, os.path.getsize(pcap), "bytes")
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
