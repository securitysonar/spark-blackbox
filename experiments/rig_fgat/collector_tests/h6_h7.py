#!/usr/bin/env python3
"""H6 (forgery) and H7 (byte edit) tests against an FGAT collector.

Run once against the unmodified collector ("before") and again after the
collector fixes ("after"), with the same script, so the two outputs compare
directly. Everything is written to --out verbatim.

H6: start the collector on temp paths, send three records from the host (the
    harness's position), then send one forged record from inside a tool
    container (bbx-tools image, same flags as sandbox/sandbox.py) that has the
    socket's directory mounted. Question: is the forged record accepted and
    chained? The trial sandbox does not mount the socket; this test gives the
    container access on purpose, to show what happens if a tool can reach it.

H7: copy the resulting journal, change one byte in one record's payload (not
    the _chain fields), and run the collector's own `--verify` on the copy.
    Question: does the verifier pass the edited journal?

Usage (on the Spark):
  python3 h6_h7.py --collector /path/to/collector_daemon.py --label before --out results/
"""
import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

IMAGE = os.environ.get("BBX_TOOLS_IMAGE", "bbx-tools:1")
FORGED_MARKER = "H6-FORGED-RECORD"


def record(session, turn, name, params, status, exit_code):
    return {"session_id": session, "turn_id": turn,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "proposed_action": {"name": name, "parameters": params},
            "gate_verdict": {"status": status, "rule_id": "test"},
            "execution_result": {"exit_code": exit_code}}


def send_host(sock_path, rec):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.sendto(json.dumps(rec).encode("utf-8"), sock_path)
    finally:
        s.close()


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", required=True)
    ap.add_argument("--label", required=True, help="before | after")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    out = os.path.join(os.path.abspath(a.out), a.label)
    os.makedirs(out, exist_ok=False)
    log = open(os.path.join(out, "transcript.txt"), "w", encoding="utf-8")

    def say(*parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        log.write(line + "\n")
        log.flush()

    work = tempfile.mkdtemp(prefix="bbx-h6h7-")
    sock_dir = os.path.join(work, "agent-journal")
    os.makedirs(sock_dir)
    os.chmod(sock_dir, 0o755)
    sock_path = os.path.join(sock_dir, "events.sock")
    worm = os.path.join(work, "worm", "audit_journal.jsonl")
    oper = os.path.join(work, "operational", "events.jsonl")

    say(f"# H6/H7 {a.label} — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    rc, sha_out, _ = run(["sha256sum", a.collector])
    say("collector:", sha_out.strip())
    rc, img, _ = run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE])
    say("image:", IMAGE, img.strip())
    say("host uid:", os.getuid())

    coll = subprocess.Popen([sys.executable, a.collector, "--socket", sock_path,
                             "--worm", worm, "--operational", oper],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        if os.path.exists(sock_path):
            break
        time.sleep(0.1)
    else:
        coll.kill()
        say("collector socket never appeared; collector output:", coll.communicate()[0])
        sys.exit(2)
    say("socket mode:", oct(os.stat(sock_path).st_mode & 0o777))

    # Three records from the harness position (host, uid of the harness).
    sid = "bbx-h6h7-test"
    send_host(sock_path, record(sid, 1, "read_file", {"path": "docs/internals/architecture.md"}, "allow", 0))
    send_host(sock_path, record(sid, 2, "run_shell", {"cmd": "pytest -q"}, "allow", 0))
    send_host(sock_path, record(sid, 3, "update_progress", {"notes": "audit in progress"}, "allow", 0))
    time.sleep(0.5)

    # H6: forged record from inside a tool container with the socket dir mounted.
    forged = record(sid, 4, "update_progress", {"notes": FORGED_MARKER}, "allow", 0)
    forged["note"] = "sent from inside the tool container"
    sender = ("import json,socket,sys,os; r=json.loads(sys.argv[1]); "
              "s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); "
              "n=s.sendto(json.dumps(r).encode(),'/run/agent-journal/events.sock'); "
              "print('container uid',os.getuid(),'sent',n,'bytes')")
    cmd = ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "-v", f"{sock_dir}:/run/agent-journal", IMAGE,
           "python3", "-c", sender, json.dumps(forged)]
    say("\n## H6 forgery")
    say("container command:", " ".join(cmd[:-1]), "'<forged record JSON>'")
    rc, so, se = run(cmd)
    say("container exit:", rc)
    say("container stdout:", so.strip())
    if se.strip():
        say("container stderr:", se.strip())
    time.sleep(1.0)

    coll.send_signal(signal.SIGTERM)
    try:
        coll_out = coll.communicate(timeout=10)[0]
    except subprocess.TimeoutExpired:
        coll.kill()
        coll_out = coll.communicate()[0]
    say("collector output:\n" + coll_out.rstrip())

    shutil.copy(worm, os.path.join(out, "journal.jsonl"))
    shutil.copy(oper, os.path.join(out, "operational.jsonl"))
    with open(worm, encoding="utf-8") as f:
        lines = [l for l in f.read().splitlines() if l.strip()]
    say(f"journal records: {len(lines)}")
    forged_idx = [i for i, l in enumerate(lines) if FORGED_MARKER in l]
    h6_accepted = bool(forged_idx)
    h6_chained = False
    if forged_idx:
        i = forged_idx[0]
        rec_i = json.loads(lines[i])
        prev_block = json.loads(lines[i - 1])["_chain"]["block_hash"] if i > 0 else "0" * 64
        h6_chained = rec_i["_chain"]["prev_hash"] == prev_block
        say(f"forged record at line {i + 1}:")
        say(lines[i])
    rc, so, se = run([sys.executable, a.collector, "--verify", "--worm", worm])
    say("verify (unedited journal) exit:", rc)
    say((so + se).rstrip())
    h6_verify_rc = rc
    say(f"H6 RESULT: forged record accepted={h6_accepted} chained={h6_chained} "
        f"verifier_exit_on_journal_with_forgery={h6_verify_rc}")

    # H7: edit one byte in one record's payload, leave _chain alone.
    say("\n## H7 byte edit")
    target = 1  # line 2: the pytest record
    old = '"pytest -q"'
    new = '"pytesT -q"'
    edited = list(lines)
    if old not in edited[target]:
        say("expected text not found in line", target + 1)
        sys.exit(2)
    edited[target] = edited[target].replace(old, new, 1)
    edited_path = os.path.join(out, "journal_edited.jsonl")
    with open(edited_path, "w", encoding="utf-8") as f:
        f.write("\n".join(edited) + "\n")
    say(f"edited line {target + 1}: {old} -> {new} (one byte, payload field; _chain untouched)")
    rc, so, se = run(["cmp", "-l", os.path.join(out, "journal.jsonl"), edited_path])
    say("cmp -l (byte offset, octal old, octal new):", so.strip())
    rc, so, se = run([sys.executable, a.collector, "--verify", "--worm", edited_path])
    say("verify (edited journal) exit:", rc)
    say((so + se).rstrip())
    h7_passed = rc == 0
    say(f"H7 RESULT: verifier passed the edited journal={h7_passed}")

    summary = {"label": a.label, "collector_sha256": sha_out.split()[0] if sha_out else None,
               "image": img.strip(), "host_uid": os.getuid(),
               "h6": {"accepted": h6_accepted, "chained": h6_chained,
                      "verify_exit_with_forgery": h6_verify_rc},
               "h7": {"verifier_passed_edit": h7_passed}}
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    say("\nsummary:", json.dumps(summary))
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
