#!/usr/bin/env python3
"""Fix 2 tests: records carry hashes; content lives in the collector's store.

Run against the unmodified collector ("before") and the fixed one ("after") with
the same script. Everything is written to --out verbatim.

S1  A record with ~100 KB of tool output inline (the original design put full
    stdout and context in the record). Before: the collector reads 65,535 bytes
    of it. After: rejected for size, and logged.
S2  (after) The same output put in the store, record carries its hash: chained,
    record stays small, object stored under its SHA-256.
S3  (after) A record referencing a hash the collector never stored: rejected.
S4  (after) A tool container (BBX_TOOL_UID) connects to the blob socket:
    refused by file mode (0660); with the mode relaxed to 0666, rejected by the
    collector's SO_PEERCRED check.
S5  (after) verify --store: passes; fails after one byte of a stored object is
    changed; fails after an object is deleted.

Usage (on the Spark):
  python3 fix2_store.py --collector /path/to/collector_daemon.py --label after --out results/
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

OUTPUT_BYTES = 100_000
BIG_BYTES = 1_000_000


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--image", default=os.environ.get("BBX_TOOLS_IMAGE", "bbx-tools:2"))
    ap.add_argument("--tool-uid", default=os.environ.get("BBX_TOOL_UID", "2000"))
    a = ap.parse_args()

    out = os.path.join(os.path.abspath(a.out), "fix2-" + a.label)
    os.makedirs(out, exist_ok=False)
    log = open(os.path.join(out, "transcript.txt"), "w", encoding="utf-8")

    def say(*parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        log.write(line + "\n")
        log.flush()

    rc, helptext, _ = run([sys.executable, a.collector, "--help"])
    fixed = "--store" in helptext
    if fixed:
        sys.path.insert(0, os.path.dirname(os.path.abspath(a.collector)))
        from fgat_client import FgatClient, RecorderError  # noqa: E402

    work = tempfile.mkdtemp(prefix="bbx-fix2-")
    sock_dir = os.path.join(work, "agent-journal")
    os.makedirs(sock_dir)
    os.chmod(sock_dir, 0o755)
    sock_path = os.path.join(sock_dir, "events.sock")
    blob_path = os.path.join(sock_dir, "blobs.sock")
    worm = os.path.join(work, "worm", "audit_journal.jsonl")
    oper = os.path.join(work, "operational", "events.jsonl")
    store = os.path.join(work, "worm", "store")

    say(f"# Fix 2 {a.label} — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    rc, sha_out, _ = run(["sha256sum", a.collector])
    say("collector:", sha_out.strip(), " fixed:", fixed)

    cmd = [sys.executable, a.collector, "--socket", sock_path, "--worm", worm, "--operational", oper]
    coll = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        if os.path.exists(sock_path):
            break
        time.sleep(0.1)
    time.sleep(0.3)

    sid = "bbx-fix2-test"
    output = ("x" * 79 + "\n") * (OUTPUT_BYTES // 80)  # stand-in for a long pytest/stdout result
    results = {}

    # S1: inline content, as the original design did.
    say("\n## S1 record with ~100 KB of tool output inline")
    rec = {"session_id": sid, "turn_id": 1, "kind": "result", "tool": "run",
           "args": {"command": "pytest -q"}, "result": output}
    data = json.dumps(rec).encode("utf-8")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        n = s.sendto(data, sock_path)
        say(f"sendto accepted {n} of {len(data)} bytes")
    except OSError as e:
        say("sendto failed:", e)
    s.close()
    time.sleep(0.5)

    if fixed:
        client = FgatClient(sock_path, blob_path)

        say("\n## S2 same output via the store; record carries the hash")
        h = client.put(output)
        say("put returned", h, "local sha256", hashlib.sha256(output.encode()).hexdigest())
        big = os.urandom(BIG_BYTES // 2).hex()
        hb = client.put(big)
        say(f"put {len(big)} bytes returned", hb)
        r2 = {"session_id": sid, "turn_id": 2, "kind": "result", "tool": "run",
              "args": {"command": "pytest -q"}, "result_sha256": h, "result_bytes": len(output)}
        r3 = {"session_id": sid, "turn_id": 3, "kind": "result", "tool": "read_file",
              "args": {"path": "data/large.bin"}, "result_sha256": hb, "result_bytes": len(big)}
        say("record bytes sent:", client.emit(r2), "and", client.emit(r3))
        time.sleep(0.5)

        say("\n## S3 record referencing content the collector never stored")
        fake = hashlib.sha256(b"never stored").hexdigest()
        r4 = {"session_id": sid, "turn_id": 4, "kind": "result", "tool": "run",
              "args": {"command": "echo"}, "result_sha256": fake, "result_bytes": 12}
        say("record bytes sent:", client.emit(r4), "(reference", fake + ")")
        try:
            client.emit({"session_id": sid, "turn_id": 5, "result": output})
        except RecorderError as e:
            say("client refused oversize record locally:", e)
        time.sleep(0.5)
        client.close()

        say("\n## S4 tool container connects to the blob socket")
        sender = ("import socket,struct,os,sys\n"
                  "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(5)\n"
                  "s.connect('/run/agent-journal/blobs.sock')\n"
                  "b=b'forged content from the tool sandbox'\n"
                  "try:\n"
                  "    s.sendall(struct.pack('>Q',len(b))+b); r=s.recv(100)\n"
                  "except OSError as e:\n"
                  "    r=repr(e).encode()\n"
                  "print('container uid',os.getuid(),'reply',r)\n")
        dcmd = ["docker", "run", "--rm", "--network", "none", "--user", f"{a.tool_uid}:{a.tool_uid}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-v", f"{sock_dir}:/run/agent-journal", a.image, "python3", "-c", sender]
        for mode in (None, 0o666):
            if mode:
                os.chmod(blob_path, mode)
            say("blob socket mode:", oct(os.stat(blob_path).st_mode & 0o777))
            rc, so, se = run(dcmd)
            say("container exit:", rc, "stdout:", so.strip())
            if se.strip():
                say("container stderr:", se.strip().splitlines()[-1])
            time.sleep(0.5)

    coll.send_signal(signal.SIGTERM)
    try:
        coll_out = coll.communicate(timeout=10)[0]
    except subprocess.TimeoutExpired:
        coll.kill()
        coll_out = coll.communicate()[0]
    say("\ncollector output:\n" + coll_out.rstrip())

    lines = []
    if os.path.exists(worm):
        shutil.copy(worm, os.path.join(out, "journal.jsonl"))
        with open(worm, encoding="utf-8") as f:
            lines = [l for l in f.read().splitlines() if l.strip()]
    say(f"\njournal records: {len(lines)}")
    for i, l in enumerate(lines):
        r = json.loads(l)
        say(f"  line {i + 1}: turn {r.get('turn_id')}, {len(l.encode())} bytes, "
            f"inline result: {'result' in r}, result_sha256: {r.get('result_sha256')}")
    rejects = os.path.join(os.path.dirname(worm), "rejected.jsonl")
    if os.path.exists(rejects):
        shutil.copy(rejects, os.path.join(out, "rejected.jsonl"))
        with open(rejects, encoding="utf-8") as f:
            rej = [l for l in f.read().splitlines() if l.strip()]
        say(f"rejected: {len(rej)}")
        for l in rej:
            say("  " + l)
    results["journal_records"] = len(lines)
    results["s1_inline_record_in_journal"] = any(json.loads(l).get("turn_id") == 1 for l in lines)

    if fixed:
        objs = sorted(os.listdir(store))
        say(f"store objects: {len(objs)}")
        for o in objs:
            p = os.path.join(store, o)
            say(f"  {o}  {os.path.getsize(p)} bytes  mode {oct(os.stat(p).st_mode & 0o777)}")
        shutil.copytree(store, os.path.join(out, "store"))

        say("\n## S5 verify --store")
        vcmd = [sys.executable, a.collector, "--verify", "--worm", worm, "--store", store]
        rc0, so, se = run(vcmd)
        say("verify (intact) exit:", rc0)
        say((so + se).rstrip())
        target = os.path.join(store, h)
        os.chmod(target, 0o640)
        with open(target, "r+b") as f:
            f.seek(100)
            b = f.read(1)
            f.seek(100)
            f.write(b"Y" if b != b"Y" else b"Z")
        rc1, so, se = run(vcmd)
        say("verify (one byte of a stored object changed) exit:", rc1)
        say((so + se).rstrip())
        os.remove(target)
        rc2, so, se = run(vcmd)
        say("verify (stored object deleted) exit:", rc2)
        say((so + se).rstrip())
        results.update({"s2_record_bytes": [len(l.encode()) for l in lines],
                        "verify_intact": rc0, "verify_object_edited": rc1, "verify_object_deleted": rc2})

    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump({"label": a.label, "collector_sha256": sha_out.split()[0], "fixed": fixed, **results}, f, indent=2)
    say("\nsummary:", json.dumps(results))
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
