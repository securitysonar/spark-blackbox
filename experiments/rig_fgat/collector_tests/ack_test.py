#!/usr/bin/env python3
"""Does the sender learn what happened to its record?

Run with a collector directory holding collector_daemon.py and fgat_client.py
("before": no replies, emit() returns bytes sent; "after": emit() returns the
block_hash or raises). Scenarios:

A1  accepted record: what emit() returns, and whether it matches the journal.
A2  record over the size limit (client-side check bypassed).
A3  record citing content the collector never stored.
A4  malformed payload (not JSON), sent on the client's own connection.
A5  collector stopped (SIGSTOP) while a record is sent; then resumed.
A6  (after) the next emit() after A5's timeout: not confused by A5's late reply.
A7  (after) a tool container (uid 2000) connects to the records socket: refused
    by file mode; with the mode relaxed to 0666, rejected with a reply.
A8  legacy datagram sender: record still chained, no reply.
A9  (after) a client that never reads its replies floods its connection; then
    a normal client emits: does the collector stall?
A10 collector not running: emit().

Usage (on the Spark):
  python3 ack_test.py --collector-dir DIR --label after --out results/
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector-dir", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--image", default=os.environ.get("BBX_TOOLS_IMAGE", "bbx-tools:2"))
    ap.add_argument("--tool-uid", default=os.environ.get("BBX_TOOL_UID", "2000"))
    a = ap.parse_args()

    cdir = os.path.abspath(a.collector_dir)
    collector = os.path.join(cdir, "collector_daemon.py")
    sys.path.insert(0, cdir)
    import fgat_client  # noqa: E402
    from fgat_client import FgatClient, RecorderError, canonical  # noqa: E402

    out = os.path.join(os.path.abspath(a.out), "ack-" + a.label)
    os.makedirs(out, exist_ok=False)
    log = open(os.path.join(out, "transcript.txt"), "w", encoding="utf-8")

    def say(*parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        log.write(line + "\n")
        log.flush()

    acks = "ack_timeout" in open(fgat_client.__file__).read()
    sha = lambda p: subprocess.run(["sha256sum", p], capture_output=True, text=True).stdout.split()[0]
    say(f"# Ack test {a.label} — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say("collector:", sha(collector), " client:", sha(fgat_client.__file__), " client waits for reply:", acks)

    work = tempfile.mkdtemp(prefix="bbx-ack-")
    os.chmod(work, 0o755)
    sock = os.path.join(work, "events.sock")
    blobs = os.path.join(work, "blobs.sock")
    worm = os.path.join(work, "worm", "audit_journal.jsonl")
    oper = os.path.join(work, "operational.jsonl")
    coll = subprocess.Popen([sys.executable, collector, "--socket", sock, "--worm", worm, "--operational", oper],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    time.sleep(0.3)

    kw = {"max_record_bytes": 1 << 20}
    if acks:
        kw["ack_timeout"] = 2.0
    c = FgatClient(sock, blobs, **kw)
    sid = "bbx-ack-test"
    res = {}

    def attempt(name, fn):
        t0 = time.monotonic()
        try:
            r = fn()
            dt = time.monotonic() - t0
            say(f"[{name}] returned {r!r} ({dt:.2f}s)")
            res[name] = {"returned": r, "seconds": round(dt, 2)}
            return r
        except RecorderError as e:
            dt = time.monotonic() - t0
            say(f"[{name}] RecorderError: {e} ({dt:.2f}s)")
            res[name] = {"raised": str(e), "seconds": round(dt, 2)}

    def rec(turn, **f):
        return {"session_id": sid, "seq": turn, "kind": "intent", "turn": turn, "ts": time.time(),
                "tool": "run", "args": {"command": "pytest -q"}, "classify": "allow",
                "branch": "classify_allow", "allowed": True, **f}

    say("\n## A1 accepted record")
    a1 = attempt("A1 accepted", lambda: c.emit(rec(1)))

    say("\n## A2 record over the size limit")
    attempt("A2 oversize", lambda: c.emit(rec(2, args={"content": "x" * 40000})))

    say("\n## A3 record citing content never stored")
    attempt("A3 unknown ref", lambda: c.emit(rec(3, result_sha256=hashlib.sha256(b"never stored").hexdigest())))

    say("\n## A4 malformed payload on the client's own connection")
    bad = b"not json at all"
    if acks:
        c._rec.send(bad)
        reply = c._rec.recv(4096).decode()
        say(f"[A4 malformed] reply: {reply}")
        res["A4 malformed"] = {"reply": reply}
    else:
        c._dgram.sendto(bad, sock)
        say("[A4 malformed] sent; this client has no way to receive a reply")
        res["A4 malformed"] = {"reply": "client cannot receive"}

    say("\n## A5 collector stopped while a record is sent")
    os.kill(coll.pid, signal.SIGSTOP)
    attempt("A5 collector stopped", lambda: c.emit(rec(5)))
    os.kill(coll.pid, signal.SIGCONT)
    time.sleep(1.0)

    if acks:
        say("\n## A6 next emit after the timeout")
        a6 = attempt("A6 next emit", lambda: c.emit(rec(6)))

        say("\n## A7 tool container connects to the records socket")
        recs_path = os.path.join(work, "records.sock")
        py = ("import socket\ns=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET); s.settimeout(5)\n"
              "try:\n    s.connect('/run/agent-journal/records.sock')\n"
              "    s.send(b'{\"session_id\":\"forged\",\"seq\":1,\"kind\":\"intent\",\"turn\":1}')\n"
              "    print('reply:', s.recv(4096).decode())\n"
              "except OSError as e:\n    print('failed:', e)\n")
        dcmd = ["docker", "run", "--rm", "--network", "none", "--user", f"{a.tool_uid}:{a.tool_uid}",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-v", f"{work}:/run/agent-journal", a.image, "python3", "-c", py]
        out7 = []
        for mode in (None, 0o666):
            if mode:
                os.chmod(recs_path, mode)
            p = subprocess.run(dcmd, capture_output=True, text=True)
            line = p.stdout.strip() or p.stderr.strip().splitlines()[-1]
            say(f"[A7 container, socket mode {oct(os.stat(recs_path).st_mode & 0o777)}] {line}")
            out7.append(line)
        os.chmod(recs_path, 0o660)
        res["A7 container"] = out7

    say("\n## A8 legacy datagram sender")
    raw = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    n = raw.sendto(canonical(rec(8)), sock)
    say(f"[A8 legacy] sendto returned {n}; no reply path")
    time.sleep(0.5)

    if acks:
        say("\n## A9 a client that never reads its replies")
        mute = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        mute.connect(os.path.join(work, "records.sock"))
        mute.setblocking(False)
        sent = 0
        t0 = time.monotonic()
        while time.monotonic() - t0 < 3.0 and sent < 2000:
            try:
                mute.send(canonical(rec(10000 + sent)))
                sent += 1
            except BlockingIOError:
                time.sleep(0.01)
        say(f"mute client sent {sent} records in 3s without reading replies "
            f"({'blocked by backpressure' if sent < 2000 else 'never blocked'})")
        res["A9 mute sent"] = sent
        attempt("A9 normal client during flood", lambda: FgatClient(sock, blobs, ack_timeout=5.0).emit(rec(9)))
        n_replies = 0
        mute.setblocking(True)
        mute.settimeout(1.0)
        try:
            while True:
                if not mute.recv(4096):
                    break
                n_replies += 1
        except socket.timeout:
            pass
        say(f"mute client then read {n_replies} replies")
        res["A9 mute replies read"] = n_replies
        mute.close()
        time.sleep(0.5)

    coll.send_signal(signal.SIGTERM)
    coll_out = coll.communicate(timeout=20)[0]

    say("\n## A10 collector not running")
    attempt("A10 no collector", lambda: c.emit(rec(10)))

    with open(worm, encoding="utf-8") as f:
        journal = [json.loads(l) for l in f if l.strip()]
    rej_path = os.path.join(os.path.dirname(worm), "rejected.jsonl")
    rejects = []
    if os.path.exists(rej_path):
        with open(rej_path, encoding="utf-8") as f:
            rejects = [json.loads(l) for l in f if l.strip()]
    seqs = [r.get("seq") for r in journal]
    say(f"\njournal: {len(journal)} records; seqs (first 10): {seqs[:10]}; rejected: {len(rejects)}")
    for r in rejects:
        say("  rejected:", r["reason"][:100])
    if isinstance(a1, str) and len(a1) == 64:
        match = journal[0]["_chain"]["block_hash"] == a1
        say("A1 block_hash returned by emit() equals the journal's:", match)
        res["A1 matches journal"] = match
    a5_in_journal = any(r.get("seq") == 5 for r in journal)
    if acks:
        res["A6 chained"] = any(r.get("seq") == 6 for r in journal)
        say("A6 record chained:", res["A6 chained"])
    say("A5 record chained after the collector resumed:", a5_in_journal)
    res["A5 chained after resume"] = a5_in_journal
    res["A8 chained"] = any(r.get("seq") == 8 for r in journal)
    say("A8 legacy sender's record chained:", res["A8 chained"])
    if acks:
        res["A9 flood records chained"] = sum(1 for s in seqs if isinstance(s, int) and s >= 10000)
        say("A9 flood records chained:", res["A9 flood records chained"])
    say("\ncollector output (tail):\n" + "\n".join(coll_out.rstrip().splitlines()[-8:]))

    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump({"label": a.label, "acks": acks, **res}, f, indent=2, default=str)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
