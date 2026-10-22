#!/usr/bin/env python3
"""Fix 4 test: can the host account rewrite the evidence after the fact?

Two phases, so the append-only flag can be set in between (it needs root):

  prepare  run the collector into <out>/fix4-<label>/evidence, send 3 records
           with stored content, stop it, print the chattr command.
  attack   as the unprivileged host user (the same UID the harness and the
           collector run as), try each way of rewriting history, record whether
           the kernel allowed it, then run verify with --anchor and --store.

"before": run prepare then attack without setting any flag.
"after":  run prepare, then (as root) chattr +a on the journal, operational,
          rejects files and the store directory, then attack.

Attacks, least destructive first: append a forged record with a recomputed
hash; overwrite one byte in place; replace the file via rename (sed -i style);
truncate; rename; delete; delete a store object; edit a store object in place.

Files with +a can't be removed without root: clean up with chattr -a first.
"""
import argparse
import errno
import json
import os
import signal
import subprocess
import sys
import time


def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("phase", choices=["prepare", "attack"])
    ap.add_argument("--collector", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    base = os.path.join(os.path.abspath(a.out), "fix4-" + a.label)
    ev = os.path.join(base, "evidence")
    sock_dir = os.path.join(base, "run")
    worm = os.path.join(ev, "audit_journal.jsonl")
    oper = os.path.join(ev, "operational.jsonl")
    rejects = os.path.join(ev, "rejected.jsonl")
    store = os.path.join(ev, "store")
    sys.path.insert(0, os.path.dirname(os.path.abspath(a.collector)))

    log = open(os.path.join(base, f"{a.phase}.txt") if os.path.isdir(base) else os.devnull, "a")

    def say(*parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        log.write(line + "\n")
        log.flush()

    if a.phase == "prepare":
        os.makedirs(ev, exist_ok=False)
        os.makedirs(sock_dir)
        log = open(os.path.join(base, "prepare.txt"), "a")
        from fgat_client import FgatClient
        say(f"# Fix 4 {a.label} prepare — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
        rc, so, _ = run(["sha256sum", a.collector])
        say("collector:", so.strip())
        sock = os.path.join(sock_dir, "events.sock")
        coll = subprocess.Popen([sys.executable, a.collector, "--socket", sock, "--worm", worm,
                                 "--operational", oper, "--rejects", rejects, "--store", store],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        time.sleep(0.3)
        c = FgatClient(sock, os.path.join(sock_dir, "blobs.sock"))
        for turn, (tool, out) in enumerate([("read_file", "module layout ...\n" * 50),
                                            ("run", "3 passed in 0.12s\n"),
                                            ("update_progress", "audit: 12 of 36 modules read\n")], 1):
            h = c.put(out)
            c.emit({"session_id": "bbx-fix4-test", "turn_id": turn, "kind": "result",
                    "tool": tool, "result_sha256": h, "result_bytes": len(out)})
        c.close()
        time.sleep(0.5)
        coll.send_signal(signal.SIGTERM)
        say(coll.communicate(timeout=10)[0].rstrip())
        rc, so, se = run([sys.executable, a.collector, "--verify", "--worm", worm, "--anchor", oper, "--store", store])
        say("verify exit:", rc)
        say((so + se).rstrip())
        say("\nTo seal (after run only), as root:")
        say(f"  sudo chattr +a {worm} {oper} {rejects} {store}")
        return

    say(f"\n# Fix 4 {a.label} attack — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say("uid:", os.getuid())
    rc, so, se = run(["lsattr", "-d", worm, oper, rejects, store])
    say("lsattr:\n" + (so + se).rstrip())

    from collector_daemon import block_hash, canonical  # noqa: E402
    results = {}

    def attempt(name, fn):
        try:
            detail = fn()
            results[name] = "ALLOWED"
            say(f"[ALLOWED] {name}" + (f": {detail}" if detail else ""))
        except OSError as e:
            results[name] = f"DENIED ({errno.errorcode.get(e.errno, e.errno)})"
            say(f"[DENIED]  {name}: {e}")

    def append_forged():
        with open(worm, encoding="utf-8") as f:
            last = json.loads([l for l in f if l.strip()][-1])
        prev = last["_chain"]["block_hash"]
        rec = {"session_id": "bbx-fix4-test", "turn_id": 99, "kind": "result", "tool": "run",
               "note": "appended directly to the file by the host account"}
        rec["_chain"] = {"prev_hash": prev, "block_hash": block_hash(prev, rec)}
        with open(worm, "a", encoding="utf-8") as f:
            f.write(canonical(rec).decode() + "\n")
        return "forged record with a valid recomputed hash appended"

    def overwrite_byte():
        with open(worm, "r+b") as f:
            f.seek(40)
            f.write(b"X")

    def replace_via_rename():
        tmp = worm + ".sed"
        with open(worm, encoding="utf-8") as f:
            data = f.read().replace('"run"', '"RUN"')
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        try:
            os.replace(tmp, worm)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def truncate():
        os.truncate(worm, 0)

    def rename():
        os.rename(worm, worm + ".moved")
        os.rename(worm + ".moved", worm)

    def delete():
        os.remove(worm)

    objs = sorted(os.listdir(store))

    def delete_object():
        os.remove(os.path.join(store, objs[0]))

    def edit_object():
        p = os.path.join(store, objs[-1])
        os.chmod(p, 0o640)
        with open(p, "r+b") as f:
            f.seek(0)
            f.write(b"!")
        return f"one byte changed in {objs[-1][:16]}..."

    attempt("append a forged record (recomputed hash)", append_forged)
    attempt("overwrite one byte in place", overwrite_byte)
    attempt("replace the file via rename (sed -i style)", replace_via_rename)
    attempt("truncate the journal", truncate)
    attempt("rename the journal", rename)
    attempt("delete the journal", delete)
    attempt("delete a store object", delete_object)
    attempt("edit a store object in place", edit_object)

    say("")
    if os.path.exists(worm):
        rc, so, se = run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(a.collector)),
                          "collector_daemon.py"), "--verify", "--worm", worm, "--store", store])
        say("verify --store (no anchor) exit:", rc)
        say((so + se).rstrip())
        rc2, so, se = run([sys.executable, a.collector, "--verify", "--worm", worm, "--anchor", oper,
                           "--store", store])
        say("verify --anchor --store exit:", rc2)
        say((so + se).rstrip())
        results["verify_no_anchor"] = rc
        results["verify_anchor"] = rc2
    else:
        say("journal no longer exists; nothing to verify")
        results["verify_no_anchor"] = results["verify_anchor"] = "journal gone"
    with open(os.path.join(base, "summary.json"), "w") as f:
        json.dump({"label": a.label, **results}, f, indent=2)
    say("summary:", json.dumps(results))


if __name__ == "__main__":
    main()
