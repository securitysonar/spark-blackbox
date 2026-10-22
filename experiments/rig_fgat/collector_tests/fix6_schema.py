#!/usr/bin/env python3
"""Fix 6 test: does the collector handle the Volume 2 event schema?

Replays the two pilot journals (runs/<session>/journal.jsonl, event schema)
through the collector with fgat_client: each record's store objects are put
first, then the record is emitted. A Volume 1 per-turn record is sent last.

Reports, per collector:
  - records accepted, and rejected with the reason (records over 16 KiB are the
    step-4 work of moving model text and large args into the store);
  - for accepted records, whether the journal copy minus _ingest/_chain equals
    the original (the fields Part 3's queries read survive the collector);
  - operational events: which fields are populated, per kind.

Usage (on the Spark):
  python3 fix6_schema.py --collector DIR/collector_daemon.py --runs runs --label after --out results/
"""
import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter

SESSIONS = ["bbx-smoke-V2A-781a4c", "bbx-V2A-af0fa0"]
V1_RECORD = {"session_id": "bbx-v1-legacy", "turn_id": 1, "timestamp_utc": "2026-10-22T12:00:00Z",
             "proposed_action": {"name": "read_file", "parameters": {"path": "README.md"}},
             "gate_verdict": {"status": "allow", "rule_id": "R-READ"},
             "execution_result": {"exit_code": 0}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    out = os.path.join(os.path.abspath(a.out), "fix6-" + a.label)
    os.makedirs(out, exist_ok=False)
    log = open(os.path.join(out, "transcript.txt"), "w", encoding="utf-8")

    def say(*parts):
        line = " ".join(str(p) for p in parts)
        print(line)
        log.write(line + "\n")
        log.flush()

    sys.path.insert(0, os.path.dirname(os.path.abspath(a.collector)))
    from collector_daemon import content_refs  # noqa: E402
    from fgat_client import FgatClient, RecorderError  # noqa: E402

    sha = subprocess.run(["sha256sum", a.collector], capture_output=True, text=True).stdout
    say(f"# Fix 6 {a.label} — {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    say("collector:", sha.strip())

    work = tempfile.mkdtemp(prefix="bbx-fix6-")
    sock = os.path.join(work, "events.sock")
    worm = os.path.join(work, "worm", "audit_journal.jsonl")
    oper = os.path.join(work, "operational.jsonl")
    coll = subprocess.Popen([sys.executable, a.collector, "--socket", sock, "--worm", worm,
                             "--operational", oper],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    time.sleep(0.3)
    c = FgatClient(sock, os.path.join(work, "blobs.sock"), max_record_bytes=1 << 20)

    sent = []
    for sid in SESSIONS:
        d = os.path.join(a.runs, sid)
        with open(os.path.join(d, "journal.jsonl"), encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        missing_objs = 0
        for r in recs:
            for _, h in content_refs(r):
                p = os.path.join(d, "store", h)
                if os.path.exists(p):
                    with open(p, "rb") as bf:
                        c.put(bf.read())
                else:
                    missing_objs += 1
            try:
                c.emit(r)
            except RecorderError as e:
                say("send failed:", e)
                continue
            sent.append(r)
            time.sleep(0.005)
        say(f"{sid}: {len(recs)} records sent; referenced objects missing from the run store: {missing_objs}")
    c.emit(V1_RECORD)
    sent.append(V1_RECORD)
    c.close()
    time.sleep(1.0)
    coll.send_signal(signal.SIGTERM)
    coll.communicate(timeout=10)

    with open(worm, encoding="utf-8") as f:
        journal = [json.loads(l) for l in f if l.strip()]
    with open(oper, encoding="utf-8") as f:
        ops = [json.loads(l) for l in f if l.strip()]
    rej_path = os.path.join(os.path.dirname(worm), "rejected.jsonl")
    rejects = []
    if os.path.exists(rej_path):
        with open(rej_path, encoding="utf-8") as f:
            rejects = [json.loads(l) for l in f if l.strip()]
    for src, name in ((oper, "operational.jsonl"), (rej_path, "rejected.jsonl")):
        if os.path.exists(src):
            shutil.copy(src, os.path.join(out, name))

    say(f"\nsent {len(sent)}, journal {len(journal)}, operational {len(ops)}, rejected {len(rejects)}")
    reasons = Counter(r["reason"].split(" (")[0].split(":")[0] for r in rejects)
    for reason, n in reasons.items():
        say(f"  rejected x{n}: {reason}")
    big = Counter()
    for r in sent:
        if len(json.dumps(r, sort_keys=True, separators=(",", ":")).encode()) > 16384:
            big[r.get("kind", "v1")] += 1
    say("  records over 16 KiB by kind:", dict(big))

    def strip(r):
        return {k: v for k, v in r.items() if k not in ("_ingest", "_chain")}
    by_key = {(r.get("session_id"), r.get("seq"), r.get("turn_id")): r for r in sent}
    same = sum(1 for r in journal
               if strip(r) == by_key.get((r.get("session_id"), r.get("seq"), r.get("turn_id"))))
    say(f"journal records identical to the originals (minus _ingest/_chain): {same} of {len(journal)}")

    say("\noperational events: populated (non-null) fields by record kind")
    stats = {}
    for r, o in zip(journal, ops):
        k = r.get("kind", "v1 per-turn")
        s = stats.setdefault(k, {"n": 0, "fields": Counter()})
        s["n"] += 1
        for f, v in o.items():
            if v not in (None, [], ""):
                s["fields"][f] += 1
    for k, s in stats.items():
        nulls = sorted(f for f in set().union(*(o.keys() for o in ops)) if s["fields"][f] == 0)
        say(f"  {k} (n={s['n']}): populated {dict(sorted(s['fields'].items()))}")
        say(f"  {k}: always null {nulls}")
    for k in stats:
        ex = next(o for r, o in zip(journal, ops) if r.get("kind", "v1 per-turn") == k)
        say(f"  example {k}: {json.dumps(ex)}")

    summary = {"label": a.label, "collector_sha256": sha.split()[0], "sent": len(sent),
               "journal": len(journal), "rejected": dict(reasons), "over_16k_by_kind": dict(big),
               "journal_identical": same,
               "operational_populated": {k: dict(s["fields"]) for k, s in stats.items()},
               "operational_n": {k: s["n"] for k, s in stats.items()}}
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
