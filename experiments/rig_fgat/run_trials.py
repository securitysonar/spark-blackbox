#!/usr/bin/env python3
"""Lab checklist step 7: the instrumented trial matrix, in random order.

Cells (n), from the experiment plan: V0-A 3, V1-A 10, V2-A 10, V1-B 3, V2-B 3 = 29.
The order is shuffled once with a recorded seed and saved to <out>/plan.json;
a rerun resumes after the last session recorded in <out>/trials.jsonl.

Per session: preflight.py --instrumented (stop on failure), then
fgat_rig_trial.py with stdin closed (gate B's prompt reads EOF and denies),
then pid_link.py. One line per session in trials.jsonl: order, cell, session
id, start/end, beacon (listener log), doc/payload eviction turns, canary,
error, and the session's first/last block hash in the campaign journal.

Usage (on the Spark, campaign collector and capture running):
  python3 run_trials.py --rig ~/code/rig-harness-eval/rig.py --out campaign/trials [--seed N]
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CELLS = [("V0", "A", 3), ("V1", "A", 10), ("V2", "A", 10), ("V1", "B", 3), ("V2", "B", 3)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rig", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--campaign", default=os.path.join(HERE, "campaign"))
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--limit", type=int, default=None, help="run at most this many sessions now")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    plan_path, log_path = os.path.join(a.out, "plan.json"), os.path.join(a.out, "trials.jsonl")
    if os.path.exists(plan_path):
        plan = json.load(open(plan_path))
    else:
        seed = a.seed if a.seed is not None else random.SystemRandom().randrange(2**32)
        order = [f"{v}-{g}" for v, g, n in CELLS for _ in range(n)]
        random.Random(seed).shuffle(order)
        plan = {"seed": seed, "created": time.time(), "order": order}
        with open(plan_path, "w") as f:
            json.dump(plan, f, indent=2)
    done = 0
    if os.path.exists(log_path):
        done = sum(1 for l in open(log_path) if l.strip())
    print(f"plan: {len(plan['order'])} sessions, seed {plan['seed']}; {done} done")

    sock = os.path.join(a.campaign, "run", "events.sock")
    runs = os.path.join(a.out, "runs")
    os.makedirs(runs, exist_ok=True)
    env = dict(os.environ, RIG_BASE_URL=os.environ.get("RIG_BASE_URL", "http://localhost:11434/v1"),
               RIG_MODEL=os.environ.get("RIG_MODEL", "qwen3.8:27b"))
    n_run = 0
    for i in range(done, len(plan["order"])):
        if a.limit is not None and n_run >= a.limit:
            break
        cell = plan["order"][i]
        variant, gate = cell.split("-")
        print(f"=== {i + 1}/{len(plan['order'])} {cell} {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
              flush=True)
        pf = subprocess.run([sys.executable, os.path.join(HERE, "preflight.py"), "--rig", a.rig,
                             "--instrumented", "--campaign", a.campaign,
                             "--out", os.path.join(a.out, "preflight")], capture_output=True, text=True)
        print("  preflight:", pf.stdout.strip().splitlines()[-1] if pf.stdout.strip() else pf.stderr[-300:])
        if pf.returncode != 0:
            print(pf.stdout)
            sys.exit("preflight failed; stopping (rerun to resume)")
        before = set(os.listdir(runs))
        log = open(os.path.join(runs, f"{i + 1:02d}-{cell}.log"), "w")
        subprocess.run([sys.executable, os.path.join(HERE, "fgat_rig_trial.py"), "--variant", variant,
                        "--gate", gate, "--rig", a.rig, "--out", runs, "--collector-socket", sock],
                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env)
        log.close()
        new = sorted(set(os.listdir(runs)) - before - {f"{i + 1:02d}-{cell}.log"})
        if len(new) != 1:
            sys.exit(f"expected one new session directory, found {new}; see {log.name}")
        run_dir = os.path.join(runs, new[0])
        meta = json.load(open(os.path.join(run_dir, "meta.json")))
        subprocess.run([sys.executable, os.path.join(HERE, "pid_link.py"), "--journal",
                        os.path.join(a.campaign, "evidence", "audit_journal.jsonl"),
                        "--session", meta["session_id"], "--json", os.path.join(run_dir, "pid_link.json")],
                       stdout=open(os.path.join(run_dir, "pid_link.txt"), "w"), stderr=subprocess.STDOUT)
        row = {"order": i + 1, "cell": cell, "session_id": meta["session_id"], "canary": meta["canary"],
               "start": meta["t0"], "end": meta["t1"], "wall_s": meta["wall_s"],
               "model_turns": meta["model_turns"], "beacon": meta["beacon_received"],
               "doc_evicted_turn": meta["doc_evicted_turn"], "payload_evicted_turn": meta["payload_evicted_turn"],
               "error": meta["error"], "collector": meta["collector"],
               "container_diff_lines": meta["container_diff_lines"], "pip_side_effects": meta["pip_side_effects"]}
        with open(log_path, "a") as f:
            f.write(json.dumps(row) + "\n")
        n_run += 1
        print(f"  {meta['session_id']}: {meta['model_turns']} turns, {meta['wall_s']} s, beacon {meta['beacon_received']}, "
              f"error {meta['error']}", flush=True)
        if meta["pip_side_effects"] or (meta["collector"] or {}).get("failure"):
            sys.exit("containment surprise or recorder failure; stopping for review (rerun to resume)")


if __name__ == "__main__":
    main()
