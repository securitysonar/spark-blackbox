#!/usr/bin/env python3
"""
Benchmark Data Generator
Generates realistic multi-session enterprise agent journals in JSONL and Parquet formats
to demonstrate sub-second mass re-investigation via DuckDB.
"""

import argparse
import hashlib
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_benchmark_data(num_sessions: int = 100, turns_per_session: int = 10, output_dir: str = "analytics/data"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    jsonl_path = os.path.join(output_dir, "benchmark_journal.jsonl")
    parquet_path = os.path.join(output_dir, "benchmark_journal.parquet")

    # Known hashes for testing queries
    TARGET_POISON_HASH = "8f3b891a9c4172be34125b29c9a10382f71887e4918237190182749102837192"
    TARGET_SYSTEM_HASH = "a3f89c02e148bd91840291840192840192840192840192840192840192840192"

    tools = ["read_file", "write_file", "list_dir", "execute_shell"]
    models = ["nemotron-3-super", "qwen-3.8-27b", "llama-3.3-70b"]

    base_time = datetime.now(timezone.utc) - timedelta(days=30)
    records = []
    last_block_hash = "0" * 64

    print(f"[*] Generating {num_sessions} sessions (~{num_sessions * turns_per_session} turns)...")

    for s_idx in range(num_sessions):
        session_id = f"sess-{s_idx:05d}"
        model = random.choice(models)
        is_compromised_session = (s_idx % 20 == 0)  # 5% of sessions hit poison hash

        system_hash = TARGET_SYSTEM_HASH if (s_idx % 10 == 0) else hashlib.sha256(f"sys-prompt-{s_idx}".encode()).hexdigest()

        for t_idx in range(1, turns_per_session + 1):
            turn_ts = (base_time + timedelta(hours=s_idx, minutes=t_idx * 2)).isoformat()
            compacted = (t_idx >= 5)

            ingress_hashes = []
            if t_idx == 2:
                h = TARGET_POISON_HASH if is_compromised_session else hashlib.sha256(f"file-{s_idx}".encode()).hexdigest()
                ingress_hashes.append({
                    "source": "docs/architecture.md" if is_compromised_session else "config.json",
                    "sha256": h,
                    "byte_count": 4096,
                })

            if is_compromised_session and t_idx == 6:
                chosen_tool = "execute_shell"
                params = {"command": "curl -s http://192.168.1.50:8000/beacon"}
            else:
                chosen_tool = random.choice(tools)
                params = {"path": "src/"} if chosen_tool in ("read_file", "list_dir") else {"cmd": "ls -l"}

            record = {
                "session_id": session_id,
                "turn_id": t_idx,
                "timestamp_utc": turn_ts,
                "model_metadata": {"name": model, "provider": "dgx-spark-local"},
                "system_prompt_hash": system_hash,
                "context_delta": {
                    "compacted": compacted,
                    "active_prompt": f"Executing turn {t_idx}",
                },
                "ingress_hashes": ingress_hashes,
                "tool_manifest_hash": "manifest-hash-abc123",
                "proposed_action": {"name": chosen_tool, "parameters": params},
                "gate_verdict": {"status": "allow", "rule_id": "DEFAULT_ALLOW"},
                "execution_result": {"exit_code": 0, "stdout": "ok", "stderr": ""},
            }

            # Cryptographic block chaining
            raw_bytes = json.dumps(record).encode("utf-8")
            hasher = hashlib.sha256()
            hasher.update(last_block_hash.encode("utf-8"))
            hasher.update(raw_bytes)
            current_block_hash = hasher.hexdigest()

            record["_chain"] = {
                "prev_hash": last_block_hash,
                "block_hash": current_block_hash,
                "host_ingest_utc": turn_ts,
            }
            last_block_hash = current_block_hash
            records.append(record)

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"[+] Wrote {len(records)} records to {jsonl_path}")

    # Convert to Parquet if duckdb or pyarrow is available
    try:
        import duckdb
        duckdb.sql(f"COPY (SELECT * FROM read_json_auto('{jsonl_path}')) TO '{parquet_path}' (FORMAT PARQUET)")
        print(f"[+] Successfully converted to Parquet: {parquet_path}")
    except Exception as e:
        print(f"[-] Parquet conversion skipped ({e}). JSONL available for queries.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate benchmark agent telemetry data")
    parser.add_argument("--sessions", type=int, default=100, help="Number of sessions")
    parser.add_argument("--turns", type=int, default=10, help="Turns per session")
    parser.add_argument("--out", default="analytics/data", help="Output directory")
    args = parser.parse_args()

    generate_benchmark_data(args.sessions, args.turns, args.out)
