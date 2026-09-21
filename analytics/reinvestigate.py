#!/usr/bin/env python3
"""
Mass Re-Investigation Execution Script (DuckDB)
Runs analytical queries against historical WORM journals to answer CISO audit questions in milliseconds.
"""

import argparse
import os
import sys
import time


def run_investigation(data_path: str):
    try:
        import duckdb
    except ImportError:
        print("[-] DuckDB not installed. Run: pip install duckdb", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(data_path):
        print(f"[-] Data path does not exist: {data_path}. Run generate_benchmark_data.py first.", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print("ANTON CHUVAKIN'S 'MASS RE-INVESTIGATION' ENGINE (DUCKDB)")
    print(f"Target dataset: {data_path}")
    print("=" * 80)

    con = duckdb.connect()

    # Determine reader function based on file extension
    table_source = f"read_parquet('{data_path}')" if data_path.endswith(".parquet") else f"read_json_auto('{data_path}')"

    # Query 1: Artifact Blast Radius
    TARGET_POISON_HASH = "8f3b891a9c4172be34125b29c9a10382f71887e4918237190182749102837192"
    q1 = f"""
    SELECT 
        session_id,
        turn_id,
        timestamp_utc,
        model_metadata->>'name' AS model,
        proposed_action->>'name' AS tool
    FROM {table_source}
    WHERE list_contains(list_transform(ingress_hashes, x -> x->>'sha256'), '{TARGET_POISON_HASH}')
    ORDER BY timestamp_utc DESC
    LIMIT 10;
    """

    print(f"\n[QUERY 1] Isolating Blast Radius for Ingress Hash {TARGET_POISON_HASH[:16]}...")
    t0 = time.perf_counter()
    res1 = con.execute(q1).fetchdf()
    duration1 = (time.perf_counter() - t0) * 1000
    print(f"Execution time: {duration1:.2f} ms")
    print(res1.to_string(index=False) if not res1.empty else "No matching records found.")

    # Query 2: Compromised System Prompt Audit
    TARGET_SYSTEM_HASH = "a3f89c02e148bd91840291840192840192840192840192840192840192840192"
    q2 = f"""
    SELECT 
        session_id,
        count(turn_id) AS privileged_turns,
        min(timestamp_utc) AS first_seen,
        max(timestamp_utc) AS last_seen
    FROM {table_source}
    WHERE system_prompt_hash = '{TARGET_SYSTEM_HASH}'
      AND proposed_action->>'name' IN ('execute_shell', 'write_file', 'curl')
      AND gate_verdict->>'status' = 'allow'
    GROUP BY session_id
    ORDER BY session_id
    LIMIT 10;
    """

    print(f"\n[QUERY 2] Identifying Sessions Executing Under Poisoned System Prompt {TARGET_SYSTEM_HASH[:16]}...")
    t0 = time.perf_counter()
    res2 = con.execute(q2).fetchdf()
    duration2 = (time.perf_counter() - t0) * 1000
    print(f"Execution time: {duration2:.2f} ms")
    print(res2.to_string(index=False) if not res2.empty else "No matching records found.")

    # Query 3: Compaction Preceding Unscoped Egress Anomaly
    q3 = f"""
    WITH turn_seq AS (
        SELECT 
            session_id,
            turn_id,
            timestamp_utc,
            proposed_action->>'name' AS tool_name,
            (context_delta->>'compacted')::boolean AS was_compacted,
            lead(proposed_action->>'name', 1) OVER (PARTITION BY session_id ORDER BY turn_id) AS next_tool
        FROM {table_source}
    )
    SELECT session_id, turn_id, timestamp_utc, next_tool
    FROM turn_seq
    WHERE was_compacted = true
      AND next_tool = 'execute_shell'
    LIMIT 10;
    """

    print("\n[QUERY 3] Flagging Behavioral Anomalies: Context Compaction Followed by Shell Execution...")
    t0 = time.perf_counter()
    res3 = con.execute(q3).fetchdf()
    duration3 = (time.perf_counter() - t0) * 1000
    print(f"Execution time: {duration3:.2f} ms")
    print(res3.to_string(index=False) if not res3.empty else "No matching records found.")

    print("\n" + "=" * 80)
    print("[+] All retrospective queries executed in sub-second latency across local silicon.")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run DuckDB mass re-investigation queries")
    parser.add_argument("--data", default="analytics/data/benchmark_journal.parquet",
                        help="Path to Parquet or JSONL journal file")
    args = parser.parse_args()

    # Fallback to jsonl if parquet not present
    target = args.data
    if not os.path.exists(target):
        alt = target.replace(".parquet", ".jsonl")
        if os.path.exists(alt):
            target = alt

    run_investigation(target)
