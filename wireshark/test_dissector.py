#!/usr/bin/env python3
"""
Test Suite for FGAT Wireshark Lua Dissector
Validates dissection, field extractions, expert info alerts,
and edge-case handling using tshark.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from wireshark.pcap_writer import PcapWriter

REPO_ROOT = Path(__file__).resolve().parent.parent
DISSECTOR_LUA = REPO_ROOT / "wireshark" / "fgat_dissector.lua"
DRILL_PCAP = REPO_ROOT / "wireshark" / "fgat_drill.pcap"


class TestFgatDissector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Verify tshark is installed
        try:
            res = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=True)
            cls.tshark_available = True
        except (subprocess.SubprocessError, FileNotFoundError):
            cls.tshark_available = False

    def setUp(self):
        if not self.tshark_available:
            self.skipTest("tshark is not installed or not in PATH")

    def run_tshark(self, pcap_path: str, display_filter: str = None, verbose: bool = False):
        cmd = ["tshark", "-X", f"lua_script:{DISSECTOR_LUA}", "-r", str(pcap_path)]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        if verbose:
            cmd.append("-V")
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_drill_pcap_turns(self):
        """Verifies standard 5-turn drill PCAP dissection."""
        res = self.run_tshark(DRILL_PCAP)
        self.assertEqual(res.returncode, 0, f"tshark failed: {res.stderr}")
        lines = [line.strip() for line in res.stdout.strip().split("\n") if line.strip()]
        self.assertEqual(len(lines), 5, f"Expected 5 frames in drill PCAP, got {len(lines)}")

        self.assertIn("[Turn 1] list_dir(.)", lines[0])
        self.assertIn("docs/internals/architecture.md", lines[1])
        self.assertIn("setup.py", lines[2])
        self.assertIn("[Turn 4] read_file(src/core.py)", lines[3])
        self.assertIn("[COMPACTION ALERT]", lines[3])
        self.assertIn("execute_shell", lines[4])

    def test_display_filters(self):
        """Tests standard Wireshark display filter queries."""
        # 1. Turn ID filter
        res = self.run_tshark(DRILL_PCAP, display_filter="fgat.turn_id == 5")
        self.assertEqual(res.returncode, 0)
        lines = res.stdout.strip().split("\n")
        self.assertEqual(len(lines), 1)
        self.assertIn("[Turn 5]", lines[0])

        # 2. Compaction filter
        res = self.run_tshark(DRILL_PCAP, display_filter="fgat.compacted == 1")
        self.assertEqual(res.returncode, 0)
        lines = res.stdout.strip().split("\n")
        self.assertEqual(len(lines), 1)
        self.assertIn("[Turn 4]", lines[0])

        # 3. Ingress SHA-256 filter
        res = self.run_tshark(DRILL_PCAP, display_filter='fgat.ingress_sha256 contains "69335b27"')
        self.assertEqual(res.returncode, 0)
        lines = res.stdout.strip().split("\n")
        self.assertEqual(len(lines), 1)
        self.assertIn("architecture.md", lines[0])

        # 4. Security expert info filter (compaction alert in turn 4)
        res = self.run_tshark(DRILL_PCAP, display_filter='_ws.expert.group == "Security"')
        self.assertEqual(res.returncode, 0)
        lines = res.stdout.strip().split("\n")
        self.assertEqual(len(lines), 1)
        self.assertIn("[Turn 4]", lines[0])

    def test_all_18_protocol_fields(self):
        """Verifies extraction and correctness of all 18 declared FGAT ProtoFields."""
        fields = [
            "fgat.session_id", "fgat.turn_id", "fgat.timestamp",
            "fgat.model_name", "fgat.model_provider", "fgat.system_prompt_hash",
            "fgat.compacted", "fgat.tool_manifest_hash", "fgat.tool_name",
            "fgat.tool_params", "fgat.gate_verdict", "fgat.gate_rule",
            "fgat.exit_code", "fgat.ingress_count", "fgat.ingress_source",
            "fgat.ingress_sha256", "fgat.chain_prev_hash", "fgat.chain_block_hash"
        ]
        cmd = ["tshark", "-X", f"lua_script:{DISSECTOR_LUA}", "-r", str(DRILL_PCAP),
               "-Y", "fgat.turn_id == 2", "-T", "fields"]
        for f in fields:
            cmd.extend(["-e", f])

        res = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"tshark failed: {res.stderr}")
        extracted = res.stdout.strip().split("\t")
        self.assertEqual(len(extracted), 18, f"Expected 18 fields, got {len(extracted)}: {extracted}")

        # Assert key field values from Turn 2
        self.assertEqual(extracted[0], "sess-fgat-drill-8812")  # session_id
        self.assertEqual(extracted[1], "2")                     # turn_id
        self.assertEqual(extracted[3], "nemotron-3-super")      # model_name
        self.assertEqual(extracted[4], "nvidia-dgx-spark-local")# model_provider
        self.assertEqual(extracted[8], "read_file")             # tool_name
        self.assertEqual(extracted[9], "docs/internals/architecture.md")  # tool_params
        self.assertEqual(extracted[10], "allow")                # gate_verdict
        self.assertEqual(extracted[13], "1")                    # ingress_count
        self.assertEqual(extracted[14], "docs/internals/architecture.md")  # ingress_source
        self.assertIn("69335b27", extracted[15])                # ingress_sha256

    def test_synthetic_edge_cases(self):
        """Tests string unescaping, non-table parameters, policy violation, and malformed frames."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_pcap = os.path.join(tmp_dir, "edge_cases.pcap")

            with PcapWriter(test_pcap) as writer:
                # 1. Frame 1: String unescaping (\n, \t, \")
                writer.write_udp_packet(json.dumps({
                    "turn_id": 1,
                    "session_id": "sess-test-edge",
                    "timestamp_utc": "2026-09-22T20:00:00Z",
                    "model_metadata": {"name": "test-model", "provider": "local"},
                    "system_prompt_hash": "0" * 64,
                    "context_delta": {"compacted": False},
                    "ingress_hashes": [],
                    "tool_manifest_hash": "0" * 64,
                    "proposed_action": {"name": "execute_shell", "parameters": {"command": "echo \"hello world\"\nls\t/tmp"}},
                    "gate_verdict": {"status": "allow", "rule_id": "DEFAULT_ALLOW"},
                    "execution_result": {"exit_code": 0},
                    "_chain": {"prev_hash": "0" * 64, "block_hash": "1" * 64}
                }).encode("utf-8"))

                # 2. Frame 2: Policy denial verdict
                writer.write_udp_packet(json.dumps({
                    "turn_id": 2,
                    "session_id": "sess-test-edge",
                    "timestamp_utc": "2026-09-22T20:00:01Z",
                    "model_metadata": {"name": "test-model", "provider": "local"},
                    "system_prompt_hash": "0" * 64,
                    "context_delta": {"compacted": False},
                    "ingress_hashes": [],
                    "tool_manifest_hash": "0" * 64,
                    "proposed_action": {"name": "execute_shell", "parameters": {"command": "rm -rf /"}},
                    "gate_verdict": {"status": "deny", "rule_id": "RESTRICTED_ROOT_COMMAND"},
                    "execution_result": {"exit_code": 126},
                    "_chain": {"prev_hash": "1" * 64, "block_hash": "2" * 64}
                }).encode("utf-8"))

                # 3. Frame 3: Primitive integer parameter (sleep_seconds: 60)
                writer.write_udp_packet(json.dumps({
                    "turn_id": 3,
                    "session_id": "sess-test-edge",
                    "timestamp_utc": "2026-09-22T20:00:02Z",
                    "model_metadata": {"name": "test-model", "provider": "local"},
                    "system_prompt_hash": "0" * 64,
                    "context_delta": {"compacted": False},
                    "ingress_hashes": [],
                    "tool_manifest_hash": "0" * 64,
                    "proposed_action": {"name": "sleep_seconds", "parameters": 60},
                    "gate_verdict": {"status": "allow", "rule_id": "DEFAULT_ALLOW"},
                    "execution_result": {"exit_code": 0},
                    "_chain": {"prev_hash": "2" * 64, "block_hash": "3" * 64}
                }).encode("utf-8"))

                # 4. Frame 4: Corrupted non-JSON binary
                writer.write_udp_packet(b"\x00\xff\xfe\x01NOT_JSON_DATA")

                # 5. Frame 5: Unterminated truncated JSON
                writer.write_udp_packet(b'{"turn_id": 5, "session_id": "unclosed_string...')

                # 6. Frame 6: Trailing garbage after valid JSON
                writer.write_udp_packet(b'{"turn_id": 6, "status": "ok"} GARBAGE_DATA_AT_END')

            # Verify all 6 frames dissected without Lua runtime crashes
            res = self.run_tshark(test_pcap)
            self.assertEqual(res.returncode, 0, f"tshark failed: {res.stderr}")
            lines = [l.strip() for l in res.stdout.strip().split("\n") if l.strip()]
            self.assertEqual(len(lines), 6)

            # Frame 1: Check parameter string preservation
            self.assertIn("echo \"hello world\"", lines[0])

            # Frame 2: Policy violation tag
            self.assertIn("DENY [POLICY VIOLATION]", lines[1])

            # Frame 3: Primitive parameter handling
            self.assertIn("sleep_seconds(60)", lines[2])

            # Frames 4, 5, 6: Malformed markers
            self.assertIn("[MALFORMED]", lines[3])
            self.assertIn("[MALFORMED]", lines[4])
            self.assertIn("[MALFORMED]", lines[5])

            # Verify Malformed expert info filter returns frames 4, 5, 6
            malformed_res = self.run_tshark(test_pcap, display_filter='_ws.expert.group == "Malformed"')
            self.assertEqual(malformed_res.returncode, 0)
            malformed_lines = [l.strip() for l in malformed_res.stdout.strip().split("\n") if l.strip()]
            self.assertEqual(len(malformed_lines), 3)

            # Verify Security expert info filter returns policy violation (frame 2)
            sec_res = self.run_tshark(test_pcap, display_filter='_ws.expert.group == "Security"')
            self.assertEqual(sec_res.returncode, 0)
            sec_lines = [l.strip() for l in sec_res.stdout.strip().split("\n") if l.strip()]
            self.assertEqual(len(sec_lines), 1)
            self.assertIn("[Turn 2]", sec_lines[0])


if __name__ == "__main__":
    unittest.main()
