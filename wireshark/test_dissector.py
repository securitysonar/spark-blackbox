#!/usr/bin/env python3
"""
Test Suite for FGAT Wireshark Lua Dissector
Validates dissection, field extractions, expert info alerts,
and edge-case handling using tshark.

Run from the repository root:  python3 wireshark/test_dissector.py
                           or: python3 -m unittest wireshark.test_dissector

Fixtures:
  fgat_pilot_operational.pcap  Real tcpdump capture of the collector's
                               operational mirror while both Volume 2 pilot
                               journals were replayed through it (event schema).
  fgat_drill.pcap              Synthetic (pcap_writer.py), Volume 1 full-record
                               format. Exercises the legacy branch only.
Edge-case frames are synthesized with pcap_writer.py: they test the parser,
not the network.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from wireshark.pcap_writer import PcapWriter  # noqa: E402

DISSECTOR_LUA = REPO_ROOT / "wireshark" / "fgat_dissector.lua"
DRILL_PCAP = REPO_ROOT / "wireshark" / "fgat_drill.pcap"
PILOT_PCAP = REPO_ROOT / "wireshark" / "fgat_pilot_operational.pcap"

V2_FIELDS = ["fgat.session_id", "fgat.seq", "fgat.kind", "fgat.turn", "fgat.tool",
             "fgat.classify", "fgat.branch", "fgat.allowed", "fgat.result_bytes",
             "fgat.trimmed", "fgat.payload_in_window", "fgat.canary_in_window",
             "fgat.tool_calls", "fgat.sender_uid", "fgat.block_hash"]


def udp_payloads(pcap_path):
    """UDP payloads from a libpcap file (Ethernet or Linux cooked), in order."""
    data = Path(pcap_path).read_bytes()
    e = "<" if struct.unpack("<I", data[:4])[0] in (0xa1b2c3d4, 0xa1b23c4d) else ">"
    l2 = {1: 14, 113: 16, 276: 20}[struct.unpack(e + "I", data[20:24])[0]]
    out, off = [], 24
    while off + 16 <= len(data):
        incl = struct.unpack(e + "I", data[off + 8:off + 12])[0]
        ip = data[off + 16 + l2:off + 16 + incl]
        off += 16 + incl
        if len(ip) >= 28 and ip[0] >> 4 == 4 and ip[9] == 17:
            ihl = (ip[0] & 0x0F) * 4
            ulen = struct.unpack("!H", ip[ihl + 4:ihl + 6])[0]
            out.append(ip[ihl + 8:ihl + ulen])
    return out


def lua_bool(v):
    return {True: "True", False: "False"}.get(v, "")


class TestFgatDissector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=True)
            cls.tshark_available = True
        except (subprocess.SubprocessError, FileNotFoundError):
            cls.tshark_available = False

    def setUp(self):
        if not self.tshark_available:
            self.skipTest("tshark is not installed or not in PATH")

    def run_tshark(self, pcap_path, display_filter=None, verbose=False, fields=None):
        cmd = ["tshark", "-X", f"lua_script:{DISSECTOR_LUA}", "-r", str(pcap_path)]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        if verbose:
            cmd.append("-V")
        if fields:
            cmd.extend(["-T", "fields", "-E", "occurrence=f"])
            for f in fields:
                cmd.extend(["-e", f])
        return subprocess.run(cmd, capture_output=True, text=True)

    def lines(self, res):
        self.assertEqual(res.returncode, 0, f"tshark failed: {res.stderr}")
        self.assertNotIn("Lua: Error", res.stderr)
        return [l for l in res.stdout.split("\n") if l.strip()]

    # ------------------------------------------------------------------
    # Volume 2: real capture of the operational mirror
    # ------------------------------------------------------------------
    def pilot_events(self):
        if not PILOT_PCAP.exists():
            self.skipTest(f"{PILOT_PCAP.name} not present")
        return [json.loads(p) for p in udp_payloads(PILOT_PCAP)]

    def test_pilot_every_frame_dissected(self):
        """Every frame in the real pilot capture dissects as a known kind, none malformed."""
        events = self.pilot_events()
        self.assertGreater(len(events), 0)
        lines = self.lines(self.run_tshark(PILOT_PCAP))
        self.assertEqual(len(lines), len(events))
        for line, ev in zip(lines, events):
            self.assertIn(f"{ev['kind']} ", line)
            self.assertIn(ev["block_hash"][:8], line)
        malformed = self.lines(self.run_tshark(PILOT_PCAP, display_filter='_ws.expert.group == "Malformed"'))
        self.assertEqual(malformed, [])

    def test_pilot_fields_match_payloads(self):
        """tshark field values equal the JSON in each captured payload, frame by frame."""
        events = self.pilot_events()
        rows = [l.split("\t") for l in self.lines(self.run_tshark(PILOT_PCAP, fields=V2_FIELDS))]
        self.assertEqual(len(rows), len(events))
        for row, ev in zip(rows, events):
            got = dict(zip(V2_FIELDS, row))
            self.assertEqual(got["fgat.session_id"], ev["session_id"])
            self.assertEqual(got["fgat.seq"], str(ev["seq"]))
            self.assertEqual(got["fgat.kind"], ev["kind"])
            self.assertEqual(got["fgat.turn"], str(ev["turn"]))
            self.assertEqual(got["fgat.sender_uid"], str(ev["sender_uid"]))
            self.assertEqual(got["fgat.block_hash"], ev["block_hash"])
            if ev["kind"] in ("intent", "result"):
                self.assertEqual(got["fgat.tool"], ev["tool"])
            if ev["kind"] == "intent":
                self.assertEqual(got["fgat.classify"], ev["classify"])
                self.assertEqual(got["fgat.branch"], ev["branch"])
                self.assertEqual(got["fgat.allowed"], lua_bool(ev["allowed"]))
            if ev["kind"] == "result":
                self.assertEqual(got["fgat.result_bytes"], str(ev["result_bytes"]))
            if ev["kind"] == "model_turn":
                self.assertEqual(got["fgat.trimmed"], lua_bool(ev["trimmed"]))
                self.assertEqual(got["fgat.payload_in_window"], lua_bool(ev["payload_in_window"]))
                self.assertEqual(got["fgat.canary_in_window"], lua_bool(ev["canary_in_window"]))
                self.assertEqual(got["fgat.tool_calls"], ",".join(ev["tool_calls"]))

    def test_pilot_display_filters(self):
        """Filter counts on the real capture equal counts computed from the payloads."""
        events = self.pilot_events()
        cases = {
            'fgat.kind == "intent"': sum(e["kind"] == "intent" for e in events),
            'fgat.kind == "intent" && fgat.branch == "auto_approve"':
                sum(e["kind"] == "intent" and e["branch"] == "auto_approve" for e in events),
            'fgat.kind == "intent" && fgat.allowed == 0':
                sum(e["kind"] == "intent" and e["allowed"] is False for e in events),
            "fgat.payload_in_window == 1": sum(e.get("payload_in_window") is True for e in events),
            "fgat.trimmed == 1": sum(e.get("trimmed") is True for e in events),
            'fgat.tool == "run"': sum(e.get("tool") == "run" for e in events),
            '_ws.expert.group == "Security"': sum(
                (e["kind"] == "intent" and (e["allowed"] is False or e["branch"] == "auto_approve"))
                or e.get("payload_in_window") is True for e in events),
        }
        for flt, expected in cases.items():
            with self.subTest(filter=flt):
                self.assertEqual(len(self.lines(self.run_tshark(PILOT_PCAP, display_filter=flt))), expected)

    def test_v2_edge_cases(self):
        """Refused intent, auto-approve, v1_turn, unknown kind, missing block_hash."""
        frames = [
            {"session_id": "s", "seq": 1, "kind": "intent", "turn": 3, "ts": 1.5, "tool": "run",
             "classify": "ask", "branch": "human_or_eof", "allowed": False, "block_hash": "a" * 64},
            {"session_id": "s", "seq": 2, "kind": "intent", "turn": 3, "ts": 1.6, "tool": "run",
             "classify": "ask", "branch": "auto_approve", "allowed": True, "block_hash": "b" * 64},
            {"session_id": "s", "seq": None, "kind": "v1_turn", "turn": 4, "ts": "2026-10-22T12:00:00Z",
             "tool": "execute_shell", "classify": "deny", "rule_id": "R-X", "exit_code": 126,
             "block_hash": "c" * 64},
            {"session_id": "s", "seq": 4, "kind": "mystery", "turn": 5, "block_hash": "d" * 64},
            {"session_id": "s", "seq": 5, "kind": "result", "turn": 5, "tool": "read_file", "result_bytes": 10},
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            pcap = os.path.join(tmp_dir, "v2_edge.pcap")
            with PcapWriter(pcap) as w:
                for f in frames:
                    w.write_udp_packet(json.dumps(f).encode("utf-8"))
            lines = self.lines(self.run_tshark(pcap))
            self.assertEqual(len(lines), 5)
            self.assertIn("[REFUSED]", lines[0])
            self.assertIn("[AUTO-APPROVED]", lines[1])
            self.assertIn("v1_turn execute_shell | DENY", lines[2])
            self.assertIn("[s T4]", lines[2])
            self.assertIn("kind mystery", lines[3])
            self.assertIn("Block: none", lines[4])
            sec = self.lines(self.run_tshark(pcap, display_filter='_ws.expert.group == "Security"'))
            self.assertEqual(len(sec), 2)
            bad = self.lines(self.run_tshark(pcap, display_filter='_ws.expert.group == "Malformed"'))
            self.assertEqual(len(bad), 2)

    # ------------------------------------------------------------------
    # Volume 1 full-record format (legacy branch), synthetic drill file
    # ------------------------------------------------------------------
    def test_drill_pcap_turns(self):
        """Verifies standard 5-turn drill PCAP dissection."""
        lines = self.lines(self.run_tshark(DRILL_PCAP))
        self.assertEqual(len(lines), 5, f"Expected 5 frames in drill PCAP, got {len(lines)}")
        self.assertIn("[v1 Turn 1] list_dir(.)", lines[0])
        self.assertIn("docs/internals/architecture.md", lines[1])
        self.assertIn("setup.py", lines[2])
        self.assertIn("[v1 Turn 4] read_file(src/core.py)", lines[3])
        self.assertIn("[COMPACTION ALERT]", lines[3])
        self.assertIn("execute_shell", lines[4])

    def test_display_filters(self):
        """Display filters on the drill file, using the shared field names."""
        lines = self.lines(self.run_tshark(DRILL_PCAP, display_filter="fgat.turn == 5"))
        self.assertEqual(len(lines), 1)
        self.assertIn("[v1 Turn 5]", lines[0])

        lines = self.lines(self.run_tshark(DRILL_PCAP, display_filter="fgat.v1.compacted == 1"))
        self.assertEqual(len(lines), 1)
        self.assertIn("[v1 Turn 4]", lines[0])

        lines = self.lines(self.run_tshark(DRILL_PCAP, display_filter='fgat.v1.ingress_sha256 contains "69335b27"'))
        self.assertEqual(len(lines), 1)
        self.assertIn("architecture.md", lines[0])

        lines = self.lines(self.run_tshark(DRILL_PCAP, display_filter='fgat.tool == "read_file"'))
        self.assertEqual(len(lines), 3)

        lines = self.lines(self.run_tshark(DRILL_PCAP, display_filter='_ws.expert.group == "Security"'))
        self.assertEqual(len(lines), 1)
        self.assertIn("[v1 Turn 4]", lines[0])

    def test_v1_fields(self):
        """Field extraction for a Volume 1 record (turn 2 of the drill file)."""
        fields = ["fgat.session_id", "fgat.turn", "fgat.v1.model_name", "fgat.v1.model_provider",
                  "fgat.tool", "fgat.v1.tool_params", "fgat.classify", "fgat.v1.ingress_count",
                  "fgat.v1.ingress_source", "fgat.v1.ingress_sha256", "fgat.block_hash"]
        rows = self.lines(self.run_tshark(DRILL_PCAP, display_filter="fgat.turn == 2", fields=fields))
        self.assertEqual(len(rows), 1)
        got = dict(zip(fields, rows[0].split("\t")))
        self.assertEqual(got["fgat.session_id"], "sess-fgat-drill-8812")
        self.assertEqual(got["fgat.turn"], "2")
        self.assertEqual(got["fgat.v1.model_name"], "nemotron-3-super")
        self.assertEqual(got["fgat.v1.model_provider"], "nvidia-dgx-spark-local")
        self.assertEqual(got["fgat.tool"], "read_file")
        self.assertEqual(got["fgat.v1.tool_params"], "docs/internals/architecture.md")
        self.assertEqual(got["fgat.classify"], "allow")
        self.assertEqual(got["fgat.v1.ingress_count"], "1")
        self.assertEqual(got["fgat.v1.ingress_source"], "docs/internals/architecture.md")
        self.assertIn("69335b27", got["fgat.v1.ingress_sha256"])
        self.assertEqual(len(got["fgat.block_hash"]), 64)

    def test_synthetic_edge_cases(self):
        """String unescaping, non-table parameters, policy violation, and malformed frames."""
        base = {"session_id": "sess-test-edge", "timestamp_utc": "2026-09-22T20:00:00Z",
                "model_metadata": {"name": "test-model", "provider": "local"},
                "system_prompt_hash": "0" * 64, "context_delta": {"compacted": False},
                "ingress_hashes": [], "tool_manifest_hash": "0" * 64}
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_pcap = os.path.join(tmp_dir, "edge_cases.pcap")
            with PcapWriter(test_pcap) as writer:
                writer.write_udp_packet(json.dumps({**base, "turn_id": 1,
                    "proposed_action": {"name": "execute_shell", "parameters": {"command": "echo \"hello world\"\nls\t/tmp"}},
                    "gate_verdict": {"status": "allow", "rule_id": "DEFAULT_ALLOW"},
                    "execution_result": {"exit_code": 0},
                    "_chain": {"prev_hash": "0" * 64, "block_hash": "1" * 64}}).encode("utf-8"))
                writer.write_udp_packet(json.dumps({**base, "turn_id": 2,
                    "proposed_action": {"name": "execute_shell", "parameters": {"command": "rm -rf /"}},
                    "gate_verdict": {"status": "deny", "rule_id": "RESTRICTED_ROOT_COMMAND"},
                    "execution_result": {"exit_code": 126},
                    "_chain": {"prev_hash": "1" * 64, "block_hash": "2" * 64}}).encode("utf-8"))
                writer.write_udp_packet(json.dumps({**base, "turn_id": 3,
                    "proposed_action": {"name": "sleep_seconds", "parameters": 60},
                    "gate_verdict": {"status": "allow", "rule_id": "DEFAULT_ALLOW"},
                    "execution_result": {"exit_code": 0},
                    "_chain": {"prev_hash": "2" * 64, "block_hash": "3" * 64}}).encode("utf-8"))
                writer.write_udp_packet(b"\x00\xff\xfe\x01NOT_JSON_DATA")
                writer.write_udp_packet(b'{"turn_id": 5, "session_id": "unclosed_string...')
                writer.write_udp_packet(b'{"turn_id": 6, "status": "ok"} GARBAGE_DATA_AT_END')

            lines = self.lines(self.run_tshark(test_pcap))
            self.assertEqual(len(lines), 6)
            self.assertIn("echo \"hello world\"", lines[0])
            self.assertIn("DENY [POLICY VIOLATION]", lines[1])
            self.assertIn("sleep_seconds(60)", lines[2])
            for i in (3, 4, 5):
                self.assertIn("[MALFORMED]", lines[i])

            malformed = self.lines(self.run_tshark(test_pcap, display_filter='_ws.expert.group == "Malformed"'))
            self.assertEqual(len(malformed), 3)
            sec = self.lines(self.run_tshark(test_pcap, display_filter='_ws.expert.group == "Security"'))
            self.assertEqual(len(sec), 1)
            self.assertIn("[v1 Turn 2]", sec[0])


if __name__ == "__main__":
    unittest.main()
