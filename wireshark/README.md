# Wireshark Monitoring for Forensic-Grade Agent Telemetry (FGAT)

This directory contains the Wireshark Lua dissector and PCAP artifacts for inspecting the **10-field Decision-Turn Provenance Tuple** in real time or post-incident.

[![Protocol: FGAT](https://img.shields.io/badge/Protocol-FGAT%20(UDP%209999)-blue.svg)](https://securitysonar.com)
[![Wireshark: Lua Dissector](https://img.shields.io/badge/Wireshark-Lua%20Dissector-green.svg)](https://www.wireshark.org)

---

## Why Monitor Agent Telemetry with Wireshark?

Traditional host EDR and SIEM platforms see application executions as generic process spawns (`python3` -> `curl`). 
By streaming the **Operational Plane** over UDP (port `9999`) and capturing it in standard PCAP format:
1. **The Wire Doesn't Lie:** Network packets provide an unalterable, independent witness to every agent decision.
2. **Standard DFIR Tooling:** Analysts and incident responders can triage agent behavior in the exact same packet analysis tool they use for enterprise network forensics.
3. **Structured Protocol Tree:** The custom Wireshark Lua dissector (`fgat_dissector.lua`) unpacks the raw JSON provenance payload into discrete, filterable protocol fields.

---

## Wireshark Protocol Dissection Tree

When a packet is selected in Wireshark, the `FGAT` dissector expands into five forensic sections:

```text
▼ Forensic-Grade Agent Telemetry, Turn 5: execute_shell [ALLOW]
  ▼ 1. Agent Identity & Serving Metadata
      Session ID: sess-fgat-drill-8812
      Turn ID: 5
      Timestamp (UTC): 2026-09-20T14:20:01.812491Z
      Model Name: nemotron-3-super
      Model Provider: dgx-spark-local
  ▼ 2. System Instructions & Context State
      System Prompt Hash (SHA-256): a3f89c02e148bd918402918401928401...
      Context Compacted: True
      [Expert Info (Warning/Security): Context auto-compaction occurred in this turn! Input prompt may be evicted.]
  ▼ 3. Untrusted Ingress Artifacts (1 object)
      Ingress Artifact Count: 1
      ▼ Artifact #1: docs/internals/architecture.md
          Ingress Source: docs/internals/architecture.md
          Ingress SHA-256: 69335b279b02c234a98a07b8b2fe177a7ae7cce68c8c5a8fc50f2fb983f390fc
  ▼ 4. Tool Execution Boundary & Gate Verdict
      Tool Manifest Hash (SHA-256): manifest-hash-abc123...
      Proposed Tool: execute_shell
      Tool Parameters: curl -s http://192.168.1.50:8000/telemetry-beacon?host=dgx-spark-node1
      Gate Verdict: ALLOW
      Gate Rule ID: DEFAULT_SHELL_PERMIT
      Execution Exit Code: 0
  ▼ 5. Evidentiary Hash Chain (Non-Repudiation)
      Previous Block Hash: f891b2c4...
      Current Block Hash:  a4b89f21c990...
```

---

## Quickstart: Inspecting the Drill PCAP

A pre-recorded capture of the full 5-turn attack trajectory is included in this directory: `fgat_drill.pcap`.

### Launch Wireshark with the FGAT Dissector

Run from the root of the repository:

```bash
wireshark -X lua_script:wireshark/fgat_dissector.lua wireshark/fgat_drill.pcap
```

Or using `tshark` in the terminal:

```bash
tshark -X lua_script:wireshark/fgat_dissector.lua -r wireshark/fgat_drill.pcap -V
```

---

## Wireshark Display Filters

With `fgat_dissector.lua` loaded, you can filter packets using native Wireshark syntax:

| Display Filter | Purpose |
|---|---|
| `fgat.turn_id == 5` | Isolate specific decision turn |
| `fgat.compacted == 1` | Filter turns where context auto-compaction occurred |
| `fgat.tool_name == "execute_shell"` | Isolate all shell execution tool attempts |
| `fgat.gate_verdict == "allow"` | Filter approved tool actions |
| `fgat.ingress_sha256 contains "69335b27"` | Trace every turn that touched a specific file hash |
| `fgat.session_id == "sess-fgat-drill-8812"` | Isolate an entire agent session |

---

## Live Monitoring on NVIDIA DGX Spark

To monitor agent telemetry live as it executes:

1. **Start the Collector Daemon with UDP Mirroring on DGX Spark:**
   ```bash
   python3 collector/collector_daemon.py --udp-mirror 127.0.0.1:9999
   ```

2. **Capture Live on DGX Spark:**
   ```bash
   # Sniff live UDP packets on loopback
   tcpdump -i lo -nn -s0 -w /tmp/live_fgat.pcap port 9999
   ```

3. **Or Stream Remotely to Your Workstation Wireshark:**
   If running the DGX Spark remotely, set `--udp-mirror <your-workstation-ip>:9999` and start Wireshark on your local machine capturing on UDP port 9999. Every decision turn will appear in your live packet stream in real time.

---

## Permanent Wireshark Plugin Installation

To load the dissector automatically whenever Wireshark opens:

- **macOS:**
  ```bash
  mkdir -p ~/.local/lib/wireshark/plugins/
  cp wireshark/fgat_dissector.lua ~/.local/lib/wireshark/plugins/
  ```
- **Linux:**
  ```bash
  mkdir -p ~/.local/lib/wireshark/plugins/
  cp wireshark/fgat_dissector.lua ~/.local/lib/wireshark/plugins/
  ```
- **Windows:**
  Copy `fgat_dissector.lua` to `%APPDATA%\Wireshark\plugins\`.
