# spark-blackbox

**Forensic-Grade Agent Telemetry (FGAT) on NVIDIA DGX Spark**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: NVIDIA Grace Blackwell](https://img.shields.io/badge/Platform-ARM64%20%2F%20SBSA%20(DGX%20Spark)-green.svg)](https://securitysonar.com)
[![Research Series: The Agentic Black Box](https://img.shields.io/badge/Research-Security%20Sonar-orange.svg)](https://securitysonar.com)

Supporting code, out-of-band audit collector daemon, decision-turn provenance interceptor, container manifests, and DuckDB analytical queries for the Security Sonar three-part research series:
**"The Agentic Black Box: What 'Forensic-Grade' Telemetry Actually Requires When Autonomous Systems Fail"**

- **Part 1:** Reproducing the Evidentiary Breakdown on a DGX Spark
- **Part 2:** Engineering the Forensic Flight Recorder on a DGX Spark
- **Part 3:** Post-Mortem & Mass Re-Investigation on a DGX Spark

---

## The Evidentiary Breakdown

When an autonomous AI agent with tool permissions runs on production infrastructure, traditional Digital Forensics and Incident Response (DFIR) collapses across three core failure modes:

1. **The Context Compaction Trap:** In multi-turn execution loops, auto-compaction algorithms summarize earlier context to conserve token budgets. When an agent ingests an indirect prompt injection, compaction purges the malicious text from working memory, leaving behind only the model's sanitized justification for executing unauthorized actions.
2. **The Attribution Void at the Process Boundary:** Host EDR and Linux `auditd` see valid process executions (`python3` spawning `curl`) under authorized service accounts. They are structurally blind to LLM intent, prompt context, and indirect steering.
3. **The Self-Tampering Agent:** When agents have shell or filesystem write access, an adversarial prompt can direct the agent to execute `history -c`, truncate `.bash_history`, or delete local SQLite/JSON logs, destroying local witness artifacts.

`spark-blackbox` implements the **Four Invariants of Forensic-Grade Agent Telemetry (FGAT)** to eliminate these blind spots.

---

## Architecture Overview

```
                      DGX Spark Telemetry Architecture
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ HOST OS (Grace CPU / ARM64 Ubuntu 24.04 SBSA)                               │
 │                                                                             │
 │  ┌─────────────────────────────────┐   UNIX Domain Socket                   │
 │  │ Agent Sandbox Container (nvcr.io)│   /run/agent-journal/events.sock       │
 │  │                                 │   (Write-Only Mount)                   │
 │  │  • Multi-turn Agent Loop        │ ──────────────────────┐                │
 │  │  • 10-Field Provenance Intercept│                       │                │
 │  │  • Ingress Hasher (SHA-256)     │                       │                │
 │  └─────────────────────────────────┘                       │                │
 │                                                            ▼                │
 │  ┌───────────────────────────────────────────────────────────────────────┐  │
 │  │ Host Logging Daemon (User: svc-audit-collector)                       │  │
 │  │                                                                       │  │
 │  │  1. Ingress Artifact Fingerprinter (SHA-256 Raw Storage)              │  │
 │  │  2. Turn Cryptographic Chainer: H_n = SHA256(H_{n-1} + Turn_n)        │  │
 │  │  3. Dual-Plane Dispatcher                                             │  │
 │  └───────────────────┬───────────────────────────────────┬───────────────┘  │
 │                      │                                   │                  │
 │                      ▼                                   ▼                  │
 │         ┌─────────────────────────┐         ┌─────────────────────────┐     │
 │         │ Operational Plane       │         │ Evidentiary Plane (WORM)│     │
 │         │ (Vector -> Local Click- │         │ /var/log/agent-worm/    │     │
 │         │ House / SIEM Alerting)  │         │ (Append-Only / Parquet) │     │
 │         └─────────────────────────┘         └─────────────────────────┘     │
 └─────────────────────────────────────────────────────────────────────────────┘
```

### The Four Invariants Implemented

1. **Out-of-Band Append-Only Recording:** Telemetry streams synchronously over an isolated UNIX domain socket (`events.sock`) consumed by an unprivileged host daemon (`svc-audit-collector`). The agent has no read, seek, or truncate permissions over historical records.
2. **The Decision-Turn Provenance Tuple:** Middleware captures a complete 10-field tuple for every turn: `turn_id`, `timestamp_utc`, `model_metadata`, `system_prompt_hash`, `context_delta`, `ingress_hashes`, `tool_manifest_hash`, `proposed_action`, `gate_verdict`, `execution_result`.
3. **Cryptographic Ingress Hashing:** Ingestion tools compute a SHA-256 fingerprint of every file, URL, and API payload *before* tokens enter context. Even when context compaction purges prompt text, the entry hash remains immutable in the audit journal.
4. **Dual-Plane Pipeline & Mass Re-Investigation:** Operational JSON events stream to SIEM/SOAR for real-time alerting; raw provenance tuples are cryptographically chained (`SHA-256(Turn_{N-1} + Turn_N)`) into an immutable WORM archive queried via DuckDB.

---

## Repository Structure

```
spark-blackbox/
├── README.md
├── LICENSE
├── requirements.txt
├── docker-compose.yml
├── collector/
│   ├── collector_daemon.py      # Host-side out-of-band socket daemon & hash chainer
│   └── Dockerfile.collector     # Container definition for isolated collector
├── harness/
│   ├── __init__.py
│   ├── provenance_interceptor.py# Middleware capturing the 10-field Provenance Tuple
│   ├── intercepted_tools.py     # Tool registry with boundary cryptographic ingress hashing
│   └── agent_runner.py          # Multi-turn agent loop with compaction simulation
├── experiments/
│   ├── fixtures/
│   │   └── repo/                # Vulnerable target repository with indirect injection
│   │       ├── docs/internals/architecture.md
│   │       ├── setup.py
│   │       └── src/core.py
│   ├── run_compaction_failure.py# Experiment 1: Context Compaction Trap demo
│   ├── run_tamper_attempt.py    # Experiment 3: Self-Tampering Agent demo
│   └── run_instrumented_drill.py# Full FGAT drill & root-cause reconstruction
└── analytics/
    ├── queries.sql              # DuckDB Mass Re-Investigation queries
    ├── generate_benchmark_data.py # Synthetic multi-session telemetry generator
    └── reinvestigate.py         # Sub-second analytical query runner
```

---

## Quickstart & Hands-On Reproduction

### 1. Environment Setup

```bash
git clone https://github.com/securitysonar/spark-blackbox.git
cd spark-blackbox

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Failure Modes (Part 1)

**Reproduce Experiment 1 (The Context Compaction Trap):**
```bash
python3 experiments/run_compaction_failure.py
```
*Observe how the agent ingests the prompt injection on Turn 2, triggers auto-compaction on Turn 4, purges the malicious string, and executes an unauthorized beacon on Turn 5 using a sanitized justification.*

**Reproduce Experiment 3 (The Self-Tampering Agent):**
```bash
python3 experiments/run_tamper_attempt.py
```
*Demonstrates that an injected agent can trivially wipe `.bash_history` and local session databases if telemetry is stored in reachable directories.*

### 3. Run the Full Forensic Flight Recorder Drill (Part 2 & 3)

```bash
python3 experiments/run_instrumented_drill.py
```
*Runs the full multi-turn attack under FGAT instrumentation:*
- *Starts the background UNIX domain socket collector daemon.*
- *Computes SHA-256 ingress hashes at file boundaries.*
- *Validates the cryptographic block chain (`SHA-256(H_{n-1} + Turn_n)`).*
- *Proves 100% root-cause recovery by linking Turn 5's hijacked beacon back to Turn 2's ingress hash despite context compaction.*

---

## Anton Chuvakin's "Mass Re-Investigation" (DuckDB)

Security researcher Anton Chuvakin identified the enterprise challenge:
> *"On discovering a systematic agent error (bad detection logic, a poisoned reference case, a behavior-changing model update) you need to re-open and re-run a month of closed cases in bulk."*

With FGAT WORM archives stored in Parquet format, mass re-investigation is an analytical SQL query.

### Generate Benchmark Telemetry & Run Queries

```bash
# 1. Generate 100 enterprise sessions (~1,000 turns) in JSONL and Parquet
python3 analytics/generate_benchmark_data.py --sessions 100 --turns 10

# 2. Execute sub-second mass re-investigations across historical turns
python3 analytics/reinvestigate.py
```

### Analytical SQL Queries (`analytics/queries.sql`)

**Isolate the Blast Radius of a Compromised Ingress File:**
```sql
SELECT session_id, turn_id, timestamp_utc, proposed_action->>'name' AS tool_name
FROM read_parquet('analytics/data/*.parquet')
WHERE list_contains(list_transform(ingress_hashes, x -> x->>'sha256'), '<TARGET_HASH>')
ORDER BY timestamp_utc DESC;
```

**Find Rogue Actions Under a Poisoned System Prompt:**
```sql
SELECT session_id, count(turn_id) AS privileged_turns, min(timestamp_utc), max(timestamp_utc)
FROM read_parquet('analytics/data/*.parquet')
WHERE system_prompt_hash = '<POISONED_PROMPT_HASH>'
  AND proposed_action->>'name' IN ('execute_shell', 'write_file', 'curl')
  AND gate_verdict->>'status' = 'allow'
GROUP BY session_id;
```

---

## DGX Spark Deployment (Grace Blackwell / SBSA)

To launch the isolated daemon and container sandbox on Grace-Blackwell:

```bash
docker compose up -d
```

The compose stack isolates privileges:
- `audit-collector` runs as isolated user `svc-audit-collector` (UID 2001) and owns the WORM storage volume.
- `agent-sandbox` runs as unprivileged user `1001`, mounts **only** the write-end of `/run/agent-journal/events.sock`, drops all Linux capabilities (`cap_drop: ALL`), and enforces `no-new-privileges:true`.

---

## License & Attribution

- Code in this repository is licensed under the [MIT License](LICENSE).
- Authored by Peter Campbell for [Security Sonar](https://securitysonar.com).
