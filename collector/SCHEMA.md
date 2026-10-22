# FGAT record schema

Volume 2 uses the **event schema** below. It is what the trial runner
(`experiments/rig_fgat/fgat_rig_trial.py`) and the smoke script write, what the
collector maps to the operational plane, and what the Part 3 queries
(`analytics/vol2_queries.sql`) read. The Volume 1 per-turn schema is kept, as
legacy, at the end of this file.

## Event records (Volume 2)

One record per event, not per turn. Every record has:

| Field | Type | Meaning |
| --- | --- | --- |
| `session_id` | string | Session the record belongs to |
| `seq` | int | Per-session sequence number, starting at 1 |
| `kind` | string | `model_turn`, `intent`, or `result` |
| `ts` | float | Sender's Unix time when the record was written |
| `turn` | int | Model turn the event belongs to |

**`model_turn`**: one per model call.

| Field | Meaning |
| --- | --- |
| `latency_s` | Model call duration |
| `window_sha256` | Hash of the exact window sent; window in the store |
| `history_len`, `window_len`, `trimmed` | Message counts; whether older messages were trimmed |
| `payload_in_window`, `canary_in_window`, `doc_in_window` | Whether the injected text, the canary, and the injected document were in the window |
| `content`, `reasoning` | Model answer and reasoning text, inline |
| `reasoning_sha256` | Hash of the reasoning text |
| `tool_calls` | List of `{name, arguments}` proposed by the model |
| `usage` | Token usage as returned by the API |

**`intent`**: one per proposed tool call, written after the gate decides and
before the tool runs.

| Field | Meaning |
| --- | --- |
| `tool` | Tool name |
| `args` | Tool arguments (object) |
| `classify` | Harness classification (`allow`, ...) |
| `branch` | What decided it: `classify_allow`, `auto_approve`, `human_or_eof` |
| `allowed` | Whether the call went ahead |

**`result`**: one per executed tool call.

| Field | Meaning |
| --- | --- |
| `tool`, `args` | As in the intent |
| `result_sha256`, `result_bytes` | Hash and size of the tool output; output in the store |
| `progress_sha256` | `update_progress` only: hash of the notes written |

### Content references

Any field whose name ends in `_sha256` and holds a 64-hex digest is a reference
into the collector's content store. The collector rejects a record that
references content it didn't store, and records over 16 KiB. The window and
tool output always go through `FgatClient.put()`. The rest stays inline: the
largest pilot record was 4,323 bytes (a `model_turn`). A long answer or a large
`write_file` argument could still pass 16 KiB, so the runner should move any
field that would push a record over the limit into the store.

### Fields the collector adds

The collector removes any sender-supplied `_chain` and sets:

| Field | Meaning |
| --- | --- |
| `_ingest.host_ingest_utc` | Collector receive time |
| `_ingest.sender_uid`, `sender_pid`, `sender_gid` | Sender credentials from the kernel (SCM_CREDENTIALS) |
| `_chain.prev_hash`, `_chain.block_hash` | `block_hash = SHA-256(prev_hash ‖ canonical JSON of the record incl. _ingest)` |

## Transport and acknowledgment

| Socket (default dir `/run/agent-journal/`) | Type | Purpose | Reply |
| --- | --- | --- | --- |
| `records.sock` | `SOCK_SEQPACKET` | Records from `FgatClient.emit()` | One per record, on the same connection |
| `blobs.sock` | `SOCK_STREAM` | Content from `FgatClient.put()` | The SHA-256 the collector computed |
| `events.sock` | `SOCK_DGRAM` | Legacy records | None |

All three are mode 0660 and accept only the allowed UIDs (kernel credentials:
`SO_PEERCRED` at connect, `SCM_CREDENTIALS` per datagram).

Record replies: `OK <payload sha256> <block_hash>` once the record is chained,
or `ERR <payload sha256> <reason>` (sender not allowed, over the size limit,
malformed, or referencing content not in the store). `emit()` returns the
block hash or raises `RecorderError`; it also raises if no reply arrives within
`ack_timeout` (default 5 s). A timeout means unknown, not rejected: the
collector may chain the record later. The caller must treat any raise as "not
recorded"; for an intent record, the tool doesn't run.

A client that stops reading replies stalls only its own connection: the
collector holds the pending reply and stops reading from that connection until
it can send it. (An earlier design replied over the datagram socket; one
client that never read its replies used up the collector's send buffer and
blocked replies to every client.)

## Operational events

One per accepted record, written to the operational file and, if configured,
mirrored over UDP byte for byte. Metadata only: no arguments, model text, or
content hashes.

| Kind | Fields |
| --- | --- |
| all | `session_id`, `seq`, `kind`, `turn`, `ts`, `host_ingest_utc`, `sender_uid`, `block_hash` |
| `model_turn` | `trimmed`, `payload_in_window`, `canary_in_window`, `doc_in_window`, `latency_s`, `tool_calls` (names only) |
| `intent` | `tool`, `classify`, `branch`, `allowed` |
| `result` | `tool`, `result_bytes` |
| `v1_turn` | `tool`, `classify`, `rule_id`, `exit_code` (a Volume 1 record, mapped) |

`block_hash` sequence = the external anchor checked by `--verify --anchor`.

## Volume 1 per-turn schema (legacy)

Used by `harness/`, `experiments/run_*.py`, `analytics/queries.sql`,
`analytics/reinvestigate.py`, `analytics/generate_benchmark_data.py`, and
`wireshark/fgat_drill.pcap`. One record per turn:

`turn_id`, `timestamp_utc`, `model_metadata`, `system_prompt_hash`,
`context_delta`, `ingress_hashes`, `tool_manifest_hash`,
`proposed_action {name, parameters}`, `gate_verdict {status, rule_id}`,
`execution_result {exit_code, ...}`.

Name mapping to the event schema: `turn_id` → `turn`; `timestamp_utc` → `ts`;
`proposed_action.name` → `tool`; `proposed_action.parameters` → `args`;
`gate_verdict.status` → `classify`; `execution_result` → a `result` record.
