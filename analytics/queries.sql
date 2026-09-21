-- ============================================================================
-- Anton Chuvakin's "Mass Re-Investigation" Analytical Queries
-- Vectorized SQL queries executed across historical agent WORM journals via DuckDB
-- ============================================================================

-- Query 1: Artifact Blast Radius
-- Given a newly identified malicious or backdoored ingress artifact hash,
-- identify every past agent session and turn that ingested it over the last 90 days.
SELECT 
    session_id,
    turn_id,
    timestamp_utc,
    model_metadata->>'name' AS model_name,
    proposed_action->>'name' AS tool_name,
    gate_verdict->>'status' AS gate_verdict
FROM read_parquet('analytics/data/*.parquet')
WHERE list_contains(
    list_transform(ingress_hashes, x -> x->>'sha256'), 
    '8f3b891a9c4172be34125b29c9a10382f71887e4918237190182749102837192'
)
ORDER BY timestamp_utc DESC;


-- Query 2: Identifying Compromised System Prompts & Injected Skills
-- When an upstream system prompt revision or skill template is found backdoored,
-- isolate all privileged tool executions that operated under that system prompt hash.
SELECT 
    session_id,
    count(turn_id) AS privileged_turns,
    min(timestamp_utc) AS first_execution,
    max(timestamp_utc) AS last_execution,
    list(proposed_action->>'name') AS tools_invoked
FROM read_parquet('analytics/data/*.parquet')
WHERE system_prompt_hash = 'a3f89c02e148bd91840291840192840192840192840192840192840192840192'
  AND proposed_action->>'name' IN ('execute_shell', 'write_file', 'curl')
  AND gate_verdict->>'status' = 'allow'
GROUP BY session_id
HAVING privileged_turns > 0;


-- Query 3: Detecting Context Compaction Preceding Unscoped Egress
-- Detects sessions where automated compaction occurred within 2 turns
-- immediately preceding outbound network or shell activity.
WITH turn_sequence AS (
    SELECT 
        session_id,
        turn_id,
        timestamp_utc,
        proposed_action->>'name' AS tool_name,
        (context_delta->>'compacted')::boolean AS was_compacted,
        lead(proposed_action->>'name', 1) OVER (PARTITION BY session_id ORDER BY turn_id) AS next_tool,
        lead(proposed_action->>'name', 2) OVER (PARTITION BY session_id ORDER BY turn_id) AS second_tool
    FROM read_parquet('analytics/data/*.parquet')
)
SELECT 
    session_id,
    turn_id,
    timestamp_utc,
    next_tool,
    second_tool
FROM turn_sequence
WHERE was_compacted = true
  AND (next_tool IN ('execute_shell', 'curl') OR second_tool IN ('execute_shell', 'curl'));
