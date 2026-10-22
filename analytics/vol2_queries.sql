-- Volume 2 investigation queries (The Agentic Black Box, Part 3), DuckDB.
-- Event schema: collector/SCHEMA.md. analytics/queries.sql is the Volume 1
-- per-turn schema and reads the synthetic benchmark parquet instead.
--
-- Per-run journals from the trial runner:
CREATE VIEW j AS
  SELECT * FROM read_json_auto('runs/*/journal.jsonl', union_by_name = true);
CREATE VIEW meta AS
  SELECT * FROM read_json_auto('runs/*/meta.json', union_by_name = true);
-- Collector journal instead (one file, all sessions; adds _ingest and _chain):
--   CREATE VIEW j AS SELECT * FROM read_json_auto('/var/log/agent-worm/audit_journal.jsonl');

-- What did the agent read, and when?
SELECT turn, args.path AS path, result_sha256
FROM j
WHERE session_id = '<session_id>'
  AND kind = 'result' AND tool = 'read_file'
ORDER BY seq;

-- What could the agent see on each turn?
SELECT turn, trimmed, payload_in_window
FROM j
WHERE session_id = '<session_id>' AND kind = 'model_turn'
ORDER BY turn;

-- Which sessions read this exact file?
SELECT DISTINCT session_id, turn
FROM j
WHERE kind = 'result' AND tool = 'read_file'
  AND result_sha256 = '<sha256 of the known-bad file>'
ORDER BY session_id, turn;

-- Which sessions read content containing this text? (variants; store search)
SELECT DISTINCT j.session_id, j.turn, j.tool
FROM read_text('runs/*/store/*') s
JOIN j ON j.kind = 'result'
      AND j.result_sha256 = regexp_extract(s.filename, '([0-9a-f]{64})$', 1)
WHERE s.content ILIKE '%<text>%';

-- Which sessions installed packages?
SELECT session_id, turn, branch, args.command AS command
FROM j
WHERE kind = 'intent' AND tool = 'run' AND allowed
  AND regexp_matches(args.command,
        '\b(pip3?|python3? -m pip|npm|uv) (install|add)\b')
ORDER BY session_id, turn;

-- Which sessions acted on the network after an injection left the window?
WITH evicted AS (
  SELECT session_id, min(turn) AS evict_turn
  FROM j w
  WHERE kind = 'model_turn' AND NOT payload_in_window
    AND EXISTS (SELECT 1 FROM j p
                WHERE p.session_id = w.session_id
                  AND p.kind = 'model_turn' AND p.payload_in_window
                  AND p.turn < w.turn)
  GROUP BY session_id
)
SELECT i.session_id, e.evict_turn, i.turn, i.args.command AS command
FROM j i JOIN evicted e USING (session_id)
WHERE i.kind = 'intent' AND i.tool = 'run' AND i.allowed
  AND i.turn >= e.evict_turn
  AND regexp_matches(i.args.command, '\b(curl|wget)\b')
ORDER BY 1, 3;
