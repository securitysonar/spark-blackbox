-- ============================================================================
-- Wireshark Lua Dissector for Forensic-Grade Agent Telemetry (FGAT)
-- Protocol: FGAT over UDP port 9999
-- Security Sonar (c) 2026 Peter Campbell
--
-- Dissects two payload formats:
--   * Volume 2 operational events, as the collector mirrors them: one per
--     record, kind model_turn / intent / result (or v1_turn for a mapped
--     Volume 1 record). Metadata only. Schema: collector/SCHEMA.md.
--   * Volume 1 full per-turn records (proposed_action / gate_verdict / ...),
--     as in fgat_drill.pcap. Legacy; the collector no longer mirrors these.
-- Both populate the same field names where the meaning is the same
-- (fgat.turn, fgat.tool, fgat.classify, fgat.block_hash, ...). Fields only
-- the Volume 1 format has are under fgat.v1.*.
-- ============================================================================

local fgat_proto = Proto("FGAT", "Forensic-Grade Agent Telemetry (FGAT)")

-- ----------------------------------------------------------------------------
-- Field Declarations (display filters like fgat.kind == "intent")
-- ----------------------------------------------------------------------------
local f_session_id     = ProtoField.string("fgat.session_id", "Session ID")
local f_seq            = ProtoField.uint32("fgat.seq", "Sequence")
local f_kind           = ProtoField.string("fgat.kind", "Record Kind")
local f_turn           = ProtoField.uint32("fgat.turn", "Turn")
local f_ts             = ProtoField.string("fgat.ts", "Sender Time")
local f_tool           = ProtoField.string("fgat.tool", "Tool")
local f_classify       = ProtoField.string("fgat.classify", "Classification")
local f_branch         = ProtoField.string("fgat.branch", "Decision Branch")
local f_allowed        = ProtoField.bool("fgat.allowed", "Allowed")
local f_rule_id        = ProtoField.string("fgat.rule_id", "Gate Rule ID")
local f_exit_code      = ProtoField.int32("fgat.exit_code", "Exit Code")
local f_result_bytes   = ProtoField.uint32("fgat.result_bytes", "Result Bytes")
local f_trimmed        = ProtoField.bool("fgat.trimmed", "Window Trimmed")
local f_payload_in     = ProtoField.bool("fgat.payload_in_window", "Injected Payload in Window")
local f_canary_in      = ProtoField.bool("fgat.canary_in_window", "Canary in Window")
local f_doc_in         = ProtoField.bool("fgat.doc_in_window", "Injected Document in Window")
local f_latency        = ProtoField.string("fgat.latency_s", "Model Latency (s)")
local f_tool_calls     = ProtoField.string("fgat.tool_calls", "Proposed Tool Calls")
local f_ingest_utc     = ProtoField.string("fgat.host_ingest_utc", "Collector Ingest Time (UTC)")
local f_sender_uid     = ProtoField.uint32("fgat.sender_uid", "Sender UID")
local f_block_hash     = ProtoField.string("fgat.block_hash", "Block Hash")

-- Volume 1 full-record fields
local f_v1_model_name  = ProtoField.string("fgat.v1.model_name", "Model Name")
local f_v1_model_prov  = ProtoField.string("fgat.v1.model_provider", "Model Provider")
local f_v1_sys_hash    = ProtoField.string("fgat.v1.system_prompt_hash", "System Prompt Hash (SHA-256)")
local f_v1_compacted   = ProtoField.bool("fgat.v1.compacted", "Context Compacted")
local f_v1_manifest    = ProtoField.string("fgat.v1.tool_manifest_hash", "Tool Manifest Hash (SHA-256)")
local f_v1_params      = ProtoField.string("fgat.v1.tool_params", "Tool Parameters")
local f_v1_ing_count   = ProtoField.uint32("fgat.v1.ingress_count", "Ingress Artifact Count")
local f_v1_ing_source  = ProtoField.string("fgat.v1.ingress_source", "Ingress Source")
local f_v1_ing_sha256  = ProtoField.string("fgat.v1.ingress_sha256", "Ingress SHA-256")
local f_v1_prev_hash   = ProtoField.string("fgat.v1.prev_hash", "Previous Block Hash")

fgat_proto.fields = {
    f_session_id, f_seq, f_kind, f_turn, f_ts, f_tool, f_classify, f_branch,
    f_allowed, f_rule_id, f_exit_code, f_result_bytes, f_trimmed, f_payload_in,
    f_canary_in, f_doc_in, f_latency, f_tool_calls, f_ingest_utc, f_sender_uid,
    f_block_hash,
    f_v1_model_name, f_v1_model_prov, f_v1_sys_hash, f_v1_compacted, f_v1_manifest,
    f_v1_params, f_v1_ing_count, f_v1_ing_source, f_v1_ing_sha256, f_v1_prev_hash
}

-- ----------------------------------------------------------------------------
-- Minimal Embedded JSON Parser (Zero-Dependency for universal compatibility)
-- ----------------------------------------------------------------------------
local function parse_json_value(str, i)
    i = str:find("%S", i)
    if not i then return nil, i end
    local c = str:sub(i, i)

    if c == "{" then
        local obj = {}
        i = i + 1
        while true do
            i = str:find("%S", i)
            if not i then error("unterminated object") end
            if str:sub(i, i) == "}" then return obj, i + 1 end
            if str:sub(i, i) == "," then
                i = i + 1
                i = str:find("%S", i)
                if not i then error("unterminated object after comma") end
                if str:sub(i, i) == "}" then return obj, i + 1 end
            end

            local key
            key, i = parse_json_value(str, i)
            if type(key) ~= "string" then error("expected string key") end
            i = str:find("%S", i)
            if not i or str:sub(i, i) ~= ":" then error("expected colon") end
            i = i + 1
            local val
            val, i = parse_json_value(str, i)
            obj[key] = val
        end
    elseif c == "[" then
        local arr = {}
        i = i + 1
        while true do
            i = str:find("%S", i)
            if not i then error("unterminated array") end
            if str:sub(i, i) == "]" then return arr, i + 1 end
            if str:sub(i, i) == "," then
                i = i + 1
                i = str:find("%S", i)
                if not i then error("unterminated array after comma") end
                if str:sub(i, i) == "]" then return arr, i + 1 end
            end

            local val
            val, i = parse_json_value(str, i)
            table.insert(arr, val)
        end
    elseif c == '"' then
        local j = i + 1
        local escaped = false
        local res = ""
        while j <= #str do
            local ch = str:sub(j, j)
            if escaped then
                if ch == "n" then
                    res = res .. "\n"
                elseif ch == "r" then
                    res = res .. "\r"
                elseif ch == "t" then
                    res = res .. "\t"
                elseif ch == "b" then
                    res = res .. "\b"
                elseif ch == "f" then
                    res = res .. "\f"
                elseif ch == '"' then
                    res = res .. '"'
                elseif ch == "\\" then
                    res = res .. "\\"
                elseif ch == "/" then
                    res = res .. "/"
                elseif ch == "u" and j + 4 <= #str then
                    local hex = str:sub(j + 1, j + 4)
                    local cp = tonumber(hex, 16)
                    if cp and cp < 128 then
                        res = res .. string.char(cp)
                    else
                        res = res .. "\\u" .. hex
                    end
                    j = j + 4
                else
                    res = res .. ch
                end
                escaped = false
            elseif ch == "\\" then
                escaped = true
            elseif ch == '"' then
                return res, j + 1
            else
                res = res .. ch
            end
            j = j + 1
        end
        error("unterminated string")
    elseif str:sub(i, i + 3) == "true" then
        return true, i + 4
    elseif str:sub(i, i + 4) == "false" then
        return false, i + 5
    elseif str:sub(i, i + 3) == "null" then
        return nil, i + 4
    else
        local num_str = str:match("^[-0-9%.eE]+", i)
        if num_str then
            return tonumber(num_str), i + #num_str
        end
        error("unexpected character: " .. c)
    end
end

local function json_decode(str)
    if not str or str == "" then return nil end
    local ok, res = pcall(function()
        local val, next_i = parse_json_value(str, 1)
        if next_i then
            local rest = str:find("%S", next_i)
            if rest then error("trailing garbage") end
        end
        return val
    end)
    if ok then return res else return nil end
end


-- ----------------------------------------------------------------------------
-- Helpers
-- ----------------------------------------------------------------------------
local function str(v)
    if v == nil then return "" end
    if type(v) == "number" and v == math.floor(v) and math.abs(v) < 2^53 then
        return string.format("%d", v)
    end
    return tostring(v)
end

local function add_if(tree, field, v)
    if v ~= nil then tree:add(field, v) end
end

local function add_uint(tree, field, v)
    if type(v) == "number" and v >= 0 then tree:add(field, math.floor(v)) end
end

local function short(h)
    if type(h) == "string" and #h >= 8 then return string.sub(h, 1, 8) .. "..." end
    return "none"
end

local KNOWN_KINDS = { model_turn = true, intent = true, result = true, v1_turn = true }

-- ----------------------------------------------------------------------------
-- Volume 2 operational event
-- ----------------------------------------------------------------------------
local function dissect_event(data, buffer, pinfo, tree)
    local kind = data.kind
    local turn = data.turn
    local tool = data.tool
    local subtree = tree:add(fgat_proto, buffer(),
        string.format("Forensic-Grade Agent Telemetry, %s, turn %s", str(kind), str(turn)))

    local t_id = subtree:add("Record")
    t_id:add(f_session_id, str(data.session_id))
    add_uint(t_id, f_seq, data.seq)
    t_id:add(f_kind, str(kind))
    add_uint(t_id, f_turn, turn)
    if data.ts ~= nil then
        t_id:add(f_ts, type(data.ts) == "number" and string.format("%.6f", data.ts) or str(data.ts))
    end
    if not KNOWN_KINDS[kind] then
        t_id:add_expert_info(PI_MALFORMED, PI_WARN, "Unknown FGAT record kind: " .. str(kind))
    end

    local info
    if kind == "model_turn" then
        local calls = {}
        for _, n in ipairs(type(data.tool_calls) == "table" and data.tool_calls or {}) do
            table.insert(calls, str(n))
        end
        local t_m = subtree:add("Model Turn")
        add_if(t_m, f_latency, data.latency_s ~= nil and str(data.latency_s) or nil)
        t_m:add(f_tool_calls, table.concat(calls, ","))
        local flags = {}
        if data.trimmed ~= nil then t_m:add(f_trimmed, data.trimmed == true) end
        if data.payload_in_window ~= nil then t_m:add(f_payload_in, data.payload_in_window == true) end
        if data.canary_in_window ~= nil then t_m:add(f_canary_in, data.canary_in_window == true) end
        if data.doc_in_window ~= nil then t_m:add(f_doc_in, data.doc_in_window == true) end
        if data.trimmed == true then
            table.insert(flags, "TRIMMED")
            t_m:add_expert_info(PI_SEQUENCE, PI_NOTE, "Window trimmed: older messages not sent to the model")
        end
        if data.payload_in_window == true then
            table.insert(flags, "PAYLOAD IN WINDOW")
            t_m:add_expert_info(PI_SECURITY, PI_NOTE, "Injected payload is in the model's window")
        end
        if data.canary_in_window == true then table.insert(flags, "CANARY IN WINDOW") end
        info = string.format("model_turn calls=[%s]", table.concat(calls, ","))
        if #flags > 0 then info = info .. " [" .. table.concat(flags, "] [") .. "]" end
    elseif kind == "intent" then
        local t_i = subtree:add("Tool Intent")
        t_i:add(f_tool, str(tool))
        t_i:add(f_classify, str(data.classify))
        t_i:add(f_branch, str(data.branch))
        if data.allowed ~= nil then t_i:add(f_allowed, data.allowed == true) end
        info = string.format("intent %s | %s via %s", str(tool),
            data.allowed == true and "ALLOWED" or "REFUSED", str(data.branch))
        if data.allowed == false then
            info = info .. " [REFUSED]"
            t_i:add_expert_info(PI_SECURITY, PI_WARN,
                string.format("Tool call refused: %s (classify=%s, branch=%s)", str(tool), str(data.classify), str(data.branch)))
        elseif data.branch == "auto_approve" then
            info = info .. " [AUTO-APPROVED]"
            t_i:add_expert_info(PI_SECURITY, PI_NOTE,
                string.format("Allowed by auto-approve, not by policy: %s (classify=%s)", str(tool), str(data.classify)))
        end
    elseif kind == "result" then
        local t_r = subtree:add("Tool Result")
        t_r:add(f_tool, str(tool))
        add_uint(t_r, f_result_bytes, data.result_bytes)
        info = string.format("result %s (%s bytes)", str(tool), str(data.result_bytes))
    elseif kind == "v1_turn" then
        local t_v = subtree:add("Volume 1 Turn (mapped)")
        t_v:add(f_tool, str(tool))
        t_v:add(f_classify, str(data.classify))
        add_if(t_v, f_rule_id, data.rule_id)
        if type(data.exit_code) == "number" then t_v:add(f_exit_code, data.exit_code) end
        info = string.format("v1_turn %s | %s", str(tool), string.upper(str(data.classify)))
    else
        info = "kind " .. str(kind)
    end

    local t_c = subtree:add("Collector")
    add_if(t_c, f_ingest_utc, data.host_ingest_utc)
    add_uint(t_c, f_sender_uid, data.sender_uid)
    t_c:add(f_block_hash, str(data.block_hash))
    if data.block_hash == nil then
        t_c:add_expert_info(PI_MALFORMED, PI_WARN, "No block_hash: event cannot be matched to the journal")
    end

    local seq = data.seq ~= nil and (" #" .. str(data.seq)) or ""
    pinfo.cols.info = string.format("[%s%s T%s] %s | Block: %s",
        str(data.session_id), seq, str(turn), info, short(data.block_hash))
end

-- ----------------------------------------------------------------------------
-- Volume 1 full per-turn record (legacy)
-- ----------------------------------------------------------------------------
local function dissect_v1(data, buffer, pinfo, tree)
    local turn_id    = data.turn_id or 0
    local model_info = type(data.model_metadata) == "table" and data.model_metadata or {}
    local ctx_delta  = type(data.context_delta) == "table" and data.context_delta or {}
    local compacted  = (ctx_delta.compacted == true)
    local ingress    = type(data.ingress_hashes) == "table" and data.ingress_hashes or {}
    local action     = type(data.proposed_action) == "table" and data.proposed_action or {}
    local tool_name  = action.name or "unknown"
    local tool_params = ""
    if type(action.parameters) == "table" then
        if action.parameters.command then
            tool_params = tostring(action.parameters.command)
        elseif action.parameters.path then
            tool_params = tostring(action.parameters.path)
        else
            tool_params = "JSON"
        end
    elseif action.parameters ~= nil then
        tool_params = tostring(action.parameters)
    end
    local gate       = type(data.gate_verdict) == "table" and data.gate_verdict or {}
    local verdict    = tostring(gate.status or "unknown")
    local rule_id    = gate.rule_id or "none"
    local is_denied  = (verdict:lower() == "deny" or verdict:lower() == "block")
    local result     = type(data.execution_result) == "table" and data.execution_result or {}
    local exit_code  = result.exit_code or 0
    local chain      = type(data._chain) == "table" and data._chain or {}
    local prev_hash  = chain.prev_hash or "0"
    local block_hash = chain.block_hash or "0"

    local alert_tag = compacted and " [COMPACTION ALERT]" or ""
    local verdict_tag = is_denied and " [POLICY VIOLATION]" or ""
    pinfo.cols.info = string.format("[v1 Turn %s] %s(%s) | Gate: %s%s%s | Block: %s",
        str(turn_id), tool_name, tool_params, string.upper(verdict), alert_tag, verdict_tag, short(block_hash))

    local subtree = tree:add(fgat_proto, buffer(), string.format(
        "Forensic-Grade Agent Telemetry (Volume 1 record), Turn %s: %s [%s]", str(turn_id), tool_name, string.upper(verdict)))

    local t_ident = subtree:add("1. Agent Identity & Serving Metadata")
    t_ident:add(f_session_id, str(data.session_id or "unknown"))
    t_ident:add(f_kind, "v1_record")
    add_uint(t_ident, f_turn, turn_id)
    t_ident:add(f_ts, str(data.timestamp_utc))
    t_ident:add(f_v1_model_name, str(model_info.name or "unknown"))
    t_ident:add(f_v1_model_prov, str(model_info.provider or "unknown"))

    local t_prompt = subtree:add("2. System Instructions & Context State")
    t_prompt:add(f_v1_sys_hash, str(data.system_prompt_hash))
    t_prompt:add(f_v1_compacted, compacted)
    if compacted then
        t_prompt:add_expert_info(PI_SECURITY, PI_WARN, "Context auto-compaction occurred in this turn! Input prompt may be evicted.")
    end

    local t_ingress = subtree:add(string.format("3. Untrusted Ingress Artifacts (%d objects)", #ingress))
    t_ingress:add(f_v1_ing_count, #ingress)
    for idx, item in ipairs(ingress) do
        item = type(item) == "table" and item or {}
        local item_tree = t_ingress:add(string.format("Artifact #%d: %s", idx, str(item.source or "unknown")))
        item_tree:add(f_v1_ing_source, str(item.source))
        item_tree:add(f_v1_ing_sha256, str(item.sha256))
    end

    local t_action = subtree:add("4. Tool Execution Boundary & Gate Verdict")
    t_action:add(f_v1_manifest, str(data.tool_manifest_hash))
    t_action:add(f_tool, tool_name)
    t_action:add(f_v1_params, tool_params)
    t_action:add(f_classify, verdict)
    t_action:add(f_rule_id, str(rule_id))
    if type(exit_code) == "number" then t_action:add(f_exit_code, exit_code) end
    if is_denied then
        t_action:add_expert_info(PI_SECURITY, PI_WARN, string.format("Tool execution BLOCKED by gate policy: %s", str(rule_id)))
    end
    if exit_code ~= 0 and not is_denied then
        t_action:add_expert_info(PI_RESPONSE_CODE, PI_WARN, string.format("Tool execution returned non-zero exit code: %s", str(exit_code)))
    end

    local t_chain = subtree:add("5. Evidentiary Hash Chain")
    t_chain:add(f_v1_prev_hash, str(prev_hash))
    t_chain:add(f_block_hash, str(block_hash))
end

-- ----------------------------------------------------------------------------
-- Dissector Function
-- ----------------------------------------------------------------------------
function fgat_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    local data = json_decode(buffer():string())
    pinfo.cols.protocol = "FGAT"

    if not data or type(data) ~= "table" then
        pinfo.cols.info = "[MALFORMED] Non-JSON or Corrupted FGAT Payload"
        local subtree = tree:add(fgat_proto, buffer(), "Forensic-Grade Agent Telemetry [MALFORMED / NON-JSON]")
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Payload is not valid FGAT JSON telemetry")
        return
    end

    if data.kind == nil and data.proposed_action ~= nil then
        dissect_v1(data, buffer, pinfo, tree)
    else
        dissect_event(data, buffer, pinfo, tree)
    end
end

-- Register dissector for UDP port 9999
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, fgat_proto)
