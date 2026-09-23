-- ============================================================================
-- Wireshark Lua Dissector for Forensic-Grade Agent Telemetry (FGAT)
-- Protocol: FGAT over UDP port 9999
-- Security Sonar (c) 2026 Peter Campbell
-- ============================================================================

local fgat_proto = Proto("FGAT", "Forensic-Grade Agent Telemetry (FGAT)")

-- ----------------------------------------------------------------------------
-- Field Declarations (Enables Wireshark Display Filters like fgat.turn_id == 5)
-- ----------------------------------------------------------------------------
local f_session_id     = ProtoField.string("fgat.session_id", "Session ID")
local f_turn_id        = ProtoField.uint32("fgat.turn_id", "Turn ID")
local f_timestamp      = ProtoField.string("fgat.timestamp", "Timestamp (UTC)")
local f_model_name     = ProtoField.string("fgat.model_name", "Model Name")
local f_model_provider = ProtoField.string("fgat.model_provider", "Model Provider")
local f_sys_hash       = ProtoField.string("fgat.system_prompt_hash", "System Prompt Hash (SHA-256)")
local f_compacted      = ProtoField.bool("fgat.compacted", "Context Compacted")
local f_manifest_hash  = ProtoField.string("fgat.tool_manifest_hash", "Tool Manifest Hash (SHA-256)")
local f_tool_name      = ProtoField.string("fgat.tool_name", "Proposed Tool")
local f_tool_params    = ProtoField.string("fgat.tool_params", "Tool Parameters")
local f_gate_verdict   = ProtoField.string("fgat.gate_verdict", "Gate Verdict")
local f_gate_rule      = ProtoField.string("fgat.gate_rule", "Gate Rule ID")
local f_exit_code      = ProtoField.int32("fgat.exit_code", "Execution Exit Code")
local f_ingress_count  = ProtoField.uint32("fgat.ingress_count", "Ingress Artifact Count")
local f_ingress_source = ProtoField.string("fgat.ingress_source", "Ingress Source")
local f_ingress_sha256 = ProtoField.string("fgat.ingress_sha256", "Ingress SHA-256")
local f_prev_hash      = ProtoField.string("fgat.chain_prev_hash", "Previous Block Hash")
local f_block_hash     = ProtoField.string("fgat.chain_block_hash", "Current Block Hash")

fgat_proto.fields = {
    f_session_id, f_turn_id, f_timestamp, f_model_name, f_model_provider,
    f_sys_hash, f_compacted, f_manifest_hash, f_tool_name, f_tool_params,
    f_gate_verdict, f_gate_rule, f_exit_code,
    f_ingress_count, f_ingress_source, f_ingress_sha256,
    f_prev_hash, f_block_hash
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
-- Dissector Function
-- ----------------------------------------------------------------------------
function fgat_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    local payload_str = buffer():string()
    local data = json_decode(payload_str)

    pinfo.cols.protocol = "FGAT"

    if not data or type(data) ~= "table" then
        pinfo.cols.info = "[MALFORMED] Non-JSON or Corrupted FGAT Payload"
        local subtree = tree:add(fgat_proto, buffer(), "Forensic-Grade Agent Telemetry [MALFORMED / NON-JSON]")
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Payload is not valid FGAT JSON telemetry")
        return
    end

    -- Extract Key Provenance Tuple elements
    local turn_id   = data.turn_id or 0
    local session_id = data.session_id or "unknown"
    local timestamp = data.timestamp_utc or ""
    local model_info = data.model_metadata or {}
    local model_name = model_info.name or "unknown"
    local model_prov = model_info.provider or "unknown"
    local sys_hash  = data.system_prompt_hash or ""
    
    local ctx_delta = data.context_delta or {}
    local compacted = (ctx_delta.compacted == true)
    
    local ingress   = data.ingress_hashes or {}
    local manifest  = data.tool_manifest_hash or ""
    
    local action    = data.proposed_action or {}
    local tool_name = action.name or "unknown"
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

    local gate      = data.gate_verdict or {}
    local verdict   = gate.status or "unknown"
    local rule_id   = gate.rule_id or "none"
    local is_denied = (verdict:lower() == "deny" or verdict:lower() == "block")

    local result    = data.execution_result or {}
    local exit_code = result.exit_code or 0

    local chain     = data._chain or {}
    local prev_hash = chain.prev_hash or "0"
    local block_hash= chain.block_hash or "0"

    -- Update Wireshark Packet List Info Column
    local alert_tag = compacted and " [COMPACTION ALERT]" or ""
    local verdict_tag = is_denied and " [POLICY VIOLATION]" or ""
    pinfo.cols.info = string.format("[Turn %d] %s(%s) | Gate: %s%s%s | Block: %s...", 
                                    turn_id, tool_name, tool_params, string.upper(verdict), alert_tag, verdict_tag, string.sub(block_hash, 1, 8))

    -- Populate Wireshark Protocol Tree
    local subtree = tree:add(fgat_proto, buffer(), string.format("Forensic-Grade Agent Telemetry, Turn %d: %s [%s]", turn_id, tool_name, string.upper(verdict)))
    
    local t_ident = subtree:add("1. Agent Identity & Serving Metadata")
    t_ident:add(f_session_id, session_id)
    t_ident:add(f_turn_id, turn_id)
    t_ident:add(f_timestamp, timestamp)
    t_ident:add(f_model_name, model_name)
    t_ident:add(f_model_provider, model_prov)

    local t_prompt = subtree:add("2. System Instructions & Context State")
    t_prompt:add(f_sys_hash, sys_hash)
    t_prompt:add(f_compacted, compacted)
    if compacted then
        t_prompt:add_expert_info(PI_SECURITY, PI_WARN, "Context auto-compaction occurred in this turn! Input prompt may be evicted.")
    end

    local t_ingress = subtree:add(string.format("3. Untrusted Ingress Artifacts (%d objects)", #ingress))
    t_ingress:add(f_ingress_count, #ingress)
    for idx, item in ipairs(ingress) do
        local item_tree = t_ingress:add(string.format("Artifact #%d: %s", idx, item.source or "unknown"))
        item_tree:add(f_ingress_source, item.source or "")
        item_tree:add(f_ingress_sha256, item.sha256 or "")
    end

    local t_action = subtree:add("4. Tool Execution Boundary & Gate Verdict")
    t_action:add(f_manifest_hash, manifest)
    t_action:add(f_tool_name, tool_name)
    t_action:add(f_tool_params, tool_params)
    t_action:add(f_gate_verdict, verdict)
    t_action:add(f_gate_rule, rule_id)
    t_action:add(f_exit_code, exit_code)
    if is_denied then
        t_action:add_expert_info(PI_SECURITY, PI_WARN, string.format("Tool execution BLOCKED by gate policy: %s", rule_id))
    end
    if exit_code ~= 0 and not is_denied then
        t_action:add_expert_info(PI_RESPONSE_CODE, PI_WARN, string.format("Tool execution returned non-zero exit code: %d", exit_code))
    end

    local t_chain = subtree:add("5. Evidentiary Hash Chain (Non-Repudiation)")
    t_chain:add(f_prev_hash, prev_hash)
    t_chain:add(f_block_hash, block_hash)
end

-- Register dissector for UDP port 9999
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9999, fgat_proto)
