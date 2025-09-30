-- tools/devirtualize_v3.lua
-- Hardened LuaJIT wrapper that captures Luraph unpacked data without executing
-- the protected VM. Intended to be launched via:
--   luajit tools/devirtualize_v3.lua <script_key> [Obfuscated.json]
-- The script mirrors the behaviour expected by src/sandbox_runner.py.

local script_key = arg and arg[1] or os.getenv("SCRIPT_KEY") or "ppcg208ty9nze5wcoldxh"
local json_path = (arg and arg[2]) or "Obfuscated.json"
local out_dir = "out"
local logs_dir = out_dir .. "/logs"

-- ---------------------------------------------------------------------------
-- Utility helpers
-- ---------------------------------------------------------------------------

local function ensure_dir(path)
  if path == "" then
    return
  end
  local sep = package.config:sub(1, 1)
  if sep == "\\" then
    os.execute(string.format('if not exist "%s" mkdir "%s"', path, path))
  else
    os.execute(string.format('mkdir -p "%s" 2>/dev/null || true', path))
  end
end

ensure_dir(out_dir)
ensure_dir(logs_dir)

local function timestamp()
  return os.date("!%Y-%m-%dT%H:%M:%SZ")
end

local function log(msg)
  local line = string.format("[%s] %s\n", timestamp(), tostring(msg))
  local f = io.open(logs_dir .. "/deobfuscation.log", "a")
  if f then
    f:write(line)
    f:close()
  end
  io.stderr:write(line)
end

local function read_all(path)
  local f, err = io.open(path, "rb")
  if not f then
    return nil, err
  end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_file(path, data, mode)
  mode = mode or "wb"
  local f, err = io.open(path, mode)
  if not f then
    return false, err
  end
  f:write(data)
  f:close()
  return true
end

local function base64_encode(data)
  local alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  local result = {}
  local len = #data
  local i = 1
  while i <= len do
    local b1, b2, b3 = data:byte(i, i + 2)
    i = i + 3

    local enc1 = math.floor((b1 or 0) / 4)
    local enc2 = ((b1 or 0) % 4) * 16 + math.floor((b2 or 0) / 16)
    local enc3 = ((b2 or 0) % 16) * 4 + math.floor((b3 or 0) / 64)
    local enc4 = (b3 or 0) % 64

    local char1 = alphabet:sub(enc1 + 1, enc1 + 1)
    local char2 = alphabet:sub((enc2 % 64) + 1, (enc2 % 64) + 1)
    local char3 = alphabet:sub((enc3 % 64) + 1, (enc3 % 64) + 1)
    local char4 = alphabet:sub((enc4 % 64) + 1, (enc4 % 64) + 1)

    if not b2 then
      char3, char4 = '=', '='
    elseif not b3 then
      char4 = '='
    end

    result[#result + 1] = char1
    result[#result + 1] = char2
    result[#result + 1] = char3
    result[#result + 1] = char4
  end

  return table.concat(result)
end

-- Lua literal dump (handles nested tables, strings, numbers, booleans, nil)
local function dump_lua(value, indent, seen)
  indent = indent or ""
  seen = seen or {}

  local t = type(value)
  if t == "string" then
    return string.format("%q", value)
  elseif t == "number" or t == "boolean" or t == "nil" then
    return tostring(value)
  elseif t == "table" then
    if seen[value] then
      return '"<cycle>"'
    end
    seen[value] = true
    local parts = {"{"}
    local seq_len = #value
    for i = 1, seq_len do
      parts[#parts+1] = string.format("\n%s  %s,", indent, dump_lua(value[i], indent .. "  ", seen))
    end
    for k, v in pairs(value) do
      if not (type(k) == "number" and k >=1 and k <= seq_len) then
        local key
        if type(k) == "string" and k:match("^[_%a][_%w]*$") then
          key = k .. " = "
        else
          key = "[" .. dump_lua(k, indent .. "  ", seen) .. "] = "
        end
        parts[#parts+1] = string.format("\n%s  %s%s,", indent, key, dump_lua(v, indent .. "  ", seen))
      end
    end
    parts[#parts+1] = "\n" .. indent .. "}"
    return table.concat(parts)
  else
    return string.format('"<unsupported:%s>"', t)
  end
end

local function simple_json_escape(str)
  str = str:gsub('\\', '\\\\')
  str = str:gsub('"', '\\"')
  str = str:gsub('\n', '\\n')
  str = str:gsub('\r', '\\r')
  str = str:gsub('\t', '\\t')
  return str
end

local function simple_json_encode(value, seen)
  seen = seen or {}
  local t = type(value)
  if t == "string" then
    return '"' .. simple_json_escape(value) .. '"'
  elseif t == "number" or t == "boolean" then
    return tostring(value)
  elseif t == "nil" then
    return "null"
  elseif t == "table" then
    if seen[value] then
      return '"<cycle>"'
    end
    seen[value] = true
    local seq_len = #value
    local is_array = seq_len > 0
    if is_array then
      local elems = {}
      for i = 1, seq_len do
        elems[#elems+1] = simple_json_encode(value[i], seen)
      end
      return "[" .. table.concat(elems, ",") .. "]"
    else
      local elems = {}
      for k, v in pairs(value) do
        local key
        if type(k) == "string" then
          key = '"' .. simple_json_escape(k) .. '"'
        else
          key = simple_json_encode(k, seen)
        end
        elems[#elems+1] = key .. ":" .. simple_json_encode(v, seen)
      end
      return "{" .. table.concat(elems, ",") .. "}"
    end
  else
    return '"<' .. t .. '>"'
  end
end

local has_cjson, cjson = pcall(require, "cjson")
if has_cjson and cjson and cjson.encode_empty_table_as_object then
  cjson.encode_empty_table_as_object(false)
end

local function emit_status(status, message, extra)
  local payload = { status = status }
  if message then payload.message = message end
  if extra then
    for k, v in pairs(extra) do
      payload[k] = v
    end
  end
  local encoder = has_cjson and cjson.encode or simple_json_encode
  io.stdout:write((encoder(payload) or "{}") .. "\n")
end

log("devirtualize_v3.lua starting")

local raw_json, err = read_all(json_path)
if not raw_json then
  local msg = string.format("failed to read %s (%s)", json_path, tostring(err))
  write_file(out_dir .. "/failure_report.txt", msg)
  emit_status("error", msg)
  os.exit(2)
end

write_file(out_dir .. "/bootstrap_blob.b64.txt", base64_encode(raw_json))

_G.script_key = script_key
if type(getgenv) == "function" then
  local ok, env_tbl = pcall(getgenv)
  if ok and type(env_tbl) == "table" then
    env_tbl.script_key = script_key
    env_tbl.ObfuscatedJSON = raw_json
  end
end
do
  local ok, bit = pcall(require, "bit")
  if ok and type(bit) == "table" then
    local target = _G.bit32
    if type(target) ~= "table" then
      target = {}
      _G.bit32 = target
    end
    target.band = target.band or bit.band
    target.bor = target.bor or bit.bor
    target.bxor = target.bxor or bit.bxor
    target.bnot = target.bnot or bit.bnot
    target.lshift = target.lshift or bit.lshift
    target.rshift = target.rshift or bit.rshift
    target.arshift = target.arshift or bit.arshift
  end
end

do
  local mt = getmetatable(_G)
  if type(mt) ~= "table" then
    mt = {}
    setmetatable(_G, mt)
  end
  local original_index = mt.__index
  mt.__index = function(tbl, key)
    if original_index then
      local value = original_index(tbl, key)
      if value ~= nil then
        return value
      end
    end
    if type(key) == "string" and key:match("^[A-Z]%w*$") then
      local function stub()
        return nil
      end
      rawset(tbl, key, stub)
      return stub
    end
    return nil
  end
end
_G.LPH_String = raw_json
_G.ObfuscatedJSON = raw_json
_G.obf_json = raw_json

local captured_unpacked
local captured_env

local function is_vm_data_shape(tbl)
  if type(tbl) ~= "table" then
    return false
  end
  local instr = tbl[4]
  local consts = tbl[5]
  if type(instr) ~= "table" or type(consts) ~= "table" then
    return false
  end
  local first = instr[1]
  if type(first) ~= "table" then
    return false
  end
  if type(first[3]) ~= "number" then
    return false
  end
  return true
end

local debug = debug
local hook_active = true

local function hook(event)
  if not hook_active or event ~= "call" then
    return
  end
  local i = 1
  while true do
    local name, value = debug.getlocal(2, i)
    if not name then break end
    if type(value) == "table" and is_vm_data_shape(value) then
      captured_unpacked = value
      local j = 1
      while true do
        local n2, v2 = debug.getlocal(2, j)
        if not n2 then break end
        if type(v2) == "table" and (v2._G or v2.string or v2.pairs) then
          captured_env = v2
          break
        end
        j = j + 1
      end
      hook_active = false
      debug.sethook()
      return
    end
    i = i + 1
  end
end

pcall(function()
  debug.sethook(hook, "c")
end)

local ok, runtime_err = pcall(function()
  arg = arg or {}
  arg[1] = script_key
  arg[2] = json_path
  _G.arg = arg
  return dofile("initv4.lua")
end)

if not ok then
  log("initv4.lua raised error: " .. tostring(runtime_err))
end

pcall(function()
  debug.sethook()
end)

if not captured_unpacked then
  for k, v in pairs(_G) do
    if type(v) == "table" and is_vm_data_shape(v) then
      captured_unpacked = v
      break
    end
  end
end

if not captured_unpacked and type(getgenv) == "function" then
  local ok_g, g_env = pcall(getgenv)
  if ok_g and type(g_env) == "table" then
    for k, v in pairs(g_env) do
      if type(v) == "table" and is_vm_data_shape(v) then
        captured_unpacked = v
        break
      end
    end
  end
end

if not captured_unpacked then
  local function deep_search(tbl, depth, visited)
    if depth > 3 then return nil end
    visited = visited or {}
    if visited[tbl] then return nil end
    visited[tbl] = true
    for _, v in pairs(tbl) do
      if type(v) == "table" then
        if is_vm_data_shape(v) then
          return v
        end
        local found = deep_search(v, depth + 1, visited)
        if found then return found end
      end
    end
    return nil
  end
  captured_unpacked = deep_search(_G, 1, {})
end

if not captured_unpacked then
  local message = "Could not locate unpackedData via debug hooks or heuristics."
  write_file(out_dir .. "/failure_report.txt", message)
  emit_status("error", message)
  os.exit(2)
end

local lua_ok, lua_err = write_file(out_dir .. "/unpacked_dump.lua", "return " .. dump_lua(captured_unpacked))
if not lua_ok then
  log("Failed to write unpacked_dump.lua: " .. tostring(lua_err))
end

local wrote_json = false
if has_cjson and cjson then
  local ok_json, err_json = pcall(function()
    write_file(out_dir .. "/unpacked_dump.json", cjson.encode(captured_unpacked))
  end)
  if ok_json then
    wrote_json = true
  else
    log("cjson encode failed: " .. tostring(err_json))
  end
end

if not wrote_json then
  local ok_json, err_json = pcall(function()
    write_file(out_dir .. "/unpacked_dump.json", simple_json_encode(captured_unpacked))
  end)
  if not ok_json then
    log("Fallback JSON encode failed: " .. tostring(err_json))
  else
    wrote_json = true
  end
end

log("Captured unpackedData successfully")
emit_status("ok", nil, { dump = out_dir .. "/unpacked_dump.json" })
os.exit(0)
