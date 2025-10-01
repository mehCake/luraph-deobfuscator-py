package.path = package.path .. ";./tools/?.lua;./tools/?/init.lua;./tools/shims/?.lua"

local script_key = arg and arg[1] or os.getenv("SCRIPT_KEY") or ""
local json_path = (arg and arg[2]) or "Obfuscated.json"
local out_dir = (arg and (arg[4] or arg[3])) or "out"
local logs_dir = out_dir .. "/logs"

-- BEGIN shim preload
local dumper = dofile("tools/lua_dumper.lua")
local shim_ok, shim_err = pcall(dofile, "tools/globals_shim.lua")
if not shim_ok then
  io.stderr:write("[devirtualize_v3] failed to load globals_shim.lua: " .. tostring(shim_err) .. "\n")
end

_G.script_key = script_key
if type(getgenv) == "function" then
  local ok, env = pcall(getgenv)
  if ok and type(env) == "table" then
    env.script_key = script_key
  end
end

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

do
  local shim_module
  local ok_shim, shim_candidate = pcall(dofile, "tools/shims/initv4_shim.lua")
  if ok_shim and type(shim_candidate) == "table" and type(shim_candidate.install) == "function" then
    shim_module = shim_candidate
  else
    local ok_req, shim_required = pcall(require, "tools.shims.initv4_shim")
    if ok_req and type(shim_required) == "table" and type(shim_required.install) == "function" then
      shim_module = shim_required
    end
  end
  if shim_module then
    local ok_install, err_install = pcall(shim_module.install, _G, { out_dir = out_dir })
    if not ok_install then
      io.stderr:write("[devirtualize_v3] shim install failed: " .. tostring(err_install) .. "\n")
    end
  end
end
-- END shim preload

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

local function write_failure(message)
  write_file(out_dir .. '/failure_report.txt', message or '')
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

local function emit_status(status, message, extra)
  local payload = { status = status }
  if message then
    payload.message = message
  end
  if extra then
    for k, v in pairs(extra) do
      payload[k] = v
    end
  end
  local encoded = dumper.to_json(payload)
  io.stdout:write(encoded .. "\n")
  if status ~= 'ok' then
    local details = message or 'unknown failure'
    if extra then
      local lines = {}
      for k, v in pairs(extra) do
        lines[#lines + 1] = tostring(k) .. ': ' .. tostring(v)
      end
      if #lines > 0 then
        details = details .. "\n" .. table.concat(lines, "\n")
      end
    end
    write_failure(details)
  end
end

local function is_vm_data_shape(tbl)
  if type(tbl) ~= "table" then
    return false
  end
  local instructions = tbl[4]
  if type(instructions) ~= "table" or #instructions == 0 then
    return false
  end
  local first = instructions[1]
  if type(first) ~= "table" then
    return false
  end
  return type(first[3]) == "number"
end

local raw_json, json_err = read_all(json_path)
if not raw_json then
  emit_status("error", "failed to read Obfuscated.json", { error = json_err or "unknown" })
  os.exit(1)
end

write_file(out_dir .. "/bootstrap_blob.b64.txt", base64_encode(raw_json))

local ok, load_err = pcall(function()
  _G.LPH_String = raw_json
  _G.ObfuscatedJSON = raw_json
  _G.arg = arg
  local loader, err = loadfile("initv4.lua")
  if not loader then
    error("failed to load initv4.lua: " .. tostring(err))
  end
  local result = loader()
  if type(result) == "function" then
    local ok_func, err_func = pcall(result)
    if not ok_func then
      error(err_func)
    end
  end
end)

if not ok then
  log("initv4.lua execution failed: " .. tostring(load_err))
end

local candidates = {}
if type(_G.unpackedData) == "table" then
  candidates[#candidates + 1] = _G.unpackedData
end
if type(_G.decoded_output) == "table" then
  candidates[#candidates + 1] = _G.decoded_output
end
if type(_G.DecodedLuraphScript) == "table" then
  candidates[#candidates + 1] = _G.DecodedLuraphScript
end

if type(getgenv) == "function" then
  local ok_env, env = pcall(getgenv)
  if ok_env and type(env) == "table" then
    if type(env.unpackedData) == "table" then
      candidates[#candidates + 1] = env.unpackedData
    end
    if type(env.decoded_output) == "table" then
      candidates[#candidates + 1] = env.decoded_output
    end
  end
end

local function scan_table(tbl, seen)
  seen = seen or {}
  if seen[tbl] then
    return nil
  end
  seen[tbl] = true
  if is_vm_data_shape(tbl) then
    return tbl
  end
  for _, v in pairs(tbl) do
    if type(v) == "table" then
      local found = scan_table(v, seen)
      if found then
        return found
      end
    end
  end
  return nil
end

for _, value in ipairs(candidates) do
  if is_vm_data_shape(value) then
    candidates = { value }
    break
  end
end

local unpacked = nil
for _, value in ipairs(candidates) do
  if is_vm_data_shape(value) then
    unpacked = value
    break
  end
end

if not unpacked and type(_G) == "table" then
  unpacked = scan_table(_G, {})
end

if not unpacked then
  emit_status("error", "could not locate unpackedData table", { stderr = "see out/logs/deobfuscation.log" })
  os.exit(1)
end

local ok_lua, err_lua = write_file(out_dir .. "/unpacked_dump.lua", "return " .. dumper.to_lua_literal(unpacked))
if not ok_lua then
  log("failed to write unpacked_dump.lua: " .. tostring(err_lua))
end

local json_written = false
local has_cjson, cjson = pcall(require, "cjson")
if has_cjson and cjson then
  local status, encoded = pcall(cjson.encode, unpacked)
  if status then
    json_written = write_file(out_dir .. "/unpacked_dump.json", encoded)
  end
end

if not json_written then
  write_file(out_dir .. "/unpacked_dump.json", dumper.to_json(unpacked))
end

if type(_G.__SHIM_USED) == "table" then
  local entries = {}
  for name, count in pairs(_G.__SHIM_USED) do
    entries[#entries + 1] = string.format("%s %d", tostring(name), tonumber(count) or 0)
  end
  table.sort(entries)
  write_file(out_dir .. "/shim_usage.txt", table.concat(entries, "\n"), "wb")
end

emit_status("ok", nil, { dump = out_dir .. "/unpacked_dump.json" })
os.exit(0)
