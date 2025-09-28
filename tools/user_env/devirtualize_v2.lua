-- devirtualize_v2.lua
-- Self-contained runner that hooks initv4-style bootstraps and captures
-- the unpackedData table that Luraph passes into LuraphInterpreter.
--
-- Usage:
--   luajit devirtualize_v2.lua <script_key>
--
-- Expected layout:
--   initv4.lua            -- bootstrapper
--   Obfuscated.json       -- payload (JSON text)
--   tools/user_env/lifter.lua  -- opcode lifter scaffold
--
-- The runner installs a debug hook that inspects call frames. When the
-- bootstrap calls `LuraphInterpreter(unpackedData, env)` the hook grabs the
-- first local (the unpacked table), serialises it for later inspection, and
-- then allows execution to continue. Once captured, the lifter scaffold is
-- invoked to write human-readable IR artefacts next to the bootstrap files.

local script_key = arg[1] or os.getenv("SCRIPT_KEY") or "ppcg208ty9nze5wcoldxh"
local bootstrap_path = "initv4.lua"
local payload_path = "Obfuscated.json"
local dump_lua_path = "unpacked_dump.lua"
local dump_json_path = "unpacked_dump.json"
local lifter_path = "tools/user_env/lifter.lua"

local function read_all(path)
  local f, err = io.open(path, "rb")
  if not f then
    error("devirtualize_v2: unable to open " .. path .. ": " .. tostring(err))
  end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_file(path, contents)
  local parent = path:match("^(.+)/[^"]+")
  if parent then
    os.execute(string.format("mkdir -p %s", parent))
  end
  local f, err = io.open(path, "wb")
  if not f then
    error("devirtualize_v2: unable to write " .. path .. ": " .. tostring(err))
  end
  f:write(contents)
  f:close()
end

local function encode_json(value, indent)
  indent = indent or 0
  local buffer = {}
  local pad = string.rep(" ", indent)
  local function emit(s) buffer[#buffer + 1] = s end

  local t = type(value)
  if t == "nil" then
    emit("null")
  elseif t == "boolean" then
    emit(value and "true" or "false")
  elseif t == "number" then
    emit(tostring(value))
  elseif t == "string" then
    emit(string.format("\"%s\"", value:gsub("\\", "\\\\"):gsub("\"", "\\\"")))
  elseif t == "table" then
    -- Detect array-like tables
    local is_array = true
    local count = 0
    for k, _ in pairs(value) do
      if type(k) ~= "number" then
        is_array = false
        break
      end
      if k > count then count = k end
    end
    if is_array then
      emit("[")
      for i = 1, count do
        if i > 1 then emit(", ") end
        emit(encode_json(value[i], indent + 2))
      end
      emit("]")
    else
      emit("{\n")
      local first = true
      for k, v in pairs(value) do
        if not first then emit(",\n") end
        first = false
        emit(pad .. "  " .. encode_json(tostring(k)) .. ": " .. encode_json(v, indent + 2))
      end
      emit("\n" .. pad .. "}")
    end
  else
    emit("\"<" .. t .. ">\"")
  end
  return table.concat(buffer)
end

local captured_unpacked = nil
local function hook()
  local info = debug.getinfo(2, "n")
  if info and info.name == "LuraphInterpreter" then
    local name, value = debug.getlocal(2, 1)
    if name and value then
      captured_unpacked = value
      debug.sethook() -- remove hook once captured
    end
  end
end

debug.sethook(hook, "c")

-- Expose script_key to bootstrap
_G.script_key = script_key
if type(getgenv) == "function" then
  getgenv().script_key = script_key
end

-- Execute bootstrap
local chunk, err = loadfile(bootstrap_path)
if not chunk then
  error("devirtualize_v2: cannot load " .. bootstrap_path .. ": " .. tostring(err))
end

local ok, run_err = pcall(chunk)
if not ok then
  io.stderr:write("Bootstrap execution failed: " .. tostring(run_err) .. "\n")
end

if not captured_unpacked then
  error("devirtualize_v2: failed to capture unpackedData. Ensure the bootstrap uses LuraphInterpreter and try instrumenting manually.")
end

-- Serialise the captured table for Python consumption
local function dump_table(tbl, indent)
  indent = indent or 0
  local pad = string.rep(" ", indent)
  local buffer = {"return {\n"}
  for k, v in pairs(tbl) do
    local key_repr = tostring(k)
    local value_repr
    if type(v) == "table" then
      value_repr = dump_table(v, indent + 2)
    elseif type(v) == "string" then
      value_repr = string.format("%q", v)
    else
      value_repr = tostring(v)
    end
    buffer[#buffer + 1] = string.format("%s  [%s] = %s,\n", pad, key_repr, value_repr)
  end
  buffer[#buffer + 1] = pad .. "}\n"
  return table.concat(buffer)
end

write_file(dump_lua_path, dump_table(captured_unpacked))
write_file(dump_json_path, encode_json(captured_unpacked, 0))

-- Call lifter scaffold
local lifter, lifter_err = loadfile(lifter_path)
if not lifter then
  error("devirtualize_v2: unable to load lifter.lua: " .. tostring(lifter_err))
end

local ok_lifter, lifter_run_err = pcall(lifter, captured_unpacked, {
  script_key = script_key,
  payload_path = payload_path,
  dump_lua = dump_lua_path,
  dump_json = dump_json_path,
})
if not ok_lifter then
  error("devirtualize_v2: lifter failed: " .. tostring(lifter_run_err))
end

print("[devirtualize_v2] captured unpackedData and invoked lifter scaffold")
