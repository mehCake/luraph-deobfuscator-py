-- tools/globals_shim.lua
--
-- Lightweight shim that defines the globals commonly referenced by Luraph
-- bootstrappers.  The shim keeps execution safe by exposing only no-op
-- placeholders and logging any usage so operators know which definitions need
-- real implementations.
--
-- The module is idempotent – calling dofile on it multiple times will simply
-- reuse the existing tables.  The script key is taken from the first CLI
-- argument when present.

local key = (type(arg) == "table" and arg[1]) or _G.script_key
if key ~= nil then
  _G.script_key = key
end

if rawget(_G, "__SHIM_INITIALISED") then
  return
end

_G.__SHIM_INITIALISED = true
_G.__SHIM_USED = _G.__SHIM_USED or {}
_G.__SHIM_LOGGED = true

local logged_names = {}

local function shim_log(name, ...)
  if not logged_names[name] then
    logged_names[name] = true
    local parts = {"[globals_shim] invoked stub ", tostring(name)}
    for i = 1, select("#", ...) do
      local v = select(i, ...)
      parts[#parts + 1] = " " .. tostring(v)
    end
    pcall(function()
      io.stderr:write(table.concat(parts) .. "\n")
    end)
  end
end

_G.__shim_log = _G.__shim_log or shim_log

local function mark_use(name)
  local count = (_G.__SHIM_USED[name] or 0) + 1
  _G.__SHIM_USED[name] = count
end

local function make_stub(name)
  return function(...)
    mark_use(name)
    shim_log(name, ...)
    return nil
  end
end

if rawget(_G, "safe_call") == nil then
  _G.safe_call = make_stub("safe_call")
end

local shim_names = {
  "L1",
  "L2",
  "L3",
  "Y",
  "Y0",
  "Y1",
  "Y2",
  "Y3",
  "L",
  "H1",
  "H2",
  "H",
  "Call",
  "Callback",
}

for _, name in ipairs(shim_names) do
  if rawget(_G, name) == nil then
    _G[name] = make_stub(name)
  end
end

if type(getgenv) == "function" then
  local ok, env = pcall(getgenv)
  if ok and type(env) == "table" then
    env.script_key = _G.script_key
    env.__SHIM_USED = _G.__SHIM_USED
  end
end

return true
