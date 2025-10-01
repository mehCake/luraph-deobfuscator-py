-- tools/shims/initv4_shim.lua
-- Safe fallbacks for Luraph initv4 helper globals.
-- Provides lightweight implementations for helper functions (L1, Y1, ...)
-- so the bootstrapper does not abort when they are missing.  Each call is
-- logged to out/shim_usage.txt and we attempt to capture the first global
-- assignment of `unpackedData`.

local M = {}

local unpack = table.unpack or unpack

local function open_log(path)
  local ok, handle = pcall(io.open, path, "a")
  if ok and handle then
    return handle
  end
  return nil
end

local function manual_bxor(a, b)
  a = tonumber(a) or 0
  b = tonumber(b) or 0
  a = a % 256
  b = b % 256
  local result = 0
  local bit_val = 1
  for _ = 0, 7 do
    local abit = a % 2
    local bbit = b % 2
    if abit ~= bbit then
      result = result + bit_val
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bit_val = bit_val * 2
  end
  return result
end

local has_bit, bitlib = pcall(require, "bit")
local function bxor(a, b)
  if has_bit and bitlib and bitlib.bxor then
    return bitlib.bxor(a, b)
  end
  return manual_bxor(a, b)
end

local function dump_table(value, depth)
  depth = depth or 0
  if type(value) ~= "table" then
    return tostring(value)
  end
  local parts = {"{"}
  local count = 0
  for k, v in pairs(value) do
    count = count + 1
    if depth < 2 then
      parts[#parts + 1] = tostring(k) .. "=" .. dump_table(v, depth + 1)
    else
      parts[#parts + 1] = tostring(k) .. "=…"
    end
    if count >= 10 then
      break
    end
    parts[#parts + 1] = ","
  end
  parts[#parts + 1] = "}"
  return table.concat(parts)
end

local function mk_stub(name, logf, behaviour)
  return function(...)
    local args = { ... }
    if logf then
      logf:write(string.format("[shim] %s called with %d args\n", name, select("#", ...)))
      logf:flush()
    end
    if behaviour == "identity" then
      return unpack(args)
    elseif behaviour == "xor_buf" then
      local buf = args[1]
      local key = tonumber(args[2]) or 0
      if type(buf) == "table" then
        for i = 1, #buf do
          local byte = tonumber(buf[i]) or 0
          buf[i] = bxor(byte, key) % 256
        end
      end
      return buf
    elseif behaviour == "tbl_join" then
      local out = {}
      for i = 1, #args do
        local chunk = args[i]
        if type(chunk) == "table" then
          for j = 1, #chunk do
            out[#out + 1] = chunk[j]
          end
        elseif chunk ~= nil then
          out[#out + 1] = chunk
        end
      end
      return out
    elseif behaviour == "nop_true" then
      return true
    elseif behaviour == "nop_nil" then
      return nil
    end
    return args[1]
  end
end

local function try_require(module_name)
  local ok, mod = pcall(require, module_name)
  if ok then
    return mod
  end
  return nil
end

local function encode_json(tbl)
  local dkjson = try_require("dkjson")
  if dkjson and dkjson.encode then
    local ok, res = pcall(dkjson.encode, tbl, { indent = true })
    if ok then
      return res
    end
  end
  -- very small fallback encoder
  if type(tbl) ~= "table" then
    return '"' .. tostring(tbl) .. '"'
  end
  local parts = {"{"}
  local first = true
  for k, v in pairs(tbl) do
    if not first then
      parts[#parts + 1] = ","
    end
    first = false
    parts[#parts + 1] = '"' .. tostring(k) .. '":'
    if type(v) == "table" then
      parts[#parts + 1] = encode_json(v)
    elseif type(v) == "string" then
      parts[#parts + 1] = '"' .. v:gsub('"', '\\"') .. '"'
    elseif type(v) == "number" or type(v) == "boolean" then
      parts[#parts + 1] = tostring(v)
    else
      parts[#parts + 1] = '"' .. tostring(v) .. '"'
    end
  end
  parts[#parts + 1] = "}"
  return table.concat(parts)
end

local function install_unpacked_capture(env, logf, out_dir)
  env = env or _G
  local mt = getmetatable(env) or {}
  local original_newindex = mt.__newindex

  mt.__newindex = function(t, key, value)
    if key == "unpackedData" and type(value) == "table" then
      if logf then
        logf:write("[shim] captured global 'unpackedData' = " .. dump_table(value) .. "\n")
        logf:flush()
      end
      local ok, err = pcall(function()
        local encoded = encode_json(value)
        local target = out_dir .. "/unpacked_dump.lua.json"
        local fh = io.open(target, "w")
        if fh then
          fh:write(encoded)
          fh:close()
        end
      end)
      if not ok and logf then
        logf:write("[shim] failed to serialise unpackedData: " .. tostring(err) .. "\n")
        logf:flush()
      end
    end
    if original_newindex then
      return original_newindex(t, key, value)
    end
    rawset(t, key, value)
  end

  setmetatable(env, mt)
end

function M.install(env, opts)
  env = env or _G
  opts = opts or {}
  local out_dir = opts.out_dir or "out"

  local log_path = out_dir .. "/shim_usage.txt"
  local logf = open_log(log_path)

  local helpers = {
    L1 = "xor_buf",
    L2 = "identity",
    L3 = "identity",
    Y1 = "tbl_join",
    Y2 = "identity",
    Y3 = "identity",
    G1 = "identity",
    Q1 = "identity",
    Z1 = "nop_true",
  }

  for name, behaviour in pairs(helpers) do
    if env[name] == nil then
      env[name] = mk_stub(name, logf, behaviour)
    end
  end

  if logf then
    local original_print = env.print or print
    env.print = function(...)
      logf:write("[shim] print: ")
      for i = 1, select("#", ...) do
        local value = select(i, ...)
        logf:write(tostring(value) .. " ")
      end
      logf:write("\n")
      logf:flush()
      if original_print then
        pcall(original_print, ...)
      end
    end
  end

  install_unpacked_capture(env, logf, out_dir)

  if logf then
    logf:write("[shim] installed\n")
    logf:flush()
  end
end

return M
