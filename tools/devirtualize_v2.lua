-- devirtualize_v2.lua
-- Run: luajit devirtualize_v2.lua <script_key>
-- Purpose:
--   Deterministically capture 'unpackedData' produced by the Luraph bootstrap,
--   regardless of call depth / naming. Falls back through several strategies:
--     A) Direct call to LPH_UnpackData if present
--     B) debug.sethook interception of the interpreter call frame
--     C) Global/getgenv() scan for a table with the expected vm shape

local ok_bit, bit = pcall(require, "bit")
if ok_bit and bit then
  if not bit32 then
    local function mask32(n)
      return bit.band(n, 0xffffffff)
    end
    bit32 = {}
    bit32.band = function(a, b) return bit.band(a, b) end
    bit32.bor = function(a, b) return bit.bor(a, b) end
    bit32.bxor = function(a, b) return bit.bxor(a, b) end
    bit32.bnot = function(a) return mask32(bit.bnot(a)) end
    bit32.lshift = function(a, b) return mask32(bit.lshift(a, b)) end
    bit32.rshift = function(a, b) return bit.rshift(a, b) end
    bit32.arshift = function(a, b) return bit.arshift(a, b) end
    bit32.lrotate = function(a, b)
      b = b % 32
      return mask32(bit.bor(bit.lshift(a, b), bit.rshift(a, 32 - b)))
    end
    bit32.rrotate = function(a, b)
      b = b % 32
      return mask32(bit.bor(bit.rshift(a, b), bit.lshift(a, 32 - b)))
    end
    bit32.countlz = function(a)
      a = bit.band(a, 0xffffffff)
      if a == 0 then return 32 end
      local n = 0
      for i = 31, 0, -1 do
        if bit.band(a, bit.lshift(1, i)) ~= 0 then break end
        n = n + 1
      end
      return n
    end
    bit32.countrz = function(a)
      a = bit.band(a, 0xffffffff)
      if a == 0 then return 32 end
      local n = 0
      for i = 0, 31 do
        if bit.band(a, bit.lshift(1, i)) ~= 0 then break end
        n = n + 1
      end
      return n
    end
    bit32.extract = function(n, field, width)
      width = width or 1
      local mask = bit.lshift(bit.lshift(1, width) - 1, field)
      return bit.rshift(bit.band(n, mask), field)
    end
    bit32.replace = function(n, value, field, width)
      width = width or 1
      local mask = bit.lshift(bit.lshift(1, width) - 1, field)
      local cleared = bit.band(n, bit.bnot(mask))
      local shifted = bit.lshift(bit.band(value, bit.lshift(1, width) - 1), field)
      return mask32(bit.bor(cleared, shifted))
    end
    bit32.tobit = mask32
  end
end

local script_dir = (debug.getinfo(1, "S").source or ""):match("@(.*/)") or ""
local function try_tool(path)
  if script_dir ~= "" then
    local full = script_dir .. path
    local ok, res = pcall(dofile, full)
    if ok then return res end
  end
  local ok, res = pcall(dofile, path)
  if ok then return res end
end

local function flatten_opcode_map(map)
  if type(map) ~= "table" then
    return nil
  end
  local out = {}
  for k, v in pairs(map) do
    if type(k) == "number" and type(v) == "string" then
      out[string.format("%d", k)] = v
    end
  end
  return out
end

local function write_file(name, data)
  local f = assert(io.open(name, "wb"))
  f:write(data)
  f:close()
end

local has_cjson, cjson = pcall(require, "cjson")

local JSON_NULL = {}

local function lua_to_basic(val, seen)
  if val == nil then
    return JSON_NULL
  end
  seen = seen or {}
  if type(val) ~= "table" then
    return val
  end
  if seen[val] then
    return "<cycle>"
  end
  seen[val] = true
  local array = {}
  local dict = {}
  local max_index = 0
  for k, _ in pairs(val) do
    if type(k) == "number" and k > max_index then
      max_index = k
    end
  end
  for i = 1, max_index do
    array[i] = lua_to_basic(rawget(val, i), seen)
  end
  for k, v in pairs(val) do
    if type(k) ~= "number" or k < 1 or k > max_index then
      dict[k] = lua_to_basic(v, seen)
    end
  end
  local out = { array = array }
  if next(dict) then
    out.map = dict
  end
  return out
end

local function write_json(name, value)
  local data
  if has_cjson then
    local ok, encoded = pcall(cjson.encode, value)
    if ok then
      data = encoded
    end
  end
  if not data then
    local function encode(val, depth)
      depth = depth or 0
      if val == JSON_NULL then
        return "null"
      end
      if type(val) == "table" then
        local is_array = true
        local arr = {}
        local i = 1
        for k, v in pairs(val) do
          if k ~= i then
            is_array = false
            break
          end
          arr[i] = encode(v, depth + 1)
          i = i + 1
        end
        if is_array then
          local out = {"["}
          for idx = 1, #arr do
            if idx > 1 then table.insert(out, ",") end
            table.insert(out, arr[idx])
          end
          table.insert(out, "]")
          return table.concat(out)
        else
          local out = {"{"}
          local first = true
          for k, v in pairs(val) do
            if not first then table.insert(out, ",") end
            first = false
            local key
            if type(k) == "number" then
              key = string.format("\"%s\"", tostring(k))
            else
              key = string.format("\"%s\"", tostring(k):gsub("\"", "\\\""))
            end
            table.insert(out, string.format("%s:%s", key, encode(v, depth + 1)))
          end
          table.insert(out, "}")
          return table.concat(out)
        end
      elseif type(val) == "string" then
        return string.format("\"%s\"", val:gsub("\\", "\\\\"):gsub("\"", "\\\""))
      elseif type(val) == "number" or type(val) == "boolean" then
        return tostring(val)
      elseif type(val) == "nil" then
        return "null"
      end
      return string.format("\"%s\"", tostring(val):gsub("\"", "\\\""))
    end
    data = encode(value, 0)
  end
  write_file(name, data)
end

local function dump_lua(val, indent, seen)
  indent, seen = indent or "", seen or {}
  if type(val) ~= "table" then
    if type(val) == "string" then return string.format("%q", val) end
    return tostring(val)
  end
  if seen[val] then return '"<cycle>"' end
  seen[val] = true
  local parts = {"{"}
  for i=1,#val do
    table.insert(parts, "\n"..indent.."  "..dump_lua(val[i], indent.."  ", seen)..",")
  end
  for k,v in pairs(val) do
    if type(k) ~= "number" or k<1 or k>#val then
      local key = "["..dump_lua(k, indent.."  ", seen).."]"
      table.insert(parts, "\n"..indent.."  "..key.."="..dump_lua(v, indent.."  ", seen)..",")
    end
  end
  table.insert(parts, "\n"..indent.."}")
  return table.concat(parts)
end

local function is_vm_data_shape(t)
  if type(t)~="table" then return false end
  local instrs = t[4]
  if type(instrs)~="table" or #instrs==0 then return false end
  local first = instrs[1]
  if type(first)~="table" or type(first[3])~="number" then return false end
  if type(t[5])~="table" then return false end
  return true
end

-- ensure script_key present
local SCRIPT_KEY = arg[1] or os.getenv("SCRIPT_KEY") or "zkzhqwk4b58pjnudvikpf"
_G.script_key = SCRIPT_KEY
if type(getgenv) == "function" then getgenv().script_key = SCRIPT_KEY end

-- read Obfuscated.json if present
local function read_all(p)
  local f, e = io.open(p, "rb")
  if not f then return nil end
  local s = f:read("*a"); f:close(); return s
end

local json_text = read_all("Obfuscated.json") or read_all(arg[2] or "")
if json_text then
  _G.LPH_String = json_text
  _G.ObfuscatedJSON = json_text
  _G.obf_json = json_text
end

-- numeric fallbacks some bootstrappers require
_G._LURAPH_FLAG_1 = _G._LURAPH_FLAG_1 or 1
_G._LURAPH_FLAG_2 = _G._LURAPH_FLAG_2 or 0

-- ensure arg table values
arg = arg or {}
arg[1] = arg[1] or SCRIPT_KEY
arg[2] = arg[2] or "Obfuscated.json"

-- 0) Load bootstrap (many initv4 auto-run the VM)
dofile("initv4.lua")

-- A) Direct call path if available (most robust)
local unpack_fn = rawget(_G, "LPH_UnpackData")
if not unpack_fn and type(getgenv)=="function" then
  unpack_fn = getgenv().LPH_UnpackData
end

local captured_unpacked = nil

if type(unpack_fn)=="function" then
  local ok, data = pcall(unpack_fn)
  if ok and is_vm_data_shape(data) then
    captured_unpacked = data
  end
end

-- B) Hook path (intercept the frame that carries 'unpackedData' into LuraphInterpreter)
if not captured_unpacked then
  local function hookFn(event)
    if event=="call" then
      local i=1
      while true do
        local name, value = debug.getlocal(2, i)
        if not name then break end
        if type(value)=="table" and is_vm_data_shape(value) then
          captured_unpacked = value; debug.sethook(); return
        end
        i=i+1
      end
    end
  end
  debug.sethook(hookFn, "c")
  -- If the VM didn't auto-run, try common entry points to tick it
  for _, n in ipairs({"VMRun","Run","Init","bootstrap","main"}) do
    local fn = rawget(_G, n) or (type(getgenv)=="function" and getgenv()[n])
    if type(fn)=="function" then pcall(function() fn("LPH!tick", _G) end) end
  end
  debug.sethook()
end

-- C) Global scan fallback
if not captured_unpacked then
  for _, space in ipairs({ _G, type(getgenv)=="function" and getgenv() or {} }) do
    for k,v in pairs(space) do
      if type(v)=="table" and is_vm_data_shape(v) then
        captured_unpacked = v; break
      end
    end
    if captured_unpacked then break end
  end
end

if not captured_unpacked then
  error("Could not capture 'unpackedData'. Adjust devirtualize_v2.lua to target your exact bootstrap.")
end

write_file("unpacked_dump.lua", "return "..dump_lua(captured_unpacked))
write_json("unpacked_dump.json", lua_to_basic(captured_unpacked))
print("[ok] wrote unpacked_dump.lua and unpacked_dump.json")

-- Optional: run lifter (if present)
local lifter = try_tool("lifter.lua")
if lifter and lifter.lift then
  local ir, rep, inferred, opcode_map = lifter.lift(captured_unpacked)
  if ir then
    write_file("lift_ir.lua", "return "..dump_lua(ir))
    write_file("lift_report.txt", rep or "")
    if inferred then
      write_file("lift_inferred.lua", "return "..dump_lua(inferred))
    end
    local flattened = flatten_opcode_map(opcode_map)
    if flattened and next(flattened) then
      write_json("lift_opcodes.json", flattened)
    end
    print("[ok] wrote lift_ir.lua, lift_report.txt, lift_inferred.lua")
  end
end
