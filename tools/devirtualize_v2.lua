-- devirtualize_v2.lua
-- Run: luajit devirtualize_v2.lua <script_key>
-- Purpose:
--   Deterministically capture 'unpackedData' produced by the Luraph bootstrap,
--   regardless of call depth / naming. Falls back through several strategies:
--     A) Direct call to LPH_UnpackData if present
--     B) debug.sethook interception of the interpreter call frame
--     C) Global/getgenv() scan for a table with the expected vm shape

local SCRIPT_KEY = arg[1] or os.getenv("SCRIPT_KEY") or "ppcg208ty9nze5wcoldxh"
_G.script_key = SCRIPT_KEY
if type(getgenv) == "function" then getgenv().script_key = SCRIPT_KEY end

local function write_file(name, data)
  local f = assert(io.open(name, "wb")); f:write(data); f:close()
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
print("[ok] wrote unpacked_dump.lua")

-- Optional: run lifter (if present)
local ok, lifter = pcall(function() return dofile("tools/lifter.lua") end)
if ok and lifter and lifter.lift then
  local ir, rep, inferred = lifter.lift(captured_unpacked)
  if ir then
    write_file("lift_ir.lua", "return "..dump_lua(ir))
    write_file("lift_report.txt", rep or "")
    if inferred then
      write_file("lift_inferred.lua", "return "..dump_lua(inferred))
    end
    print("[ok] wrote lift_ir.lua, lift_report.txt, lift_inferred.lua")
  end
end
