-- devirtualize_v2.lua
-- Run: luajit devirtualize_v2.lua <script_key>

local SCRIPT_KEY = arg[1] or os.getenv("SCRIPT_KEY") or "ppcg208ty9nze5wcoldxh"
_G.script_key = SCRIPT_KEY
if type(getgenv) == "function" then getgenv().script_key = SCRIPT_KEY end

local function read_all(p)
  local f, e = io.open(p, "rb")
  if not f then error("Cannot open "..p..": "..tostring(e)) end
  local s = f:read("*a"); f:close(); return s
end

-- simple writer
local function write_file(name, data)
  local f = assert(io.open(name, "wb")); f:write(data); f:close()
end

-- dump table helper
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

local captured_unpacked = nil
local function is_vm_data_shape(t)
  if type(t)~="table" then return false end
  local instr = t[4]; if type(instr)~="table" or #instr==0 then return false end
  local first = instr[1]; if type(first)~="table" then return false end
  return type(first[3])=="number" and type(t[5])=="table"
end

-- hook to intercept interpreter call
local function hookFn(event, line)
  if event=="call" then
    local i=1
    while true do
      local n,v = debug.getlocal(2,i)
      if not n then break end
      if type(v)=="table" and is_vm_data_shape(v) then
        captured_unpacked=v; debug.sethook(); return
      end
      i=i+1
    end
  end
end
debug.sethook(hookFn,"c")

dofile("initv4.lua") -- loads bootstrapper
debug.sethook() -- disable

if not captured_unpacked then error("unpackedData not captured") end

write_file("unpacked_dump.lua","return "..dump_lua(captured_unpacked))
print("[ok] wrote unpacked_dump.lua")

local ok, lifter=pcall(function() return dofile("lifter.lua") end)
if ok and lifter.lift then
  local ir, rep=lifter.lift(captured_unpacked)
  if ir then
    write_file("lift_ir.lua","return "..dump_lua(ir))
    write_file("lift_report.txt",rep)
    print("[ok] wrote lift_ir.lua and lift_report.txt")
  end
end

local function try_extract()
  local candidates = { "decoded_script", "DecodedLuraphScript", "decoded_output" }
  for _, n in ipairs(candidates) do
    if rawget(_G, n) then return rawget(_G, n) end
    if type(getgenv) == "function" and getgenv()[n] then return getgenv()[n] end
  end
  for _, fnName in ipairs({ "Init", "Run", "bootstrap", "decode" }) do
    local fn = _G[fnName] or (type(getgenv)=="function" and getgenv()[fnName])
    if type(fn) == "function" then
      local ok_call, out = pcall(fn)
      if ok_call and out then return out end
    end
  end
  return nil
end

local result = try_extract()
if type(result) == "table" then
  local count = 0
  for i, chunk in ipairs(result) do
    if type(chunk) == "string" and #chunk > 0 then
      count = count + 1
      local fname = string.format("decoded_chunk_%03d.lua", i)
      write_file(fname, chunk)
      print("[ok] wrote "..fname)
    end
  end
  if count == 0 then error("Decoded table contained no string chunks.") end
elseif type(result) == "string" then
  write_file("decoded_output.lua", result)
  print("[ok] wrote decoded_output.lua")
else
  print("[warn] No decoded output recovered automatically")
end
