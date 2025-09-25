local encoded = [[local alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+,-./:;<=>?@[]^_`{|}~"

local MAXSTACK = 250
local NUPVAL = 12
local NUM_REGS = 255
local DISPATCH_ENTRIES = 46

local dispatch = {
  [0x00] = "NOP",
  [0x01] = "LOADK",
  [0x02] = "LOADBOOL",
  [0x03] = "LOADNIL",
  [0x04] = "GETUPVAL",
  [0x05] = "GETGLOBAL",
  [0x06] = "GETTABLE",
  [0x07] = "SETGLOBAL",
  [0x08] = "SETUPVAL",
  [0x09] = "SETTABLE",
  [0x0A] = "NEWTABLE",
  [0x0B] = "SELF",
  [0x0C] = "ADD",
  [0x0D] = "SUB",
  [0x0E] = "MUL",
  [0x0F] = "DIV",
  [0x10] = "MOVE",
  [0x11] = "LOADKX",
  [0x12] = "JMP",
  [0x13] = "CALL",
  [0x14] = "TAILCALL",
  [0x15] = "RETURN",
  [0x16] = "FORITER",
  [0x17] = "TFORCALL",
  [0x18] = "SETLIST",
  [0x19] = "CLOSURE",
  [0x1A] = "VARARG",
  [0x22] = "CONCAT",
  [0x28] = "JMP"
}

dispatch[0x29] = "FORPREP"
dispatch[0x2A] = "FORLOOP"
dispatch[0x2B] = function(...) -- TFORLOOP
  return ...
end

dispatch[0x2C] = function(...) -- SETLIST
  return ...
end

case_dispatch = case_dispatch or {}
case_dispatch[0x2D] = function(...)
  return ...
end -- CLOSE

opcodes = opcodes or {}
opcodes["EXTRAARG"] = 0x2E

return {
  alphabet = alphabet,
  opcode_map = dispatch,
  constants = {
    MAXSTACK = MAXSTACK,
    NUPVAL = NUPVAL,
    NUM_REGS = NUM_REGS,
    DISPATCH_ENTRIES = DISPATCH_ENTRIES
  }
}
]]

local function decode(blob, secret)
  local out = {}
  for i = #blob, 1, -1 do
    out[#out + 1] = blob:sub(i, i)
  end
  local reversed = table.concat(out)
  out = {}
  for i = #reversed, 1, -1 do
    out[#out + 1] = reversed:sub(i, i)
  end
  return table.concat(out)
end

local secret_value = (_G.script_key or _G.scriptKey or _G.SCRIPT_KEY or '')
return load(decode(encoded, secret_value), 'fallback_chunk')()
