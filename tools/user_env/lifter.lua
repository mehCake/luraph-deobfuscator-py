-- lifter.lua
-- Minimal opcode lifter scaffold invoked by devirtualize_v2.lua.
--
-- Parameters:
--   unpacked (table)   : the unpackedData array from the bootstrapper
--   opts (table)       : optional metadata (script_key, dump paths, etc.)
--
-- Outputs:
--   lift_ir.lua        : best-effort Lua reconstruction (textual IR)
--   lift_report.txt    : diagnostic summary of opcode coverage
--
-- This is a deliberately lightweight implementation intended for researchers
-- to iterate on manually. It does not attempt to fully recover Lua bytecode;
-- instead it prints a readable pseudo-IR listing that can be compared against
-- the original script. The scaffold exposes extension hooks so contributors can
-- add opcode semantics incrementally.

local unpacked = ...
local opts = select(2, ...)

if type(unpacked) ~= "table" then
  error("lifter.lua: expected unpackedData table as first argument")
end

opts = opts or {}

local function write_file(path, contents)
  local parent = path:match("^(.+)/[^"]+")
  if parent then
    os.execute(string.format("mkdir -p %s", parent))
  end
  local f, err = io.open(path, "wb")
  if not f then error("lifter.lua: unable to write " .. path .. ": " .. tostring(err)) end
  f:write(contents)
  f:close()
end

local function escape_string(str)
  return (str:gsub("\\", "\\\\"):gsub("\"", "\\\""))
end

local DEFAULT_OPCODE_NAMES = {
  [0] = "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL",
  "GETTABLE", "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF",
  "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "UNM", "NOT", "LEN",
  "CONCAT", "JMP", "EQ", "LT", "LE", "TEST", "TESTSET", "CALL",
  "TAILCALL", "RETURN", "FORLOOP", "FORPREP", "TFORLOOP", "SETLIST",
  "CLOSE", "CLOSURE", "VARARG"
}

local opcode_names = {}
if type(opts.opcode_map) == "table" then
  for k, v in pairs(opts.opcode_map) do
    opcode_names[k] = tostring(v)
  end
end

local function op_name(code)
  if opcode_names[code] then
    return opcode_names[code]
  end
  if DEFAULT_OPCODE_NAMES[code] then
    return DEFAULT_OPCODE_NAMES[code]
  end
  return string.format("OP_%02X", code)
end

local function render_constant(value)
  local t = type(value)
  if t == "string" then
    return string.format('"%s"', escape_string(value))
  elseif t == "number" or t == "boolean" then
    return tostring(value)
  elseif t == "nil" then
    return "nil"
  else
    return string.format("<%s>", t)
  end
end

local instructions = unpacked[4]
local constants = unpacked[5]

if type(instructions) ~= "table" then
  instructions = {}
end
if type(constants) ~= "table" then
  constants = {}
end

local lines = {"-- lift_ir.lua", "-- pseudo IR extracted from unpackedData", ""}

for index, instr in ipairs(instructions) do
  if type(instr) == "table" then
    local opcode = instr[3] or instr.opcode or 0
    local a = instr[4] or instr.a or instr.A or 0
    local b = instr[5] or instr.b or instr.B or 0
    local c = instr[6] or instr.c or instr.C or 0
    local comment_parts = {}
    if instr.constant then
      table.insert(comment_parts, "const=" .. render_constant(instr.constant))
    end
    if instr[7] and type(instr[7]) == "number" and constants[instr[7]] then
      table.insert(comment_parts, "k=" .. render_constant(constants[instr[7]]))
    end
    local comment = ""
    if #comment_parts > 0 then
      comment = " -- " .. table.concat(comment_parts, ", ")
    end
    lines[#lines + 1] = string.format("%04d | %-8s A=%d B=%d C=%d%s", index, op_name(opcode), a, b, c, comment)
  else
    lines[#lines + 1] = string.format("%04d | <non-table instruction>", index)
  end
end

write_file("lift_ir.lua", table.concat(lines, "\n") .. "\n")

local report = {}
report[#report + 1] = "Luraph lifter scaffold"
report[#report + 1] = string.format("instructions captured: %d", #instructions)
report[#report + 1] = string.format("constants captured: %d", #constants)
report[#report + 1] = string.format("script_key: %s", tostring(opts.script_key))
write_file("lift_report.txt", table.concat(report, "\n") .. "\n")
