-- tools/lifter.lua
-- Minimal Luraph → IR lifter + heuristic opcode inference

local lifter = {}

-- Seed map (extend as you discover more)
local OPCODES = {
  [0]="MOVE",[4]="LOADK",[7]="ADD",[10]="CALL",[15]="GETGLOBAL",
  [18]="GETTABLE",[22]="JMP",[27]="SETGLOBAL",[30]="SETTABLE",[31]="FORLOOP",
  [32]="FORPREP",[36]="CLOSURE",[37]="VARARG",[21]="CONCAT",[28]="CALL",[29]="TAILCALL",
  [20]="LEN",[19]="NOT",[23]="EQ",[24]="LT",[25]="LE",[26]="TEST",[27]="TESTSET",
}

local function is_array(t) return type(t)=="table" and (#t>0 or next(t)==nil) end

-- Extract lightweight "features" for each instruction tuple.
-- NOTE: Luraph tuple layout varies; we keep this generic and forgiving.
local function features(instr)
  local f = {
    has_str=false, has_num=false, num_fields=0, num_nil=0,
    max_num=nil, min_num=nil,
  }
  for i=1, math.max(#instr, 12) do
    local v = rawget(instr, i)
    local t = type(v)
    if v ~= nil then f.num_fields = f.num_fields + 1 else f.num_nil = f.num_nil + 1 end
    if t == "string" then f.has_str = true end
    if t == "number" then
      f.has_num = true
      f.max_num = (f.max_num and math.max(f.max_num, v)) or v
      f.min_num = (f.min_num and math.min(f.min_num, v)) or v
    end
  end
  -- Heuristic: many encodings keep opcode at [3]
  f.opnum = tonumber(instr[3]) or -1
  -- Candidates for A,B,C-ish slots (common: 6,7,8)
  f.A, f.B, f.C = instr[6], instr[7], instr[8]
  return f
end

-- Score rules → suggest opcode names
local function score_candidates(feat)
  local cand = {}  -- name -> score
  local function add(name, s) cand[name] = (cand[name] or 0) + s end

  -- Very rough heuristics:
  -- LOADK often touches constants (strings) and sets a single register
  if feat.has_str and feat.A and feat.B and not feat.C then add("LOADK", 2) end
  -- MOVE tends to be simple, two small regs
  if feat.A and feat.B and not feat.C and not feat.has_str then add("MOVE", 1) end
  -- CALL often has multiple small integer fields (A:target, B:args+1, C:rets+1)
  if feat.A and feat.B and feat.C and not feat.has_str then add("CALL", 2) end
  -- GETGLOBAL/SETGLOBAL frequently involve strings (global name)
  if feat.has_str and feat.A and feat.B then add("GETGLOBAL", 1); add("SETGLOBAL", 1) end
  -- GETTABLE/SETTABLE often have A,B,C all present
  if feat.A and feat.B and feat.C then add("GETTABLE", 1); add("SETTABLE", 1) end
  -- JMP tends to have a big signed offset; we detect by large max_num
  if feat.has_num and feat.max_num and math.abs(feat.max_num) > 1000 then add("JMP", 1) end
  -- CONCAT uses multiple registers, often string presence across sequence; weak signal
  if feat.has_str and feat.A and feat.B and feat.C then add("CONCAT", 1) end
  -- Arithmetic (ADD/SUB/MUL/DIV) has three registers, no strings
  if feat.A and feat.B and feat.C and not feat.has_str then
    add("ADD", 0.5); add("SUB", 0.5); add("MUL", 0.5); add("DIV", 0.5)
  end

  -- If we have a seed mapping for this opnum, bias towards it
  local seeded = OPCODES[feat.opnum]
  if seeded then add(seeded, 3) end

  -- Return sorted candidates
  local out = {}
  for name, s in pairs(cand) do out[#out+1] = {name=name, score=s} end
  table.sort(out, function(a,b) return a.score > b.score end)
  return out
end

local function toIR(data)
  local ir = {}
  local instrs = data[4]
  local consts = data[5]
  if not is_array(instrs) then return nil, "data[4] is not an instruction array" end

  local unknown = {}
  local inferred = {}   -- opnum -> { {name,score}, ... }

  for pc, instr in ipairs(instrs) do
    local opnum = tonumber(instr[3]) or -1
    local opname = OPCODES[opnum] or ("OP_"..tostring(opnum))
    local A,B,C = instr[6], instr[7], instr[8]

    -- Build IR row
    ir[#ir+1] = { pc=pc, op=opname, opnum=opnum, A=A, B=B, C=C }

    -- Inference for unknowns
    if not OPCODES[opnum] then
      unknown[opnum] = true
      local feat = features(instr)
      local cands = score_candidates(feat)
      inferred[opnum] = cands
    end
  end

  local report = {}
  report[#report+1] = ("Instructions: %d; Constants: %d"):format(#instrs, is_array(consts) and #consts or 0)
  local keys = {}
  for k in pairs(unknown) do keys[#keys+1] = k end
  table.sort(keys)
  if #keys == 0 then
    report[#report+1] = "Unknown opcodes: none"
  else
    report[#report+1] = "Unknown opcodes:"
    for _, k in ipairs(keys) do
      local line = ("  - %s"):format(tostring(k))
      local best = inferred[k] and inferred[k][1]
      if best then line = line .. (" (guess: %s, score=%.1f)"):format(best.name, best.score) end
      report[#report+1] = line
    end
  end

  return ir, table.concat(report, "\n"), inferred
end

function lifter.lift(unpackedData)
  return toIR(unpackedData)
end

return lifter
