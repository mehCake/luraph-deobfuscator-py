local lifter = {}
local OPCODES = {
  [0]="MOVE",[4]="LOADK",[7]="ADD",[10]="CALL",[15]="GETGLOBAL",
  [18]="GETTABLE",[27]="SETGLOBAL",[30]="SETTABLE",
}
function lifter.lift(unpacked)
  local ir,report={},{}
  local instrs=unpacked[4]; local consts=unpacked[5]
  for pc,instr in ipairs(instrs) do
    local opnum=tonumber(instr[3])
    local opname=OPCODES[opnum] or ("OP_"..opnum)
    ir[#ir+1]={pc=pc,op=opname,opnum=opnum,A=instr[6],B=instr[7],C=instr[8]}
  end
  report[#report+1]=("Instructions: %d; Consts: %d"):format(#instrs,#consts)
  return ir,table.concat(report,"\n")
end
return lifter
