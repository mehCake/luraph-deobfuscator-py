-- Minimal, hand-made 'unpackedData' surrogate for tests
-- data[4] = vm_instructions, each instr has opcode at [3]; [6],[7],[8] act like A,B,C
return {
  4, 0, {2,2,2}, -- data[1..3] (dummy)
  {  -- data[4] = vm_instructions
    {nil,nil,4,  0, nil, 1,  0, 0},      -- LOADK A=1 (const idx implied elsewhere)
    {nil,nil,0,  0, nil, 2,  1, nil},    -- MOVE A=2,B=1
    {nil,nil,28, 0, nil, 2,  2, 1},      -- CALL A=2,B=2,C=1
    {nil,nil,30, 0, nil, 0,  0, 0},      -- RETURN
  },
  { "print", "hi" },    -- data[5] = constants (toy)
  {}, 18, {"print","hi"} -- rest dummy
}
