-- tools/test_lifter_min.lua
local data = dofile("examples/fixtures/unpacked_min.lua")
local lifter = dofile("tools/lifter.lua")
local ir, rep, inferred = lifter.lift(data)
print(rep or "")
print(string.format("OPCODES_SEEN=%d", ir and #ir or 0))
if inferred then
  local unknown = 0
  for _ in pairs(inferred) do unknown = unknown + 1 end
  print(string.format("UNKNOWN_GUESSES=%d", unknown))
end
