local SCRIPT_KEY = _G.script_key or "zkzhqwk4b58pjnudvikpf"

local unpackedData = {
  4, 0, {2, 2, 2},
  {
    {nil,nil,4,0,nil,1,0,0},
    {nil,nil,0,0,nil,2,1,nil},
    {nil,nil,28,0,nil,2,2,1},
    {nil,nil,30,0,nil,0,0,0},
  },
  {"print","hi"},
  {},
  18,
  {"print","hi"}
}

function LPH_UnpackData()
  return unpackedData
end

function LuraphInterpreter(data, env)
  assert(data == unpackedData, "unexpected data table")
  return function()
    env = env or {}
    env.decoded = "print('hi')"
    return env.decoded
  end
end

local env = {}
local runner = LuraphInterpreter(LPH_UnpackData(), env)
runner()
