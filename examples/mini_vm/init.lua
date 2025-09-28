-- examples/mini_vm/init.lua
-- Minimal initv4-style bootstrap used for regression testing the Lua toolkit.

local SCRIPT_KEY = _G.script_key or "ppcg208ty9nze5wcoldxh"
local unpackedData = {
  [1] = {},
  [3] = {},
  [4] = {
    { [3] = 0, [6] = 0, [7] = 1, [8] = 0 },
    { [3] = 4, [6] = 1, [7] = 2, [8] = 0 },
    { [3] = 10, [6] = 0, [7] = 0, [8] = 0 },
  },
  [5] = {
    "sum_three",
    "return sum_three()",
    "unused",
  },
  [6] = {},
}

function LPH_UnpackData()
  return unpackedData
end

function LuraphInterpreter(data, env)
  local decoded = table.concat({
    "local function sum_three()",
    "  local total = 0",
    "  for i = 1, 3 do",
    "    total = total + i",
    "  end",
    "  return total",
    "end",
    "",
    "return {",
    "  entry = sum_three,",
    "  result = sum_three()",
    "}",
  }, "\n")
  _G.decoded_output = decoded
  return decoded
end

local function bootstrap()
  local unpacked = LPH_UnpackData()
  return LuraphInterpreter(unpacked, { script_key = SCRIPT_KEY })
end

return bootstrap()
