-- expected.lua
local function sum_three()
  local total = 0
  for i = 1, 3 do
    total = total + i
  end
  return total
end

return {
  entry = sum_three,
  result = sum_three()
}
