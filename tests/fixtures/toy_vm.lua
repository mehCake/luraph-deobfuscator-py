-- Minimal VM sample used by regression tests.
local payload = {0x41, 0x42, 0x43}
local xor_key = 0x20

local function decrypt(buf, key)
  local out = {}
  for i = 1, #buf do
    out[i] = string.char(bit.bxor(buf[i], key))
  end
  return table.concat(out)
end

unpackedData = {
  decrypt(payload, xor_key),
  {
    array = payload,
    key = xor_key,
  },
}
return unpackedData
