-- Minimal bootstrap used to exercise the initv4 shim helpers.
local encrypted = {0x30, 0x31, 0x32}
local key = {0x10}
local decoded = L1(encrypted, key)
local fragments = {
  { {nil, nil, decoded[1]} },
  { {nil, nil, decoded[2]} },
  { {nil, nil, decoded[3]} },
}
local joined = Y1(fragments[1], fragments[2], fragments[3])
local consts = { Y2({65, 66, 67}) }

unpackedData = {
  [4] = joined,
  [5] = consts,
}
return unpackedData
