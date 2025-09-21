local alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+,-./:;<=>?@[]^_`{|}~"

local dispatch = {
  [0x10] = "MOVE",
  [0x13] = "CALL",
  [0x15] = "RETURN",
  [0x28] = "JMP"
}

dispatch[0x29] = "FORPREP"
dispatch[0x2A] = "FORLOOP"

return {
  alphabet = alphabet,
  opcode_map = dispatch
}
