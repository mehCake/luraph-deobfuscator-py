-- Sample payload for Luraph v14.4.2 bootstrap testing
local encoded = string.char(115, 109, 97, 108, 108, 95, 108, 117, 97)

local bytecode = {
  12, 34, 56, 78, 90,
  123, 210, 45, 67
}

local bootstrapper = loadstring(encoded)
return bootstrapper()
