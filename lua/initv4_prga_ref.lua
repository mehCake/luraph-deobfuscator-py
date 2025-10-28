local function xor_byte(a, b)
    local result = 0
    local bit_value = 1

    while a > 0 or b > 0 do
        local abit = a % 2
        local bbit = b % 2
        if abit ~= bbit then
            result = result + bit_value
        end
        a = math.floor((a - abit) / 2)
        b = math.floor((b - bbit) / 2)
        bit_value = bit_value * 2
    end

    return result
end

local function rotate_right8(value, rotation)
    rotation = rotation % 8
    if rotation == 0 then
        return value % 256
    end

    value = value % 256
    local shifted = math.floor(value / (2 ^ rotation))
    local wrapped = (value * (2 ^ (8 - rotation))) % 256
    return (shifted + wrapped) % 256
end

local function apply_prga_ref(decoded_lph, key)
    if type(key) ~= "string" or #key == 0 then
        error("key must be a non-empty string")
    end
    if type(decoded_lph) ~= "string" then
        error("decoded_lph must be a string")
    end

    local key_len = #key
    local output = {}

    for index = 1, #decoded_lph do
        local value = decoded_lph:byte(index)
        local key_byte = key:byte(((index - 1) % key_len) + 1)
        local mixed = xor_byte(value, key_byte)
        local rotation = key_byte % 8
        mixed = rotate_right8(mixed, rotation)
        output[index] = string.char(mixed)
    end

    return table.concat(output)
end

local module = {
    apply_prga_ref = apply_prga_ref,
}

initv4_prga_ref = module

return module
