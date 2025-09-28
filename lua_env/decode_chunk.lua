local json = dofile("lua_env/json.lua")
local ok_bit, bit32_lib = pcall(require, "bit32")
local bit32 = bit32_lib or bit32

local function bxor(a, b)
    if bit32 and bit32.bxor then
        return bit32.bxor(a, b)
    end
    return (a ~ b) & 0xFF
end

local function read_file(path)
    local fh, err = io.open(path, "rb")
    if not fh then
        error("failed to read file: " .. tostring(err))
    end
    local data = fh:read("*a")
    fh:close()
    return data
end

local function write_file(path, data)
    local fh, err = io.open(path, "wb")
    if not fh then
        error("failed to write file: " .. tostring(err))
    end
    fh:write(data)
    fh:close()
end

local function normalise_chunk(value)
    if type(value) == "string" then
        return value
    elseif type(value) == "table" then
        local parts = {}
        for i = 1, #value do
            parts[i] = tostring(value[i])
        end
        return table.concat(parts)
    else
        error("unsupported chunk type: " .. type(value))
    end
end

local function unique_chars(str)
    local seen = {}
    local uniq = {}
    for i = 1, #str do
        local ch = str:sub(i, i)
        if not seen[ch] then
            seen[ch] = true
            uniq[#uniq + 1] = ch
        end
    end
    return table.concat(uniq)
end

local function recover_alphabet(path)
    if not path or path == "" then
        return nil
    end
    local ok, data = pcall(read_file, path)
    if not ok then
        return nil
    end
    local best, best_len = nil, 0
    for chunk in data:gmatch("[!-~]+") do
        if #chunk >= 85 then
            local uniq = unique_chars(chunk)
            if #uniq >= 85 and #uniq > best_len then
                best = uniq
                best_len = #uniq
            end
        end
    end
    return best
end

local function ascii85_decode(input)
    local output = {}
    local values = {}
    local count = 0
    local i = 1
    while i <= #input do
        local ch = input:sub(i, i)
        if ch:match("%s") then
            -- ignore whitespace
        elseif ch == '~' then
            if input:sub(i + 1, i + 1) == '>' then
                break
            else
                error("unexpected '~' in ascii85 stream")
            end
        elseif ch == 'z' then
            if count ~= 0 then
                error("invalid ascii85 short form")
            end
            output[#output + 1] = string.char(0, 0, 0, 0)
        else
            local byte = ch:byte()
            if byte < 33 or byte > 126 then
                error(string.format("invalid ascii85 character %q (byte %d)", ch, byte))
            end
            count = count + 1
            values[count] = byte - 33
            if count == 5 then
                local accum = 0
                for j = 1, 5 do
                    accum = accum * 85 + values[j]
                end
                local b1 = math.floor(accum / 256 ^ 3) % 256
                local b2 = math.floor(accum / 256 ^ 2) % 256
                local b3 = math.floor(accum / 256) % 256
                local b4 = accum % 256
                output[#output + 1] = string.char(b1, b2, b3, b4)
                values = {}
                count = 0
            end
        end
        i = i + 1
    end
    if count > 0 then
        for j = count + 1, 5 do
            values[j] = 84
        end
        local accum = 0
        for j = 1, 5 do
            accum = accum * 85 + values[j]
        end
        local bytes = {
            math.floor(accum / 256 ^ 3) % 256,
            math.floor(accum / 256 ^ 2) % 256,
            math.floor(accum / 256) % 256,
            accum % 256,
        }
        for j = 1, count - 1 do
            output[#output + 1] = string.char(bytes[j])
        end
    end
    return table.concat(output)
end

local function z85_decode(input)
    local value = 0
    local count = 0
    local out = {}
    for i = 1, #input do
        local ch = input:sub(i, i)
        if ch:match("%s") then
            -- skip whitespace
        else
            local byte = ch:byte()
            if byte < 32 or byte > 126 then
                error(string.format("invalid z85 character %q (byte %d)", ch, byte))
            end
            value = value * 85 + (byte - 32)
            count = count + 1
            if count == 5 then
                local tmp = value
                local b4 = tmp % 256
                tmp = (tmp - b4) / 256
                local b3 = tmp % 256
                tmp = (tmp - b3) / 256
                local b2 = tmp % 256
                tmp = (tmp - b2) / 256
                local b1 = tmp % 256
                out[#out + 1] = string.char(b1, b2, b3, b4)
                value = 0
                count = 0
            end
        end
    end
    if count ~= 0 then
        error("z85 data length must be a multiple of 5")
    end
    return table.concat(out)
end

local function build_mapping(alphabet)
    local map = {}
    for i = 1, #alphabet do
        local ch = alphabet:sub(i, i)
        if map[ch] == nil then
            map[ch] = i - 1
        end
    end
    return map, #alphabet
end

local function base91_decode(input, alphabet)
    if not alphabet then
        error("base91 requires an alphabet")
    end
    local mapping, base = build_mapping(alphabet)
    local value = -1
    local buffer = 0
    local bits = 0
    local out = {}

    for i = 1, #input do
        local ch = input:sub(i, i)
        if ch:match("%s") then
            -- skip
        else
            local symbol = mapping[ch]
            if symbol == nil then
                error("invalid base91 symbol: " .. ch)
            end
            if value < 0 then
                value = symbol
            else
                local combined = value + symbol * base
                buffer = buffer + combined * 2 ^ bits
                local mod = combined % 8192
                if mod > 88 then
                    bits = bits + 13
                else
                    bits = bits + 14
                end
                while bits >= 8 do
                    local byte = buffer % 256
                    out[#out + 1] = string.char(byte)
                    buffer = (buffer - byte) / 256
                    bits = bits - 8
                end
                value = -1
            end
        end
    end

    if value >= 0 then
        buffer = buffer + value * 2 ^ bits
        local byte = buffer % 256
        out[#out + 1] = string.char(byte)
    end

    return table.concat(out)
end

local function apply_script_key(bytes, key)
    local out = {}
    local key_len = #key
    for i = 1, #bytes do
        local b = bytes:byte(i)
        if key_len > 0 then
            local k = key:byte(((i - 1) % key_len) + 1)
            b = bxor(b, k)
        end
        b = bxor(b, (i - 1) % 256)
        out[i] = string.char(b)
    end
    return table.concat(out)
end

local function is_printable(bytes)
    for i = 1, #bytes do
        local b = bytes:byte(i)
        if b == 9 or b == 10 or b == 13 then
            -- allow whitespace
        elseif b < 32 or b > 126 then
            return false
        end
    end
    return true
end

local function format_hexdump(bytes)
    local lines = {"-- binary payload; hex dump follows", "return [["}
    for offset = 0, #bytes - 1, 16 do
        local chunk = {}
        local ascii = {}
        for j = 0, 15 do
            local idx = offset + j + 1
            if idx <= #bytes then
                local b = bytes:byte(idx)
                chunk[#chunk + 1] = string.format("%02x", b)
                if b >= 32 and b < 127 then
                    ascii[#ascii + 1] = string.char(b)
                else
                    ascii[#ascii + 1] = '.'
                end
            else
                chunk[#chunk + 1] = "  "
                ascii[#ascii + 1] = ' '
            end
        end
        lines[#lines + 1] = string.format("%08x  %s  %s", offset, table.concat(chunk, " "), table.concat(ascii))
    end
    lines[#lines + 1] = "]]"
    return table.concat(lines, "\n") .. "\n"
end

local function resolve_chunk(doc, chunk_index)
    local index = chunk_index
    local first = doc[1]
    if type(first) == "table" and #first == 2 and type(first[1]) == "string" and type(first[2]) == "string" then
        index = index + 1
    end
    if index > #doc then
        error(string.format("chunk_index %d out of range after metadata adjustment (len=%d)", chunk_index, #doc))
    end
    return doc[index]
end

local function main()
    if #arg < 5 then
        io.stderr:write("usage: lua lua_env/decode_chunk.lua <Obfuscated.json> <chunk_index> <output> <script_key> <bootstrapper>\n")
        os.exit(1)
    end
    local json_path = arg[1]
    local chunk_index = tonumber(arg[2])
    local output_path = arg[3]
    local script_key = arg[4]
    local bootstrapper = arg[5]

    if not chunk_index or chunk_index < 1 then
        error("chunk_index must be >= 1")
    end

    local doc = json.decode(read_file(json_path))
    if type(doc) ~= "table" then
        error("root JSON value must be an array")
    end

    local raw_chunk = resolve_chunk(doc, chunk_index)
    local chunk = normalise_chunk(raw_chunk)
    local alphabet = recover_alphabet(bootstrapper)

    local decoded
    local ok, err = pcall(function()
        decoded = ascii85_decode(chunk)
    end)

    local method = "ascii85"
    if not ok then
        local err_msg = tostring(err)
        local tried_z85 = false
        if err_msg:find("ascii85 character", 1, true) then
            local z_ok, z_res = pcall(function()
                return z85_decode(chunk)
            end)
            if z_ok then
                decoded = z_res
                method = "z85"
                tried_z85 = true
            else
                io.stderr:write(string.format("z85 decode failed (%s)\n", tostring(z_res)))
            end
        end
        if not tried_z85 then
            if not alphabet then
                error("ascii85 failed and no alphabet available for base91: " .. err_msg)
            end
            io.stderr:write(string.format("ascii85 decode failed (%s); attempting base91\n", err_msg))
            io.stderr:write(string.format("alphabet length %d\n", #alphabet))
            decoded = base91_decode(chunk, alphabet)
            method = "base91"
        end
    end

    local transformed = apply_script_key(decoded, script_key)
    if is_printable(transformed) then
        write_file(output_path, transformed)
        print(string.format("chunk %d decoded via %s -> %s (%d bytes, printable)", chunk_index, method, output_path, #transformed))
    else
        write_file(output_path, format_hexdump(transformed))
        print(string.format("chunk %d decoded via %s -> %s (%d bytes, binary)", chunk_index, method, output_path, #transformed))
    end
end

main()
