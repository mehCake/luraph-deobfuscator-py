local M = {}

local whitespace = { [" "]=true, ["\t"]=true, ["\r"]=true, ["\n"]=true }

local function skip_ws(str, index)
    local i = index
    while i <= #str do
        local ch = str:sub(i, i)
        if not whitespace[ch] then
            break
        end
        i = i + 1
    end
    return i
end

local function parse_string(str, index)
    local i = index + 1
    local bytes = {}
    while i <= #str do
        local ch = str:sub(i, i)
        if ch == '"' then
            return table.concat(bytes), i + 1
        elseif ch == '\\' then
            local next_ch = str:sub(i + 1, i + 1)
            if next_ch == 'u' then
                local hex = str:sub(i + 2, i + 5)
                if not hex:match("^[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]$") then
                    error("invalid unicode escape")
                end
                local code = tonumber(hex, 16)
                bytes[#bytes + 1] = utf8.char(code)
                i = i + 6
            else
                local escape_map = {
                    ["\""] = '"',
                    ["\\"] = "\\",
                    ["/"] = "/",
                    ["b"] = "\b",
                    ["f"] = "\f",
                    ["n"] = "\n",
                    ["r"] = "\r",
                    ["t"] = "\t",
                }
                local mapped = escape_map[next_ch]
                if not mapped then
                    error("invalid escape sequence")
                end
                bytes[#bytes + 1] = mapped
                i = i + 2
            end
        else
            bytes[#bytes + 1] = ch
            i = i + 1
        end
    end
    error("unterminated string")
end

local function parse_number(str, index)
    local i = index
    local number_pattern = "^-?%d+%.?%d*[eE]?[+-]?%d*"
    local substr = str:sub(i)
    local match = substr:match(number_pattern)
    if not match or match == "" then
        error("invalid number")
    end
    local value = tonumber(match)
    if value == nil then
        error("number conversion failed")
    end
    return value, i + #match
end

local function parse_literal(str, index)
    if str:sub(index, index + 3) == "true" then
        return true, index + 4
    elseif str:sub(index, index + 4) == "false" then
        return false, index + 5
    elseif str:sub(index, index + 3) == "null" then
        return nil, index + 4
    end
    error("unexpected literal")
end

local parse_value

local function parse_array(str, index)
    local arr = {}
    local i = index + 1
    i = skip_ws(str, i)
    if str:sub(i, i) == ']' then
        return arr, i + 1
    end
    while i <= #str do
        local value
        value, i = parse_value(str, i)
        arr[#arr + 1] = value
        i = skip_ws(str, i)
        local ch = str:sub(i, i)
        if ch == ']' then
            return arr, i + 1
        elseif ch == ',' then
            i = skip_ws(str, i + 1)
        else
            error("expected ',' or ']' in array")
        end
    end
    error("unterminated array")
end

local function parse_object(str, index)
    local obj = {}
    local i = index + 1
    i = skip_ws(str, i)
    if str:sub(i, i) == '}' then
        return obj, i + 1
    end
    while i <= #str do
        if str:sub(i, i) ~= '"' then
            error("expected string key in object")
        end
        local key
        key, i = parse_string(str, i)
        i = skip_ws(str, i)
        if str:sub(i, i) ~= ':' then
            error("expected ':' after object key")
        end
        i = skip_ws(str, i + 1)
        local value
        value, i = parse_value(str, i)
        obj[key] = value
        i = skip_ws(str, i)
        local ch = str:sub(i, i)
        if ch == '}' then
            return obj, i + 1
        elseif ch == ',' then
            i = skip_ws(str, i + 1)
        else
            error("expected ',' or '}' in object")
        end
    end
    error("unterminated object")
end

function parse_value(str, index)
    local i = skip_ws(str, index)
    local ch = str:sub(i, i)
    if ch == '"' then
        return parse_string(str, i)
    elseif ch == '{' then
        return parse_object(str, i)
    elseif ch == '[' then
        return parse_array(str, i)
    elseif ch == '-' or ch:match("%d") then
        return parse_number(str, i)
    else
        return parse_literal(str, i)
    end
end

function M.decode(str)
    local value, idx = parse_value(str, 1)
    idx = skip_ws(str, idx)
    if idx <= #str then
        error("extra data after JSON document")
    end
    return value
end

return M
