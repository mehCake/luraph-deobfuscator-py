-- devirtualize.lua
-- Usage: luajit devirtualize.lua <script_key>
--
-- Place this next to initv4.lua and Obfuscated.json.
-- It sets script_key, loads initv4.lua, and attempts to extract a decoded result.
-- If result is a string -> writes decoded_output.lua
-- If result is a table of strings -> writes decoded_chunk_###.lua

local key = arg[1] or os.getenv("SCRIPT_KEY") or "zkzhqwk4b58pjnudvikpf"
local json_path = "Obfuscated.json"

-- Provide script_key to bootstrapper scopes
_G.script_key = key
if type(getgenv) == "function" then
    getgenv().script_key = key
end

-- Utility: read whole file
local function read_all(path)
    local f, err = io.open(path, "rb")
    if not f then error("cannot open " .. path .. ": " .. tostring(err)) end
    local s = f:read("*a")
    f:close()
    return s
end

local json_text = read_all(json_path)

-- Load bootstrapper (initv4.lua)
dofile("initv4.lua")

-- Try to recover decoded output
local function try_extract()
    local candidates = { "decoded_script", "DecodedLuraphScript", "decoded_output" }
    for _, n in ipairs(candidates) do
        if rawget(_G, n) then return rawget(_G, n) end
        if type(getgenv) == "function" and getgenv()[n] then return getgenv()[n] end
    end
    -- If bootstrapper defines a function we can call directly, try it
    for _, fnName in ipairs({ "Init", "Run", "bootstrap", "decode" }) do
        local fn = _G[fnName] or (type(getgenv)=="function" and getgenv()[fnName])
        if type(fn) == "function" then
            local ok, out = pcall(fn, json_text)
            if ok and out then return out end
        end
    end
    return nil
end

local result = try_extract()
if not result then
    error("No decoded output recovered. Edit devirtualize.lua to call the correct bootstrapper function.")
end

-- Write results
if type(result) == "table" then
    local count = 0
    for i, chunk in ipairs(result) do
        if type(chunk) == "string" and #chunk > 0 then
            count = count + 1
            local fname = string.format("decoded_chunk_%03d.lua", i)
            local f = assert(io.open(fname, "wb"))
            f:write(chunk)
            f:close()
            print("Wrote " .. fname)
        end
    end
    if count == 0 then error("Decoded table contained no string chunks.") end
elseif type(result) == "string" then
    local f = assert(io.open("decoded_output.lua", "wb"))
    f:write(result)
    f:close()
    print("Wrote decoded_output.lua")
else
    error("Decoded result is of unsupported type: " .. type(result))
end
