-- reformat.lua
-- Usage: luajit reformat.lua decoded_output.lua > readable.lua
-- Light reformatter: normalizes whitespace and basic block structure.

local path = arg[1]
if not path then error("Usage: luajit reformat.lua <file>") end

local function read_all(p)
    local f, err = io.open(p, "rb")
    if not f then error("Cannot open " .. tostring(p) .. ": " .. tostring(err)) end
    local s = f:read("*a")
    f:close()
    return s
end

local code = read_all(path)

-- Basic cleanup: normalize spacing, fix indentation
code = code:gsub("\r\n", "\n")
code = code:gsub("%s+\n", "\n")           -- trim trailing spaces
code = code:gsub("\n\n\n+", "\n\n")       -- collapse extra blank lines
code = code:gsub(";%s+", ";")             -- trim after semicolons
code = code:gsub("end%s+", "end\n")       -- put ends on newlines
code = code:gsub("do%s+", "do\n")         -- put do-block starts on newlines

-- Simple block-aware indentation
local out, indent, pad = {}, 0, "  "
for line in code:gmatch("[^\n]*\n?") do
    if line == "" then break end
    local trimmed = line:gsub("^%s+","")
    if trimmed:match("^end[%s;]") or trimmed:match("^until[%s(]") or trimmed:match("^else[%s;]") or trimmed:match("^elseif[%s(]") then
        indent = math.max(0, indent - 1)
    end
    table.insert(out, pad:rep(indent) .. trimmed)
    if trimmed:match("do[%s;]$") or trimmed:match("then[%s;]$") or trimmed:match("^function[%s(]") or trimmed:match("^repeat[%s;]?$") then
        indent = indent + 1
    end
end

print("-- Reformatted Lua script")
print("-- Original file: " .. path)
print("-- Cleaned and structured for readability\n")
print(table.concat(out):gsub(";[ \t]*\n","\n"):gsub(" +"," "):gsub(" ,", ","))
