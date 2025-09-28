-- reformat_v2.lua
-- Enhanced Lua source formatter for user-environment workflows.
--
-- Usage:
--   luajit reformat_v2.lua <input.lua> [--columns N]
--
-- The formatter performs lightweight parsing, reindents block constructs,
-- merges adjacent string literal concatenations, and normalises whitespace to
-- improve readability of devirtualised scripts.

local argparse = {}
function argparse.parse(argv)
  local opts = { columns = 100 }
  local i = 1
  while i <= #argv do
    local argi = argv[i]
    if argi == "--columns" then
      i = i + 1
      if i > #argv then error("--columns requires a value") end
      opts.columns = tonumber(argv[i]) or opts.columns
    elseif not opts.input then
      opts.input = argi
    else
      error("unknown argument: " .. tostring(argi))
    end
    i = i + 1
  end
  if not opts.input then error("Usage: luajit reformat_v2.lua <input.lua> [--columns N]") end
  return opts
end

local function read_all(path)
  local f, err = io.open(path, "rb")
  if not f then error("reformat_v2: cannot open " .. tostring(path) .. ": " .. tostring(err)) end
  local data = f:read("*a")
  f:close()
  return data
end

local function write_all(path, text)
  local f, err = io.open(path, "wb")
  if not f then error("reformat_v2: cannot write " .. tostring(path) .. ": " .. tostring(err)) end
  f:write(text)
  f:close()
end

local opts = argparse.parse(arg)
local source = read_all(opts.input)
source = source:gsub("\r\n", "\n")
source = source:gsub("\t", "  ")
source = source:gsub(" +\n", "\n")
source = source:gsub("\n\n\n+", "\n\n")

local tokens = {}
for line in source:gmatch("[^\n]*\n?") do
  if line == "" then break end
  tokens[#tokens + 1] = line
end

local indent = 0
local pad = "  "
local output_lines = {}
local function trim(s) return s:match("^%s*(.-)%s*$") end

for _, raw_line in ipairs(tokens) do
  local line = trim(raw_line)
  if line == "" then
    output_lines[#output_lines + 1] = ""
  else
    local lowered = line:lower()
    if lowered:match("^end[%s;]*$") or lowered:match("^until[%s;]") or lowered:match("^else[%s;]*$") or lowered:match("^elseif ") then
      indent = math.max(0, indent - 1)
    end
    local formatted = string.rep(pad, indent) .. line
    output_lines[#output_lines + 1] = formatted
    if lowered:match("then[%s;]*$") or lowered:match("do[%s;]*$") or lowered:match("^function[%s(]") or lowered:match("^repeat[%s;]*$") then
      indent = indent + 1
    end
  end
end

local function merge_concat(lines)
  local merged = {}
  local buffer = nil
  for _, line in ipairs(lines) do
    if line:find("%s%..%s") and line:match("'[^"]*' \+ '[^"]*'") then
      local repl = line:gsub("'([^']*)' %.+ '([^']*)'", "'%1%2'")
      line = repl
    end
    if not buffer then
      buffer = line
    else
      if buffer:match("..%s*$") and line:match("^%s+'") then
        buffer = buffer:gsub("%s*$", "") .. line:gsub("^%s+", "")
      else
        merged[#merged + 1] = buffer
        buffer = line
      end
    end
  end
  if buffer then merged[#merged + 1] = buffer end
  return merged
end

output_lines = merge_concat(output_lines)
local final_text = table.concat(output_lines, "\n") .. "\n"
if opts.output then
  write_all(opts.output, final_text)
else
  io.write("-- reformatted by reformat_v2\n")
  io.write(final_text)
end
