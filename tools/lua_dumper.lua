-- tools/lua_dumper.lua
--
-- Provides small helpers for serialising Lua values either as Lua literals or
-- a basic JSON representation.  The implementation is intentionally minimal –
-- it handles strings, numbers, booleans, nil, and nested tables.  Cycles are
-- broken by inserting a descriptive string.

local M = {}

local function escape_string(str)
  str = str:gsub('\\', '\\\\')
  str = str:gsub('"', '\\"')
  str = str:gsub('\n', '\\n')
  str = str:gsub('\r', '\\r')
  str = str:gsub('\t', '\\t')
  return str
end

local function dump_lua(value, indent, seen)
  indent = indent or ""
  seen = seen or {}

  local t = type(value)
  if t == "string" then
    return string.format("%q", value)
  elseif t == "number" or t == "boolean" or t == "nil" then
    return tostring(value)
  elseif t == "table" then
    if seen[value] then
      return '"<cycle>"'
    end
    seen[value] = true
    local parts = {"{"}
    local seq_len = #value
    for i = 1, seq_len do
      parts[#parts + 1] = string.format("\n%s  %s,", indent, dump_lua(value[i], indent .. "  ", seen))
    end
    for k, v in pairs(value) do
      if not (type(k) == "number" and k >= 1 and k <= seq_len) then
        local key
        if type(k) == "string" and k:match("^[_%a][_%w]*$") then
          key = k .. " = "
        else
          key = "[" .. dump_lua(k, indent .. "  ", seen) .. "] = "
        end
        parts[#parts + 1] = string.format("\n%s  %s%s,", indent, key, dump_lua(v, indent .. "  ", seen))
      end
    end
    parts[#parts + 1] = "\n" .. indent .. "}"
    return table.concat(parts)
  else
    return string.format('"<unsupported:%s>"', t)
  end
end

local function dump_json(value, seen)
  seen = seen or {}
  local t = type(value)
  if t == "string" then
    return '"' .. escape_string(value) .. '"'
  elseif t == "number" or t == "boolean" then
    return tostring(value)
  elseif t == "nil" then
    return "null"
  elseif t == "table" then
    if seen[value] then
      return '"<cycle>"'
    end
    seen[value] = true
    local seq_len = #value
    if seq_len > 0 then
      local out = {}
      for i = 1, seq_len do
        out[#out + 1] = dump_json(value[i], seen)
      end
      return "[" .. table.concat(out, ",") .. "]"
    else
      local out = {}
      for k, v in pairs(value) do
        local key
        if type(k) == "string" then
          key = '"' .. escape_string(k) .. '"'
        else
          key = dump_json(k, seen)
        end
        out[#out + 1] = key .. ":" .. dump_json(v, seen)
      end
      return "{" .. table.concat(out, ",") .. "}"
    end
  else
    return '"<' .. t .. '>"'
  end
end

function M.to_lua_literal(value)
  return dump_lua(value)
end

function M.to_json(value)
  return dump_json(value)
end

return M
