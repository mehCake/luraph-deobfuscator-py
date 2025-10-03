-- tools/shims/initv4_shim.lua
--
-- Bootstrap shim for Luraph v14.4.x initv4 loaders.  The shim provides the
-- helper functions (L1/Y1/...) that the bootstrap expects, records macro
-- usage, and captures the decoded ``unpackedData`` table even when it only
-- lives in closure upvalues.  The implementation is Windows-friendly – it
-- relies solely on stock LuaJIT facilities and plain file I/O.

local M = {}

local unpack = table.unpack or unpack

local function ensure_dir(path)
  local sep = package.config:sub(1, 1)
  local ok_lfs, lfs = pcall(require, "lfs")
  if ok_lfs and lfs then
    local accum = ""
    for part in path:gmatch("[^" .. sep .. "]+") do
      accum = accum == "" and part or (accum .. sep .. part)
      local attr = lfs.attributes(accum)
      if not attr then
        lfs.mkdir(accum)
      end
    end
    return
  end

  -- Fallback: attempt to create a probe file to ensure the directory exists.
  local probe = path .. sep .. ".shim_probe"
  local handle = io.open(probe, "a")
  if handle then
    handle:close()
    os.remove(probe)
  end
end

local function open_log(path)
  local ok, handle = pcall(io.open, path, "a")
  if ok and handle then
    return handle
  end
  return nil
end

local function close_log(state)
  if state.log then
    pcall(function()
      state.log:flush()
      state.log:close()
    end)
    state.log = nil
  end
end

local function log_line(state, message)
  if not state.log then
    return
  end
  state.log:write(message .. "\n")
  state.log:flush()
end

local function normalise_key(key)
  if type(key) == "string" then
    return key
  end
  if type(key) == "number" then
    return tostring(key)
  end
  return tostring(key)
end

local function escape_json(str)
  str = str:gsub('\\', '\\\\')
  str = str:gsub('"', '\\"')
  str = str:gsub('\r', '\\r')
  str = str:gsub('\n', '\\n')
  str = str:gsub('\t', '\\t')
  return str
end

local function encode_json(value, seen, path)
  if value == nil then
    return "null"
  end
  seen = seen or {}
  path = path or ""
  local t = type(value)
  if t == "table" then
    if seen[value] then
      return '"<cycle>"'
    end
    seen[value] = true
    local numeric_keys = {}
    for k in pairs(value) do
      if type(k) == "number" and k >= 1 then
        numeric_keys[#numeric_keys + 1] = k
      end
    end
    table.sort(numeric_keys)
    local is_array = (#numeric_keys > 0 and numeric_keys[1] == 1)
    if not is_array and #numeric_keys > 0 then
      if path == "/4" or path:match("^/4/%d+$") then
        is_array = true
      end
    end
    if is_array then
      local max_index = numeric_keys[#numeric_keys]
      local parts = {}
      for i = 1, max_index do
        parts[i] = encode_json(value[i], seen, path .. "/" .. tostring(i))
      end
      seen[value] = nil
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local entries = {}
    local used_numeric = {}
    for _, idx in ipairs(numeric_keys) do
      entries[#entries + 1] = string.format('"%s":%s', normalise_key(idx), encode_json(value[idx], seen, path .. "/" .. tostring(idx)))
      used_numeric[idx] = true
    end
    for k, v in pairs(value) do
      local key_type = type(k)
      if not (key_type == "number" and k >= 1 and used_numeric[k]) then
        entries[#entries + 1] = string.format('"%s":%s', escape_json(normalise_key(k)), encode_json(v, seen, path .. "/" .. normalise_key(k)))
      end
    end
    table.sort(entries)
    seen[value] = nil
    return "{" .. table.concat(entries, ",") .. "}"
  elseif t == "string" then
    return '"' .. escape_json(value) .. '"'
  elseif t == "number" or t == "boolean" then
    return tostring(value)
  elseif t == "function" then
    return string.format('"<function:%s>"', tostring(value))
  else
    return '"<' .. t .. '>"'
  end
end

local function bitlib()
  local ok, lib = pcall(require, "bit")
  if ok and lib then
    return lib
  end
  local shim = {}
  local function mask32(n)
    n = n % 0x100000000
    if n < 0 then
      n = n + 0x100000000
    end
    return n
  end
  function shim.band(a, b)
    local result = 0
    local bit = 1
    a = mask32(a)
    b = mask32(b)
    for _ = 0, 31 do
      if (a % 2 == 1) and (b % 2 == 1) then
        result = result + bit
      end
      a = math.floor(a / 2)
      b = math.floor(b / 2)
      bit = bit * 2
    end
    return result
  end
  function shim.bor(a, b)
    local result = 0
    local bit = 1
    a = mask32(a)
    b = mask32(b)
    for _ = 0, 31 do
      if (a % 2 == 1) or (b % 2 == 1) then
        result = result + bit
      end
      a = math.floor(a / 2)
      b = math.floor(b / 2)
      bit = bit * 2
    end
    return result
  end
  function shim.bxor(a, b)
    local result = 0
    local bit = 1
    a = mask32(a)
    b = mask32(b)
    for _ = 0, 31 do
      if (a % 2) ~= (b % 2) then
        result = result + bit
      end
      a = math.floor(a / 2)
      b = math.floor(b / 2)
      bit = bit * 2
    end
    return result
  end
  function shim.lshift(a, b)
    return mask32(a * (2 ^ b))
  end
  function shim.rshift(a, b)
    a = mask32(a)
    return math.floor(a / (2 ^ b))
  end
  function shim.rol(a, b)
    a = mask32(a)
    b = b % 32
    return mask32(shim.lshift(a, b) + shim.rshift(a, 32 - b))
  end
  function shim.ror(a, b)
    a = mask32(a)
    b = b % 32
    return mask32(shim.rshift(a, b) + shim.lshift(a, 32 - b))
  end
  return shim
end

local BIT = bitlib()

if not BIT.rol then
  function BIT.rol(a, b)
    a = BIT.band(a, 0xFFFFFFFF)
    b = b % 32
    local left = BIT.lshift(a, b)
    local right = BIT.rshift(a, 32 - b)
    return BIT.band(left + right, 0xFFFFFFFF)
  end
end

if not BIT.ror then
  function BIT.ror(a, b)
    a = BIT.band(a, 0xFFFFFFFF)
    b = b % 32
    local right = BIT.rshift(a, b)
    local left = BIT.lshift(a, 32 - b)
    return BIT.band(left + right, 0xFFFFFFFF)
  end
end

local function describe_args(args)
  local parts = {}
  for i = 1, math.min(4, #args) do
    local v = args[i]
    local t = type(v)
    if t == "table" then
      parts[#parts + 1] = string.format("table(len=%d)", #v)
    elseif t == "string" then
      local sample = v
      if #sample > 16 then
        sample = sample:sub(1, 16) .. "…"
      end
      parts[#parts + 1] = string.format('"%s"', sample)
    else
      parts[#parts + 1] = tostring(v)
    end
  end
  if #args > 4 then
    parts[#parts + 1] = string.format("+%d", #args - 4)
  end
  return table.concat(parts, ", ")
end

local function helper_xor_buffer(buffer, key, salt)
  if type(buffer) == "string" then
    local bytes = { buffer:byte(1, #buffer) }
    local result = helper_xor_buffer(bytes, key, salt)
    return string.char(table.unpack(result))
  end
  if type(buffer) ~= "table" then
    return buffer
  end
  local key_bytes = {}
  if type(key) == "string" then
    for i = 1, #key do
      key_bytes[#key_bytes + 1] = key:byte(i)
    end
  elseif type(key) == "number" then
    key_bytes[1] = key % 0x100
  elseif type(key) == "table" then
    for i = 1, #key do
      key_bytes[#key_bytes + 1] = tonumber(key[i]) or 0
    end
  else
    key_bytes[1] = 0
  end
  if salt and type(salt) == "number" then
    key_bytes[#key_bytes + 1] = salt % 0x100
  end
  local result = {}
  local key_len = #key_bytes
  if key_len == 0 then
    key_len = 1
    key_bytes[1] = 0
  end
  for i = 1, #buffer do
    local value = tonumber(buffer[i]) or 0
    local key_val = key_bytes[((i - 1) % key_len) + 1]
    result[i] = BIT.bxor(value, key_val) % 0x100
  end
  return result
end

local function helper_rotate(value, amount)
  amount = tonumber(amount) or 0
  return BIT.rol(tonumber(value) or 0, amount)
end

local function helper_unrotate(value, amount)
  amount = tonumber(amount) or 0
  return BIT.ror(tonumber(value) or 0, amount)
end

local function helper_join_tables(...)
  local out = {}
  local index = 1
  for i = 1, select("#", ...) do
    local chunk = select(i, ...)
    if type(chunk) == "table" then
      for j = 1, #chunk do
        out[index] = chunk[j]
        index = index + 1
      end
    elseif chunk ~= nil then
      out[index] = chunk
      index = index + 1
    end
  end
  return out
end

local function helper_to_string(buffer)
  if type(buffer) == "table" then
    local chars = {}
    for i = 1, #buffer do
      local byte = tonumber(buffer[i]) or 0
      chars[i] = string.char(byte % 0x100)
    end
    return table.concat(chars)
  elseif type(buffer) == "string" then
    return buffer
  end
  return tostring(buffer)
end

local function helper_slice(buffer, offset, length)
  if type(buffer) ~= "table" then
    return buffer
  end
  offset = math.max(tonumber(offset) or 1, 1)
  length = tonumber(length) or (#buffer - offset + 1)
  local result = {}
  local last = offset + length - 1
  for i = offset, last do
    result[#result + 1] = buffer[i]
  end
  return result
end

local function helper_truthy()
  return true
end

local helper_impl = {
  L1 = helper_xor_buffer,
  L2 = helper_rotate,
  L3 = helper_unrotate,
  Y1 = helper_join_tables,
  Y2 = helper_to_string,
  Y3 = helper_slice,
  G1 = helper_join_tables,
  Q1 = helper_join_tables,
  Z1 = helper_truthy,
}

local macro_limitations = {
  LPH_ENCFUNC = "Encountered LPH_ENCFUNC macro – encrypted functions require manual keys",
}

local function is_vm_shape(value)
  if type(value) ~= "table" then
    return false
  end
  local instructions = value[4] or value["4"]
  if type(instructions) ~= "table" then
    return false
  end
  local first = instructions[1] or instructions["1"]
  if type(first) == "table" then
    local opcode = first[3] or first["3"]
    if type(opcode) == "number" then
      return true
    end
  end
  return false
end

local function capture_candidate(state, value, origin)
  if state.dump_written then
    return
  end
  if not is_vm_shape(value) then
    return
  end
  state.dump_written = true
  state.capture_sources[#state.capture_sources + 1] = origin
  local json_str = encode_json(value, {}, "")
  local path = state.out_dir .. "/unpacked_dump.json"
  local ok, err = pcall(function()
    local handle = assert(io.open(path, "w"))
    handle:write(json_str)
    handle:close()
  end)
  if not ok then
    log_line(state, string.format("[shim] failed to write unpacked dump: %s", tostring(err)))
  else
    log_line(state, string.format("[shim] wrote unpacked dump (%s)", origin))
    for name, message in pairs(state.limitations) do
      log_line(state, string.format("[shim] limitation %s: %s", name, message))
    end
  end
end

local function scan_function(state, fn, origin)
  if type(fn) ~= "function" then
    return
  end
  if not debug or not debug.getupvalue then
    return
  end
  local visited = {}
  local function visit(target, label)
    if visited[target] then
      return
    end
    visited[target] = true
    local index = 1
    while true do
      local name, value = debug.getupvalue(target, index)
      if not name then
        break
      end
      if type(value) == "table" then
        capture_candidate(state, value, label .. ":" .. name)
      elseif type(value) == "function" then
        visit(value, label .. ":" .. name)
      end
      index = index + 1
    end
  end
  visit(fn, origin)
end

local function wrap_loader(state, target, name, loader)
  if type(loader) ~= "function" then
    return
  end
  target[name] = function(...)
    local ok, chunk, err = pcall(loader, ...)
    if not ok then
      error(chunk)
    end
    if type(chunk) == "function" then
      scan_function(state, chunk, name)
    end
    return chunk, err
  end
end

local function install_helper(state, target, name, impl)
  local existing = target[name]
  target[name] = function(...)
    local args = { ... }
    state.helper_counts[name] = (state.helper_counts[name] or 0) + 1
    log_line(state, string.format("[shim] %s(%s)", name, describe_args(args)))
    local results
    if impl then
      results = { impl(...) }
    elseif type(existing) == "function" then
      results = { existing(...) }
    else
      results = args
    end
    if results[1] and type(results[1]) == "table" then
      capture_candidate(state, results[1], name .. "(return)")
    end
    return unpack(results)
  end
end

local function install_macro(state, target, name)
  local limitation = macro_limitations[name]
  target[name] = function(...)
    state.macros[name] = true
    log_line(state, string.format("[shim] macro %s invoked", name))
    if limitation then
      state.limitations[name] = limitation
    end
    local first = select(1, ...)
    if type(first) == "function" then
      local ok, result = pcall(first, select(2, ...))
      if not ok then
        log_line(state, string.format("[shim] macro %s inner call failed: %s", name, tostring(result)))
        return function()
          error("LPH macro placeholder invoked")
        end
      end
      return result
    end
    return first
  end
end

local function install_unpacked_hook(state, target)
  local mt = getmetatable(target)
  if not mt then
    mt = {}
    setmetatable(target, mt)
  end
  local original_newindex = mt.__newindex
  mt.__newindex = function(tbl, key, value)
    if key == "unpackedData" then
      capture_candidate(state, value, "global:unpackedData")
    end
    if key and type(key) == "string" and key:match("^LPH_") and type(value) == "function" then
      state.macros[key] = true
      log_line(state, string.format("[shim] macro definition detected: %s", key))
    end
    if original_newindex then
      original_newindex(tbl, key, value)
    else
      rawset(tbl, key, value)
    end
  end
end

function M.install(env, opts)
  opts = opts or {}
  local out_dir = opts.out_dir or "out"
  ensure_dir(out_dir)
  local state = {
    out_dir = out_dir,
    log = open_log(out_dir .. "/shim_usage.txt"),
    helper_counts = {},
    macros = {},
    limitations = {},
    capture_sources = {},
    dump_written = false,
  }
  if state.log then
    log_line(state, "[shim] installing initv4 shim for Luraph v14.4.x")
  end
  local target = env or _G
  install_unpacked_hook(state, target)
  for name, impl in pairs(helper_impl) do
    if type(target[name]) ~= "function" then
      install_helper(state, target, name, impl)
    else
      install_helper(state, target, name, nil)
    end
  end
  local macros = {
    "LPH_NO_VIRTUALIZE",
    "LPH_JIT",
    "LPH_JIT_MAX",
    "LPH_ENCFUNC",
    "LPH_SKIP",
    "LPH_NO_UPVALUES",
  }
  for _, macro in ipairs(macros) do
    install_macro(state, target, macro)
  end
  if target.print then
    local original_print = target.print
    target.print = function(...)
      local args = { ... }
      log_line(state, "[shim] print: " .. describe_args(args))
      return original_print(...)
    end
  end
  if load then
    wrap_loader(state, target, "load", load)
  end
  if loadstring then
    wrap_loader(state, target, "loadstring", loadstring)
  end
  if loadfile then
    wrap_loader(state, target, "loadfile", loadfile)
  end
  target.__LURAPH_SHIM_STATE = state
  log_line(state, "[shim] install complete")
end

function M.shutdown()
  if _G.__LURAPH_SHIM_STATE then
    close_log(_G.__LURAPH_SHIM_STATE)
    _G.__LURAPH_SHIM_STATE = nil
  end
end

return M
