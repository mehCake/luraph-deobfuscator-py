-- tools/shims/initv4_shim.lua
-- Purpose: Provide safe stand-ins for initv4 bootstrap helpers (L1, Y1, …)
-- so initv4.lua does not abort with "nil value" calls. Also, log each call
-- to a file and capture the first observed 'unpackedData' table as JSON.
--
-- This shim is intentionally Windows-friendly: it uses only LuaJIT features
-- and ordinary file I/O (no shell commands, pipes, or POSIX paths).

local M = {}

local json_modules = { "cjson", "dkjson" }

local function open_log(path)
  local ok, handle = pcall(io.open, path, "a")
  if ok and handle then
    return handle
  end
  return nil
end

local unpack = table.unpack or unpack

local function pack(...)
  return { n = select("#", ...), ... }
end

local has_bit, bit = pcall(require, "bit")

local POW2 = {}
for i = 0, 31 do
  POW2[i] = 2 ^ i
end

local function mask32(n)
  n = tonumber(n) or 0
  if has_bit and bit.band then
    return bit.band(n, 0xFFFFFFFF)
  end
  if n >= 0 then
    return n % 0x100000000
  end
  local positive = (-n) % 0x100000000
  return 0x100000000 - positive
end

local function bxor_pair(a, b)
  if has_bit and bit.bxor then
    return mask32(bit.bxor(a, b))
  end
  local ua = mask32(a)
  local ub = mask32(b)
  local result = 0
  local bitval = 1
  for _ = 0, 31 do
    local abit = ua % 2
    local bbit = ub % 2
    if abit ~= bbit then
      result = result + bitval
    end
    ua = math.floor(ua / 2)
    ub = math.floor(ub / 2)
    bitval = bitval * 2
  end
  return result
end

local function bor_pair(a, b)
  if has_bit and bit.bor then
    return mask32(bit.bor(a, b))
  end
  local ua = mask32(a)
  local ub = mask32(b)
  local result = 0
  local bitval = 1
  for _ = 0, 31 do
    local abit = ua % 2
    local bbit = ub % 2
    if abit == 1 or bbit == 1 then
      result = result + bitval
    end
    ua = math.floor(ua / 2)
    ub = math.floor(ub / 2)
    bitval = bitval * 2
  end
  return result
end

local function band_pair(a, b)
  if has_bit and bit.band then
    return mask32(bit.band(a, b))
  end
  local ua = mask32(a)
  local ub = mask32(b)
  local result = 0
  local bitval = 1
  for _ = 0, 31 do
    local abit = ua % 2
    local bbit = ub % 2
    if abit == 1 and bbit == 1 then
      result = result + bitval
    end
    ua = math.floor(ua / 2)
    ub = math.floor(ub / 2)
    bitval = bitval * 2
  end
  return result
end

local function bitwise_reduce(pair_func, first, second, ...)
  if second == nil then
    return mask32(first)
  end
  local result = pair_func(first, second)
  local extra = { ... }
  for i = 1, #extra do
    result = pair_func(result, extra[i])
  end
  return mask32(result)
end

local function bxor(a, b, ...)
  return bitwise_reduce(bxor_pair, a, b, ...)
end

local function bor(a, b, ...)
  return bitwise_reduce(bor_pair, a, b, ...)
end

local function band(a, b, ...)
  return bitwise_reduce(band_pair, a, b, ...)
end

local function bnot(a)
  if has_bit and bit.bnot then
    return mask32(bit.bnot(a))
  end
  return mask32(0xFFFFFFFF - mask32(a))
end

local function normalize_shift(s)
  return math.floor((tonumber(s) or 0) % 32)
end

local function lshift(a, s)
  if has_bit and bit.lshift then
    return mask32(bit.lshift(a, s))
  end
  local value = mask32(a)
  local shift = normalize_shift(s)
  for _ = 1, shift do
    value = (value * 2) % 0x100000000
  end
  return mask32(value)
end

local function rshift(a, s)
  if has_bit and bit.rshift then
    return mask32(bit.rshift(a, s))
  end
  local value = mask32(a)
  local shift = normalize_shift(s)
  for _ = 1, shift do
    value = math.floor(value / 2)
  end
  return mask32(value)
end

local function arshift(a, s)
  if has_bit and bit.arshift then
    return mask32(bit.arshift(a, s))
  end
  local value = mask32(a)
  local shift = normalize_shift(s)
  if shift == 0 then
    return value
  end
  local sign = band(value, 0x80000000) ~= 0
  local result = rshift(value, shift)
  if sign then
    local fill = 0
    for i = 0, shift - 1 do
      fill = fill + POW2[31 - i]
    end
    result = bor(result, fill)
  end
  return mask32(result)
end

local function lrotate(a, s)
  if has_bit and bit.rol then
    return mask32(bit.rol(a, s))
  end
  local shift = normalize_shift(s)
  if shift == 0 then
    return mask32(a)
  end
  local left = lshift(a, shift)
  local right = rshift(a, 32 - shift)
  return mask32(bor(left, right))
end

local function rrotate(a, s)
  if has_bit and bit.ror then
    return mask32(bit.ror(a, s))
  end
  local shift = normalize_shift(s)
  if shift == 0 then
    return mask32(a)
  end
  local right = rshift(a, shift)
  local left = lshift(a, 32 - shift)
  return mask32(bor(left, right))
end

local function countlz(value)
  if has_bit and bit.clz then
    return bit.clz(mask32(value))
  end
  local v = mask32(value)
  if v == 0 then
    return 32
  end
  local count = 0
  local mask = 0x80000000
  while mask ~= 0 and band(v, mask) == 0 do
    count = count + 1
    mask = math.floor(mask / 2)
  end
  return count
end

local function countrz(value)
  if has_bit and bit.ctz then
    return bit.ctz(mask32(value))
  end
  local v = mask32(value)
  if v == 0 then
    return 32
  end
  local count = 0
  local mask = 1
  while mask <= 0x80000000 and band(v, mask) == 0 do
    count = count + 1
    mask = mask * 2
  end
  return count
end

local function ensure_bit32_table()
  local existing = rawget(_G, "bit32")
  local target = type(existing) == "table" and existing or {}
  if target.band == nil then
    target.band = band
  end
  if target.bor == nil then
    target.bor = bor
  end
  if target.bxor == nil then
    target.bxor = bxor
  end
  if target.bnot == nil then
    target.bnot = bnot
  end
  if target.lshift == nil then
    target.lshift = lshift
  end
  if target.rshift == nil then
    target.rshift = rshift
  end
  if target.arshift == nil then
    target.arshift = arshift
  end
  if target.lrotate == nil then
    target.lrotate = lrotate
  end
  if target.rrotate == nil then
    target.rrotate = rrotate
  end
  if target.rol == nil then
    target.rol = lrotate
  end
  if target.ror == nil then
    target.ror = rrotate
  end
  if target.countlz == nil then
    target.countlz = countlz
  end
  if target.countrz == nil then
    target.countrz = countrz
  end
  if existing == nil then
    rawset(_G, "bit32", target)
  end
  return target
end

local function dump_table(t, depth, visited)
  depth = depth or 0
  visited = visited or {}
  if type(t) ~= "table" then
    return tostring(t)
  end
  if visited[t] then
    return "<cycle>"
  end
  visited[t] = true
  local parts = {"{"}
  local count = 0
  for k, v in pairs(t) do
    count = count + 1
    if depth < 2 then
      parts[#parts + 1] = tostring(k) .. "=" .. dump_table(v, depth + 1, visited)
    else
      parts[#parts + 1] = tostring(k) .. "=…"
    end
    if count < 10 then
      parts[#parts + 1] = ","
    else
      break
    end
  end
  parts[#parts + 1] = "}"
  return table.concat(parts)
end

local function encode_json(value, depth, seen)
  depth = depth or 0
  seen = seen or {}
  local t = type(value)
  if t == "number" then
    return tostring(value)
  elseif t == "boolean" then
    return value and "true" or "false"
  elseif t == "string" then
    local s = value:gsub("\\", "\\\\"):gsub("\"", "\\""):gsub("\r", "\\r"):gsub("\n", "\\n")
    return "\"" .. s .. "\""
  elseif value == nil then
    return "null"
  elseif t == "table" then
    if seen[value] then
      return '"<cycle>"'
    end
    seen[value] = true
    local is_array = true
    local max_index = 0
    local count = 0
    for k, _ in pairs(value) do
      if type(k) ~= "number" then
        is_array = false
      else
        if k > max_index then
          max_index = k
        end
      end
      count = count + 1
    end
    if is_array and max_index == count then
      local items = {}
      for i = 1, max_index do
        items[i] = encode_json(value[i], depth + 1, seen)
      end
      return "[" .. table.concat(items, ",") .. "]"
    else
      local items = {}
      for k, v in pairs(value) do
        items[#items + 1] = encode_json(tostring(k), depth + 1, seen) .. ":" .. encode_json(v, depth + 1, seen)
      end
      return "{" .. table.concat(items, ",") .. "}"
    end
  end
  return '"<unsupported>"'
end

local function best_effort_json(value)
  for _, name in ipairs(json_modules) do
    local ok, mod = pcall(require, name)
    if ok and mod then
      local ok_encode, encoded
      if type(mod.encode) == "function" then
        ok_encode, encoded = pcall(mod.encode, value, { indent = true })
      elseif type(mod.new) == "function" then
        local encoder = mod.new()
        ok_encode, encoded = pcall(encoder.encode, encoder, value)
      end
      if ok_encode and type(encoded) == "string" then
        return encoded
      end
    end
  end
  return encode_json(value)
end

local function is_probable_payload(tbl)
  if type(tbl) ~= "table" then
    return false
  end
  local numeric = 0
  local total = 0
  local notable = false
  for k, v in pairs(tbl) do
    total = total + 1
    if type(k) == "number" then
      numeric = numeric + 1
      if type(v) == "table" and (v.const or v.consts or v[3]) then
        notable = true
      end
    elseif type(k) == "string" then
      local key = string.lower(k)
      if key == "array" or key == "const" or key == "consts" or key == "instructions" or key == "bytecode" then
        notable = true
      end
    end
    if total > 2048 then
      notable = true
      break
    end
  end
  if total == 0 then
    return false
  end
  if notable then
    return true
  end
  if numeric >= 64 and numeric >= math.floor(total * 0.6) then
    return true
  end
  return false
end

local function table_overview(tbl)
  if type(tbl) ~= "table" then
    return tostring(tbl)
  end
  local count = 0
  local numeric = 0
  for k, _ in pairs(tbl) do
    count = count + 1
    if type(k) == "number" then
      numeric = numeric + 1
    end
    if count > 32 then
      break
    end
  end
  return string.format("table(count=%d,numeric=%d)", count, numeric)
end

local state = {
  captured = false,
  capture_path = nil,
  log = nil,
  out_dir = nil,
  visited_tables = setmetatable({}, { __mode = "k" }),
  visited_functions = setmetatable({}, { __mode = "k" }),
}

local function log_line(msg)
  if state.log then
    state.log:write(msg .. "
")
    state.log:flush()
  end
end

local function record_capture(reason, payload)
  if state.captured then
    log_line("[shim] capture already performed, skipping subsequent capture for " .. tostring(reason))
    return
  end
  state.captured = true
  local out_dir = state.out_dir or "out"
  local path = out_dir .. "/unpacked_dump.lua.json"
  state.capture_path = path
  local json_blob = best_effort_json(payload)
  local ok_open, handle = pcall(io.open, path, "w")
  if not ok_open or not handle then
    log_line("[shim] failed to open capture file: " .. tostring(handle))
    return
  end
  handle:write(json_blob)
  handle:close()
  log_line("[shim] wrote captured payload to " .. path .. " (" .. tostring(reason) .. ")")
end

local function inspect_table(tbl, reason)
  if type(tbl) ~= "table" then
    return
  end
  if state.visited_tables[tbl] then
    return
  end
  state.visited_tables[tbl] = true
  if is_probable_payload(tbl) then
    log_line("[shim] probable payload detected via " .. reason .. " => " .. table_overview(tbl))
    record_capture(reason, tbl)
  end
end

local function scan_function(fn, reason, depth)
  if type(fn) ~= "function" then
    return
  end
  depth = depth or 0
  if depth > 4 then
    return
  end
  if state.visited_functions[fn] then
    return
  end
  state.visited_functions[fn] = true
  local dbg = debug
  if not dbg or type(dbg.getupvalue) ~= "function" then
    return
  end
  local index = 1
  while true do
    local name, value = dbg.getupvalue(fn, index)
    if not name then
      break
    end
    local label = string.format("%s.upvalue[%d]=%s", reason, index, tostring(name))
    if type(value) == "table" then
      inspect_table(value, label)
    elseif type(value) == "function" then
      scan_function(value, label, depth + 1)
    end
    index = index + 1
  end
end

local function wrap_loaded_function(fn, origin)
  if type(fn) ~= "function" then
    return fn
  end
  local label = "load:" .. (origin or "<chunk>")
  scan_function(fn, label)
  return function(...)
    log_line("[shim] executing wrapped chunk from " .. label)
    scan_function(fn, label .. ":pre")
    local results = pack(fn(...))
    scan_function(fn, label .. ":post")
    return unpack(results, 1, results.n)
  end
end

local function install_unpacked_capture(env)
  local target = env or _G
  local meta = getmetatable(target) or {}
  local original_newindex = meta.__newindex
  meta.__newindex = function(t, k, v)
    if k == "unpackedData" then
      log_line("[shim] observed assignment to global 'unpackedData'")
      inspect_table(v, "global.unpackedData")
    end
    if original_newindex then
      return original_newindex(t, k, v)
    end
    rawset(t, k, v)
  end
  setmetatable(target, meta)
end

local function helper_wrapper(name, impl)
  return function(...)
    local argc = select("#", ...)
    log_line(string.format("[shim] %s invoked (%d args)", name, argc))
    for idx = 1, argc do
      local arg = select(idx, ...)
      if type(arg) == "table" then
        inspect_table(arg, string.format("%s.arg[%d]", name, idx))
      end
    end
    local results = pack(impl(...))
    for idx = 1, results.n do
      local value = results[idx]
      if type(value) == "table" then
        inspect_table(value, string.format("%s.ret[%d]", name, idx))
      end
    end
    return unpack(results, 1, results.n)
  end
end

function M.install(env, opts)
  opts = opts or {}
  state.out_dir = opts.out_dir or "out"
  local log_path = state.out_dir .. "/shim_usage.txt"
  state.log = open_log(log_path)
  if state.log then
    log_line("[shim] install begin")
  end

  ensure_bit32_table()

  local target = env or _G
  install_unpacked_capture(target)

  local helper_impls = {
    L1 = function(a, b)
      return rrotate(a, b)
    end,
    Y1 = function(a, b, ...)
      return bor(a, b, ...)
    end,
    Z1 = function(a, b, ...)
      return band(a, b, ...)
    end,
    U1 = function(a, b)
      return lrotate(a, b)
    end,
    T1 = function(a, b)
      return lshift(a, b)
    end,
    C1 = function(a)
      return countlz(a)
    end,
    H1 = function(a)
      return countrz(a)
    end,
    M1 = function(a, b)
      return rshift(a, b)
    end,
    u1 = function(a)
      return bnot(a)
    end,
    q1 = function(a, b, ...)
      return bxor(a, b, ...)
    end,
  }

  for name, impl in pairs(helper_impls) do
    if target[name] == nil then
      target[name] = helper_wrapper(name, impl)
    end
  end

  if state.log then
    local original_print = target.print or print
    target.print = function(...)
      state.log:write("[shim] print: ")
      for i = 1, select("#", ...) do
        local v = select(i, ...)
        state.log:write(tostring(v))
        if i < select("#", ...) then
          state.log:write(" ")
        end
      end
      state.log:write("\n")
      state.log:flush()
      if original_print then
        pcall(original_print, ...)
      end
    end
  end

  local original_load = target.load or load
  if type(original_load) == "function" then
    target.load = function(chunk, chunkname, mode, env2)
      local fn, err = original_load(chunk, chunkname, mode, env2)
      if type(fn) == "function" then
        fn = wrap_loaded_function(fn, chunkname)
      end
      return fn, err
    end
  end

  local original_loadstring = target.loadstring or loadstring
  if type(original_loadstring) == "function" then
    target.loadstring = function(src, chunkname)
      local fn, err = original_loadstring(src, chunkname)
      if type(fn) == "function" then
        fn = wrap_loaded_function(fn, chunkname or "loadstring")
      end
      return fn, err
    end
  end

  local original_loadfile = target.loadfile or loadfile
  if type(original_loadfile) == "function" then
    target.loadfile = function(filename, mode, env2)
      local fn, err = original_loadfile(filename, mode, env2)
      if type(fn) == "function" then
        fn = wrap_loaded_function(fn, filename or "loadfile")
      end
      return fn, err
    end
  end

  log_line("[shim] installed")
end

return M
