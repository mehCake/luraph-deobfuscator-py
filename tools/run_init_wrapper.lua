-- tools/run_init_wrapper.lua
-- Usage: luajit tools/run_init_wrapper.lua <script_key> [path_to_obfuscated.json]

local script_key = arg[1] or os.getenv("SCRIPT_KEY") or "zkzhqwk4b58pjnudvikpf"
local json_path  = arg[2] or "Obfuscated.json"

-- minimal read helper
local function read_all(path)
  local f, err = io.open(path, "rb")
  if not f then
    io.stderr:write("Warning: cannot open "..tostring(path)..": "..tostring(err).."\n")
    return nil
  end
  local s = f:read("*a"); f:close(); return s
end

-- set common globals the bootstrapper might expect
_G.script_key = script_key
if type(getgenv) == "function" then getgenv().script_key = script_key end

-- expose obfuscated payload as a few common names
local json_text = read_all(json_path)
if json_text then
  _G.LPH_String = json_text
  _G.ObfuscatedJSON = json_text
  _G.obf_json = json_text
  -- sometimes the bootstrap expects a hex LPH string rather than raw JSON; leave as-is for now
end

-- provide a few numeric fallbacks that some bootstrappers call
_G._LURAPH_FLAG_1 = _G._LURAPH_FLAG_1 or 1
_G._LURAPH_FLAG_2 = _G._LURAPH_FLAG_2 or 0

-- Also populate arg table entries if initv4.lua uses arg[n]
arg = arg or {}
arg[1] = arg[1] or script_key
arg[2] = arg[2] or json_path
_G.arg = arg

-- Debug: print a small banner so we know the wrapper ran
print("[run_init_wrapper] script_key set, obf length:", (json_text and #json_text) or "nil")

-- Now load the real bootstrap; pcall to catch errors and report them
local ok, err = pcall(dofile, "initv4.lua")
if not ok then
  io.stderr:write("initv4.lua error: "..tostring(err).."\n")
  os.exit(2)
end
