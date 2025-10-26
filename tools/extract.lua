local function trim(value)
    if not value then
        return ""
    end
    return (value:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function assert_key(raw)
    local key_value = trim(raw)
    if key_value == "" then
        io.stderr:write("[extract] error: script key is required\n")
        os.exit(1)
    end
    return key_value
end

local function file_exists(path)
    local handle = io.open(path, "rb")
    if handle then
        handle:close()
        return true
    end
    return false
end

local function ensure_directory(path)
    local sep = package.config:sub(1, 1)
    local command
    if sep == "\\" then
        command = string.format('if not exist "%s" mkdir "%s"', path, path)
    else
        command = string.format("mkdir -p %q", path)
    end
    local ok, why, code = os.execute(command)
    if not ok or (why == "exit" and code ~= 0) then
        io.stderr:write(string.format("[extract] error: unable to create directory %s\n", path))
        os.exit(1)
    end
end

local function shell_quote(value)
    if value == nil then
        return "''"
    end
    return "'" .. value:gsub("'", "'\"'\"'") .. "'"
end

local function run_command(command)
    local ok, why, code = os.execute(command)
    if ok == true then
        return
    end
    if ok == 0 then
        return
    end
    if why == "exit" then
        io.stderr:write(string.format("[extract] decode command failed with exit code %d\n", code or -1))
    else
        io.stderr:write("[extract] decode command failed\n")
    end
    os.exit(1)
end

local session_key = assert_key(_G.key)
local input_path = "Obfuscated2.lua"
local output_dir = "extracted"

if not file_exists(input_path) then
    io.stderr:write(string.format("[extract] error: %s not found\n", input_path))
    os.exit(1)
end

ensure_directory(output_dir)

local python = os.getenv("PYTHON") or os.getenv("PYTHON3") or "python3"
local is_windows = package.config:sub(1, 1) == "\\"
local command

if is_windows then
    local escaped_key = session_key:gsub('"', '""')
    command = string.format(
        'cmd /c set "LURAPH_SESSION_KEY=%s" && "%s" -m src.main "%s" --write-artifacts "%s" --run-lifter --yes --no-report --confirm-ownership --confirm-voluntary-key --operator "extract-helper"',
        escaped_key,
        python,
        input_path,
        output_dir
    )
else
    local env_assignment = "LURAPH_SESSION_KEY=" .. shell_quote(session_key)
    command = table.concat({
        "env",
        env_assignment,
        shell_quote(python),
        "-m",
        "src.main",
        shell_quote(input_path),
        "--write-artifacts",
        shell_quote(output_dir),
        "--run-lifter",
        "--yes",
        "--no-report",
        "--confirm-ownership",
        "--confirm-voluntary-key",
        "--operator",
        "extract-helper",
    }, " ")
end

io.stderr:write("[extract] running decode pipeline...\n")
run_command(command)
io.stderr:write(string.format("[extract] artifacts written to %s\n", output_dir))

_G.key = nil

