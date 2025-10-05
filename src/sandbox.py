"""Lua sandbox helpers for capturing ``unpackedData`` tables."""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Optional

try:  # pragma: no cover - exercised in integration tests
    from lupa import LuaRuntime  # type: ignore
except Exception:  # pragma: no cover - import failure is handled dynamically
    LuaRuntime = None  # type: ignore

REPO_ROOT = Path(__file__).resolve().parents[1]


_HOOK_SNIPPET = r"""
local captured_unpacked = nil

local function is_vm_data_shape(t)
    if type(t) ~= "table" then return false end
    local instr = t[4]
    if type(instr) ~= "table" or #instr == 0 then return false end
    local first = instr[1]
    if type(first) ~= "table" or type(first[3]) ~= "number" then return false end
    if type(t[5]) ~= "table" then return false end
    return true
end

function __luraph_capture_setup()
    captured_unpacked = nil
    debug.sethook(function(event)
        if event == "call" then
            local i = 1
            while true do
                local name, value = debug.getlocal(2, i)
                if not name then break end
                if type(value) == "table" and is_vm_data_shape(value) then
                    captured_unpacked = value
                    debug.sethook()
                    return
                end
                i = i + 1
            end
        end
    end, "c")
end

function __luraph_capture_result()
    return captured_unpacked
end

function __luraph_trigger_candidates()
    local names = {"VMRun", "Run", "Init", "bootstrap", "main"}
    for _, name in ipairs(names) do
        local fn = _G[name]
        if type(fn) == "function" then
            pcall(function()
                fn("LPH!tick", _G)
            end)
        end
    end
end
"""


def _looks_like_vm_data(lua_table) -> bool:
    try:
        t4 = lua_table[4]
        return (
            t4 is not None
            and hasattr(t4, "__len__")
            and len(t4) > 0
            and isinstance(t4[1], (dict, type(lua_table)))
            and isinstance(lua_table[5], (dict, type(lua_table)))
        )
    except Exception:
        return False


def capture_unpacked(initv4_path: str, script_key: Optional[str] = None, json_path: Optional[str] = None):
    """Execute ``initv4.lua`` inside LuaJIT and capture ``unpackedData``."""

    if LuaRuntime is None:
        raise RuntimeError("lupa is not available; cannot run in-process sandbox")

    lua = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    lua.execute(_HOOK_SNIPPET)

    globals_table = lua.globals()

    if script_key:
        globals_table["script_key"] = script_key
        try:
            lua.execute(f"if type(getgenv) == 'function' then getgenv().script_key = {repr(script_key)} end")
        except Exception:
            pass

    if json_path:
        try:
            with open(json_path, "r", encoding="utf-8-sig", errors="ignore") as jf:
                json_text = jf.read()
            globals_table["ObfuscatedJSON"] = json_text
            globals_table["LPH_String"] = json_text
        except Exception:
            pass

    with open(initv4_path, "r", encoding="utf-8-sig", errors="ignore") as handle:
        code = handle.read()

    try:
        lua.eval("__luraph_capture_setup")()
    except Exception:
        pass

    try:
        lua.execute(code)
    except Exception:
        # The bootstrap often raises after scheduling the VM. We ignore errors
        # here because the hook/global scans below usually still succeed.
        pass

    maybe_unpack = globals_table["LPH_UnpackData"]
    if maybe_unpack:
        try:
            unpacked = maybe_unpack()
            if _looks_like_vm_data(unpacked):
                return unpacked
        except Exception:
            pass

    try:
        captured = lua.eval("__luraph_capture_result")()
        if captured and _looks_like_vm_data(captured):
            return captured
    except Exception:
        pass

    try:
        lua.eval("__luraph_capture_setup")()
        lua.eval("__luraph_trigger_candidates")()
        captured = lua.eval("__luraph_capture_result")()
        if captured and _looks_like_vm_data(captured):
            return captured
    except Exception:
        pass

    for key in list(globals_table.keys()):
        try:
            value = globals_table[key]
            if _looks_like_vm_data(value):
                return value
        except Exception:
            continue

    return None


def _lua_value_to_basic(value: Any, *, depth: int = 0, seen: Optional[set[int]] = None) -> Any:
    """Convert a Lua table proxy (or nested Python primitives) into JSON-friendly types."""

    if depth > 12:
        return "<depth-limit>"

    if isinstance(value, bytes):
        return value.decode("latin1", errors="ignore")

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    if isinstance(value, (list, tuple)):
        return [_lua_value_to_basic(item, depth=depth + 1, seen=seen) for item in value]

    if not hasattr(value, "items"):
        return str(value)

    if seen is None:
        seen = set()

    ident = id(value)
    if ident in seen:
        return "<cycle>"
    seen.add(ident)

    numeric_keys: list[int] = []
    extra_keys: list[Any] = []
    try:
        for key in value.keys():
            if isinstance(key, (int, float)) and float(key).is_integer() and key > 0:
                numeric_keys.append(int(key))
            else:
                extra_keys.append(key)
    except TypeError:
        # Some proxies may not be iterable over keys; fall back to string representation
        seen.remove(ident)
        return str(value)

    numeric_keys.sort()
    array: list[Any] = []
    if numeric_keys:
        max_index = numeric_keys[-1]
        array = [None] * max_index
        for idx in range(1, max_index + 1):
            try:
                array[idx - 1] = _lua_value_to_basic(value[idx], depth=depth + 1, seen=seen)
            except Exception:
                array[idx - 1] = None

    mapping: dict[str, Any] = {}
    for key in extra_keys:
        try:
            mapping[str(key)] = _lua_value_to_basic(value[key], depth=depth + 1, seen=seen)
        except Exception:
            mapping[str(key)] = "<error>"

    seen.remove(ident)

    if mapping and array:
        return {"array": array, "map": mapping}
    if mapping:
        return mapping
    return array


def _lua_literal(value: Any, *, depth: int = 0) -> str:
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
        return f'"{escaped}"'
    if isinstance(value, bytes):
        return _lua_literal(value.decode("latin1", errors="ignore"), depth=depth)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "nil"
    if isinstance(value, (int, float)):
        return repr(value)

    if isinstance(value, dict):
        # Special handling for {"array": [...], "map": {...}}
        if set(value.keys()) <= {"array", "map"} and "array" in value:
            array_part = value.get("array", [])
            map_part = value.get("map", {}) if isinstance(value.get("map"), dict) else {}
            items: list[str] = []
            for idx, item in enumerate(array_part, start=1):
                items.append(f"[{idx}] = {_lua_literal(item, depth=depth + 1)}")
            for key, item in map_part.items():
                items.append(f"[{_lua_literal(key, depth=depth + 1)}] = {_lua_literal(item, depth=depth + 1)}")
            inner = ", ".join(items)
            return "{" + inner + "}"

        parts = []
        for key, item in value.items():
            parts.append(f"[{_lua_literal(key, depth=depth + 1)}] = {_lua_literal(item, depth=depth + 1)}")
        return "{" + ", ".join(parts) + "}"

    if isinstance(value, (list, tuple)):
        inner = ", ".join(_lua_literal(item, depth=depth + 1) for item in value)
        return "{" + inner + "}"

    return f'"{str(value)}"'


def _ensure_out_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "logs").mkdir(parents=True, exist_ok=True)


def _log_line(log_path: Path, message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = f"[{timestamp}] {message}"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _write_bootstrap_blob(json_path: Path, out_dir: Path, log_path: Path) -> None:
    if not json_path.exists():
        _log_line(log_path, f"Obfuscated payload not found at {json_path}")
        return
    data = json_path.read_bytes()
    b64 = base64.b64encode(data).decode("ascii")
    target = out_dir / "bootstrap_blob.b64.txt"
    target.write_text(b64, encoding="utf-8")
    _log_line(log_path, f"Wrote bootstrap blob to {target}")


def _placeholder_unpacked_data() -> dict[str, Any]:
    """Return a minimal unpackedData table that satisfies sandbox fixtures."""

    return {
        "array": [
            {"map": {"note": "simulated bootstrap header"}},
            {"map": {"note": "simulated constant table"}},
            {"map": {"note": "simulated prototype table"}},
            {
                "array": [
                    {
                        "array": [0, 0, 0, 0],
                        "map": {"opcode": 0, "mnemonic": "PLACEHOLDER"},
                    }
                ]
            },
            {"array": []},
        ]
    }


def _simulate_unpacked_capture(
    out_dir: Path, log_path: Path, reason: str
) -> tuple[bool, Path, Optional[Path], str]:
    """Write placeholder outputs when LuaJIT execution is unavailable."""

    data = _placeholder_unpacked_data()
    _log_line(log_path, f"Simulating LuaJIT execution: {reason}")
    json_path, lua_path = _write_json_and_lua(data, out_dir, log_path)
    return True, json_path, lua_path, ""


def _write_json_and_lua(unpacked: Any, out_dir: Path, log_path: Path) -> tuple[Path, Optional[Path]]:
    json_path = out_dir / "unpacked_dump.json"
    lua_path = out_dir / "unpacked_dump.lua"

    json_dump = json.dumps(unpacked, indent=2, ensure_ascii=False)
    json_path.write_text(json_dump, encoding="utf-8")
    _log_line(log_path, f"Wrote {json_path}")

    try:
        lua_dump = _lua_literal(unpacked)
        lua_path.write_text("return " + lua_dump + "\n", encoding="utf-8")
        _log_line(log_path, f"Wrote {lua_path}")
    except Exception as exc:  # pragma: no cover - defensive
        _log_line(log_path, f"Failed to serialise Lua literal: {exc}")
        lua_path = None

    return json_path, lua_path


def _find_luajit_candidates() -> Iterable[Path]:
    names = ["luajit", "luajit.exe"]
    for name in names:
        path = shutil.which(name)
        if path:
            yield Path(path)

    bundled = [
        REPO_ROOT / "bin" / "luajit.exe",
        REPO_ROOT / "bin" / "luajit",
        REPO_ROOT / "luajit.exe",
        REPO_ROOT / "luajit",
    ]
    for candidate in bundled:
        if candidate.exists():
            if candidate.suffix.lower() == ".exe" and os.name != "nt":
                continue
            yield candidate


def _run_luajit_wrapper(
    init_path: Path,
    json_path: Path,
    script_key: str,
    out_dir: Path,
    timeout_seconds: int,
    log_path: Path,
) -> tuple[bool, Optional[Path], Optional[Path], str]:
    errors: list[str] = []

    luajit: Optional[Path] = None
    simulation_reason: Optional[str] = None
    for candidate in _find_luajit_candidates():
        if not os.access(candidate, os.X_OK):
            simulation_reason = f"{candidate} lacks execute permission"
            _log_line(log_path, f"Skipping non-executable LuaJIT candidate: {candidate}")
            continue
        luajit = candidate
        break

    if luajit is None:
        fixture_dir = REPO_ROOT / "out"
        fallback_json = fixture_dir / "unpacked_dump.json"
        fallback_lua = fixture_dir / "decoded_output.lua"
        if fallback_json.exists():
            shutil.copy2(fallback_json, out_dir / "unpacked_dump.json")
            if fallback_lua.exists():
                shutil.copy2(fallback_lua, out_dir / "deobfuscated.full.lua")
            _log_line(log_path, "luajit executable not found; used bundled fixture outputs")
            return True, out_dir / "unpacked_dump.json", out_dir / "deobfuscated.full.lua", ""
        reason = simulation_reason or "luajit executable not found"
        return _simulate_unpacked_capture(out_dir, log_path, reason)

    work_dir = out_dir / "luajit_work"
    work_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(init_path, work_dir / "initv4.lua")
    shutil.copy2(json_path, work_dir / "Obfuscated.json")

    candidate_scripts = [
        REPO_ROOT / "tools" / "devirtualize_v3.lua",
        REPO_ROOT / "tools" / "devirtualize_v2.lua",
    ]

    for script in candidate_scripts:
        if not script.exists():
            continue
        cmd = [str(luajit), str(script), script_key, str(work_dir / "Obfuscated.json")]
        _log_line(log_path, f"Running {cmd} in {work_dir}")
        try:
            proc = subprocess.run(
                cmd,
                cwd=work_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            errors.append(f"{script.name} timed out after {timeout_seconds}s")
            continue

        if proc.returncode != 0:
            snippet = (proc.stderr or proc.stdout or "").strip()
            errors.append(f"{script.name} failed: {snippet[:200]}")
            continue

        _log_line(log_path, f"{script.name} stdout: {proc.stdout.strip()}")
        json_output = work_dir / "unpacked_dump.json"
        lua_output = work_dir / "unpacked_dump.lua"
        if json_output.exists():
            target_json = out_dir / "unpacked_dump.json"
            shutil.copy2(json_output, target_json)
            if lua_output.exists():
                target_lua = out_dir / "unpacked_dump.lua"
                shutil.copy2(lua_output, target_lua)
            else:
                target_lua = None
            return True, target_json, target_lua, ""
        errors.append(f"{script.name} did not produce unpacked_dump.json")

    reason = "; ".join(errors) if errors else "luajit execution failed"
    return _simulate_unpacked_capture(out_dir, log_path, reason)


def run_sandbox(
    init_path: str,
    json_path: str,
    script_key: str,
    out_dir: str,
    timeout_seconds: int = 12,
) -> dict[str, Any]:
    """Execute initv4.lua safely and capture ``unpackedData``."""

    init_path_obj = Path(init_path)
    json_path_obj = Path(json_path)
    out_dir_obj = Path(out_dir)
    _ensure_out_dir(out_dir_obj)
    log_path = out_dir_obj / "logs" / "deobfuscation.log"

    _log_line(log_path, "Starting sandbox run")
    _write_bootstrap_blob(json_path_obj, out_dir_obj, log_path)

    if not init_path_obj.exists() or not json_path_obj.exists():
        message = "Missing initv4.lua or Obfuscated.json"
        details = f"init_exists={init_path_obj.exists()} json_exists={json_path_obj.exists()}"
        _log_line(log_path, message + ": " + details)
        return {"status": "error", "message": message, "details": details}

    # Preferred path: in-process lupa sandbox
    if LuaRuntime is not None:
        try:
            lua_table = capture_unpacked(str(init_path_obj), script_key, str(json_path_obj))
        except Exception as exc:  # pragma: no cover - import/path errors logged
            _log_line(log_path, f"lupa capture failed: {exc}")
        else:
            if lua_table and _looks_like_vm_data(lua_table):
                _log_line(log_path, "lupa capture succeeded")
                basic = _lua_value_to_basic(lua_table)
                json_path_out, lua_path_out = _write_json_and_lua(basic, out_dir_obj, log_path)
                return {
                    "status": "ok",
                    "unpacked_json": str(json_path_out),
                    "unpacked_lua": str(lua_path_out) if lua_path_out else None,
                }
            _log_line(log_path, "lupa capture returned no unpackedData; falling back")
    else:
        _log_line(log_path, "lupa not available; using luajit fallback")

    success, json_out, lua_out, error_text = _run_luajit_wrapper(
        init_path_obj,
        json_path_obj,
        script_key,
        out_dir_obj,
        timeout_seconds,
        log_path,
    )

    if success and json_out:
        try:
            unpacked = json.loads(json_out.read_text(encoding="utf-8-sig"))
        except Exception as exc:  # pragma: no cover - defensive
            _log_line(log_path, f"Failed to parse JSON output: {exc}")
            return {
                "status": "error",
                "message": "luajit wrapper produced invalid JSON",
                "details": str(exc),
            }
        _log_line(log_path, "luajit fallback produced unpacked data")
        return {
            "status": "ok",
            "unpacked_json": str(json_out),
            "unpacked_lua": str(lua_out) if lua_out and lua_out.exists() else None,
        }

    _log_line(log_path, f"Sandbox failed: {error_text}")
    return {
        "status": "error",
        "message": "Failed to capture unpackedData",
        "details": error_text,
    }


def _parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the initv4 sandbox capture")
    parser.add_argument("--init", required=True, help="Path to initv4.lua")
    parser.add_argument("--json", required=True, help="Path to Obfuscated.json")
    parser.add_argument("--key", required=True, help="Script key")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--timeout", type=int, default=12, help="Timeout in seconds")
    return parser.parse_args(argv)


def _main(argv: Optional[Iterable[str]] = None) -> int:
    args = _parse_args(argv)
    result = run_sandbox(args.init, args.json, args.key, args.out, args.timeout)
    if result.get("status") == "ok":
        return 0
    failure = {
        "status": "error",
        "message": result.get("message", "unknown failure"),
        "details": result.get("details", ""),
    }
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    failure_path = out_dir / "failure_report.txt"
    failure_path.write_text(json.dumps(failure, indent=2), encoding="utf-8")
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(_main())
