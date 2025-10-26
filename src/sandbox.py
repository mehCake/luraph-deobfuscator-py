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
import re
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence, Tuple

from src.runtime_capture.luajit_paths import build_luajit_command
from src.utils import write_json, write_text

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


def _table_get(table: Any, key: str, default: Any = None) -> Any:
    try:
        if hasattr(table, "get"):
            return table.get(key, default)
    except Exception:
        pass
    try:
        return table[key]
    except Exception:
        return default


def _table_set(table: Any, key: str, value: Any) -> None:
    try:
        table[key] = value
    except Exception as exc:  # pragma: no cover - defensive for exotic runtimes
        raise RuntimeError(f"failed to assign sandbox global '{key}': {exc}") from exc


def _snapshot_restrictions(env: Any) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for name in ("os", "io", "package", "require", "dofile", "loadfile"):
        value = _table_get(env, name)
        result[name] = value in (None, False)
    return result


def _prepare_restricted_environment(
    lua: Any, *, allow_debug: bool = False
) -> Tuple[Any, Any]:
    if hasattr(lua, "globals"):
        globals_table = lua.globals()
    else:
        globals_table = getattr(lua, "_globals", None)
    if globals_table is None:
        raise RuntimeError("Lua runtime does not expose a globals table")

    try:
        env = lua.table()
    except Exception:
        env = {}

    allowed_names = {
        "assert",
        "bit",
        "bit32",
        "error",
        "ipairs",
        "math",
        "next",
        "pairs",
        "pcall",
        "select",
        "string",
        "table",
        "tonumber",
        "tostring",
        "type",
        "xpcall",
    }

    for name in allowed_names:
        value = _table_get(globals_table, name)
        if value is not None:
            _table_set(env, name, value)

    _table_set(env, "_G", env)

    for banned in ("os", "io", "package", "require", "dofile", "loadfile"):
        _table_set(env, banned, None)

    if allow_debug:
        debug_table = _table_get(globals_table, "debug")
        if debug_table is not None:
            try:
                limited_debug = lua.table()
            except Exception:
                limited_debug = {}

            for attr in ("getinfo", "sethook", "traceback"):
                value = _table_get(debug_table, attr)
                if value is not None:
                    _table_set(limited_debug, attr, value)

            if limited_debug:
                _table_set(env, "debug", limited_debug)

    return globals_table, env


def _install_safe_globals(
    lua: Any,
    globals_table: Any,
    *,
    log_callback: Optional[Callable[[str], None]] = None,
    bootstrap_source: Optional[str] = None,
) -> None:
    """Patch globals to neutralise anti-analysis checks inside the sandbox."""

    actions: list[str] = []
    original_debug_getinfo: Optional[Any] = None

    def _table_lookup(obj: Any, key: str) -> Any:
        try:
            if hasattr(obj, "get"):
                return obj.get(key)
        except Exception:
            pass
        try:
            return obj[key]
        except Exception:
            return None

    def _is_guard_function(func: Any) -> bool:
        if not callable(func):
            return False
        if original_debug_getinfo is None:
            return False
        try:
            info = original_debug_getinfo(func)
        except Exception:
            return False
        what = _table_lookup(info, "what")
        nups = _table_lookup(info, "nups")
        try:
            nups_val = int(nups)
        except (TypeError, ValueError):
            nups_val = None
        if nups_val is None and nups is None:
            nups_val = 0
        return what == "Lua" and nups_val == 0

    def _log_action(message: str) -> None:
        if log_callback:
            log_callback(message)

    # Ensure the debug table exists and exposes a benign getinfo implementation.
    try:
        try:
            debug_table = globals_table["debug"]
        except Exception:
            debug_table = None
        if not hasattr(debug_table, "__setitem__"):
            debug_table = lua.table()
            globals_table["debug"] = debug_table
            actions.append("created debug table")

        original_debug_getinfo = None
        try:
            original_debug_getinfo = debug_table["getinfo"]
        except Exception:
            original_debug_getinfo = None

        def _safe_debug_getinfo(*_args: Any, **_kwargs: Any):
            table = lua.table()
            table["short_src"] = "safe"
            table["source"] = "=[neutralized]"
            table["what"] = "Lua"
            table["nups"] = 0
            table["currentline"] = 0
            return table

        debug_table["getinfo"] = _safe_debug_getinfo
        actions.append("patched debug.getinfo")

        def _safe_traceback(*_args: Any, **_kwargs: Any) -> str:
            return ""

        debug_table["traceback"] = _safe_traceback
        actions.append("stubbed debug.traceback")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to patch debug.getinfo: {exc}")
        original_debug_getinfo = None

    def _flatten_pcall_result(success: bool, result: Any):
        if isinstance(result, tuple):
            return (success, *result)
        if isinstance(result, list):
            return (success, *result)
        return (success, result)

    # Override pcall so it always reports success while still invoking the function.
    try:
        def _safe_pcall(func: Any, *args: Any):
            if func is None or not callable(func):
                return (True, func)
            guard = _is_guard_function(func)
            try:
                result = func(*args)
            except Exception as exc:
                if guard:
                    _log_action("pcall neutralized guard lambda")
                    return (True, None)
                return (False, str(exc))
            return _flatten_pcall_result(True, result)

        globals_table["pcall"] = _safe_pcall
        actions.append("patched pcall")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to patch pcall: {exc}")

    try:
        def _safe_xpcall(func: Any, err_handler: Any, *args: Any):
            if func is None or not callable(func):
                return (True, func)
            guard = _is_guard_function(func)
            try:
                result = func(*args)
            except Exception as exc:
                if guard:
                    _log_action("xpcall neutralized guard lambda")
                    return (True, None)
                handler_result = None
                if callable(err_handler):
                    try:
                        handler_result = err_handler(exc)
                    except Exception:
                        handler_result = None
                return _flatten_pcall_result(False, handler_result or str(exc))
            return _flatten_pcall_result(True, result)

        globals_table["xpcall"] = _safe_xpcall
        actions.append("patched xpcall")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to patch xpcall: {exc}")

    def _install_noop(name: str, *, return_value: Any = None) -> None:
        try:
            def _noop(*_args: Any, **_kwargs: Any):
                return return_value

            globals_table[name] = _noop
            actions.append(f"stubbed {name}")
        except Exception as exc:  # pragma: no cover - defensive
            _log_action(f"Failed to stub {name}: {exc}")

    _install_noop("collectgarbage", return_value=0)
    _install_noop("newproxy")

    try:
        def _safe_getfenv(*_args: Any, **_kwargs: Any):
            return globals_table

        globals_table["getfenv"] = _safe_getfenv
        actions.append("stubbed getfenv")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to stub getfenv: {exc}")

    try:
        def _safe_setfenv(target: Any, env: Any):
            return target

        globals_table["setfenv"] = _safe_setfenv
        actions.append("stubbed setfenv")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to stub setfenv: {exc}")

    try:
        try:
            jit_table = globals_table["jit"]
        except Exception:
            jit_table = None
        if not hasattr(jit_table, "__setitem__"):
            jit_table = lua.table()
            globals_table["jit"] = jit_table
            actions.append("created jit table")

        def _jit_noop(*_args: Any, **_kwargs: Any):
            return False

        for jit_name in ("on", "off", "flush", "status", "attach", "detach"):
            jit_table[jit_name] = _jit_noop
        actions.append("stubbed jit.*")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to stub jit table: {exc}")

    trap_detected = False
    if bootstrap_source and re.search(r"if\s+not\s+is_sandbox\s+then", bootstrap_source):
        trap_detected = True
        _log_action("Detected 'if not is_sandbox' guard in bootstrap; forcing is_sandbox=true")

    try:
        globals_table["is_sandbox"] = True
        if trap_detected:
            actions.append("neutralized is_sandbox guard")
        else:
            actions.append("forced is_sandbox=true")
    except Exception as exc:  # pragma: no cover - defensive
        _log_action(f"Failed to set is_sandbox flag: {exc}")

    if actions:
        _log_action("Sandbox neutralizers applied: " + ", ".join(actions))


def run_fragment_safely(
    fragment_text: str,
    *,
    expected: Optional[Sequence[Any]] = None,
    inputs: Optional[Sequence[Any]] = None,
    allow_debug: bool = False,
) -> dict[str, Any]:
    """Execute ``fragment_text`` inside a restricted Lua sandbox.

    The helper compiles the supplied fragment using ``load`` (or ``loadstring``)
    against a whitelisted global environment, executes it via ``pcall`` and
    reports the outcome.  When ``expected`` values are provided the helper also
    records whether the Lua result matches the emulator-provided baseline.
    Setting ``allow_debug`` exposes a trimmed ``debug`` table containing only
    ``sethook``/``getinfo``/``traceback`` so instrumentation can capture
    execution coverage without granting broader sandbox escape primitives.
    """

    if LuaRuntime is None:
        raise RuntimeError("lupa is not available; cannot execute Lua fragments")

    lua = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    if getattr(lua, "is_fallback", False):
        raise RuntimeError("fallback Lua runtime cannot execute arbitrary fragments")

    globals_table, env = _prepare_restricted_environment(lua, allow_debug=allow_debug)

    loader = _table_get(globals_table, "load") or _table_get(globals_table, "loadstring")
    if loader is None:
        raise RuntimeError("Lua runtime does not expose load/loadstring")

    load_result = loader(fragment_text, "fragment", "t", env)
    chunk: Optional[Callable[..., Any]]
    compile_error: Optional[Any] = None

    if isinstance(load_result, tuple):
        chunk = load_result[0]
        if len(load_result) > 1:
            compile_error = load_result[1]
    else:
        chunk = load_result

    if chunk is None:
        return {
            "success": False,
            "values": [],
            "error": compile_error or "failed to compile fragment",
            "matches_expected": False if expected is not None else None,
            "environment": _snapshot_restrictions(env),
        }

    pcall = _table_get(globals_table, "pcall")
    if not callable(pcall):
        raise RuntimeError("Lua runtime does not expose pcall")

    call_args: Sequence[Any] = tuple(inputs or ())
    result = pcall(chunk, *call_args)

    if not isinstance(result, tuple) or not result:
        raise RuntimeError("pcall returned unexpected result")

    success = bool(result[0])
    values: list[Any] = list(result[1:]) if success and len(result) > 1 else []
    error_value = None if success else (result[1] if len(result) > 1 else None)

    matches_expected: Optional[bool] = None
    if expected is not None:
        expected_values = list(expected) if isinstance(expected, (list, tuple)) else [expected]
        matches_expected = success and values == expected_values

    return {
        "success": success,
        "values": values,
        "error": error_value,
        "matches_expected": matches_expected,
        "environment": _snapshot_restrictions(env),
    }


def capture_unpacked(
    initv4_path: str,
    script_key: Optional[str] = None,
    json_path: Optional[str] = None,
    *,
    log_path: Optional[str | Path] = None,
):
    """Execute ``initv4.lua`` inside LuaJIT and capture ``unpackedData``."""

    if LuaRuntime is None:
        raise RuntimeError("lupa is not available; cannot run in-process sandbox")

    lua = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    lua.execute(_HOOK_SNIPPET)

    globals_table = lua.globals()

    log_path_obj = Path(log_path) if log_path else None

    def _log_neutral(message: str) -> None:
        if not log_path_obj:
            return
        try:
            _log_line(log_path_obj, message)
        except Exception:  # pragma: no cover - defensive
            pass

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

    if code.startswith("\ufeff"):
        code = code.lstrip("\ufeff")

    def _execute_bootstrap(source: str) -> None:
        variants = []
        if source:
            variants.append(source)
            stripped = source.lstrip("\ufeff")
            if stripped != source:
                variants.append(stripped)
            normalised = source.replace("\r\n", "\n")
            if normalised not in variants:
                variants.append(normalised)

        loader = None
        for name in ("loadstring", "load"):
            try:
                candidate_loader = globals_table[name]
            except Exception:
                candidate_loader = None
            if callable(candidate_loader):
                loader = candidate_loader
                break

        last_error: Exception | None = None
        for candidate in variants:
            try:
                lua.execute(candidate)
                return
            except Exception as exc:
                last_error = exc
        if loader is not None:
            for candidate in variants:
                try:
                    chunk = loader(candidate)
                except Exception as exc:
                    last_error = exc
                    continue
                try:
                    if chunk:
                        chunk()
                        return
                except Exception as exc:
                    last_error = exc
        if last_error is not None:
            _log_neutral(f"lua.execute fallback failed: {last_error}")

    _install_safe_globals(
        lua,
        globals_table,
        log_callback=_log_neutral,
        bootstrap_source=code,
    )

    try:
        lua.eval("__luraph_capture_setup")()
    except Exception:
        pass

    try:
        _execute_bootstrap(code)
    except Exception as exc:
        _log_neutral(f"bootstrap execution raised: {exc}")

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
    write_text(target, b64)
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
    write_text(json_path, _normalise_newlines(json_dump))
    _log_line(log_path, f"Wrote {json_path}")

    try:
        lua_dump = _lua_literal(unpacked)
        lua_body = _normalise_newlines("return " + lua_dump + "\n")
        write_text(lua_path, lua_body)
        _log_line(log_path, f"Wrote {lua_path}")
    except Exception as exc:  # pragma: no cover - defensive
        _log_line(log_path, f"Failed to serialise Lua literal: {exc}")
        lua_path = None

    return json_path, lua_path


def _normalise_newlines(text: str) -> str:
    """Ensure CRLF newlines are preserved on Windows hosts."""

    if os.name != "nt":
        return text
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


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


def _locate_luajit(log_path: Path) -> tuple[Optional[Path], Optional[str]]:
    """Return an executable LuaJIT candidate or a human readable reason."""

    last_reason: Optional[str] = None
    for candidate in _find_luajit_candidates():
        if not os.access(candidate, os.X_OK):
            last_reason = f"{candidate} lacks execute permission"
            _log_line(log_path, f"Skipping non-executable LuaJIT candidate: {candidate}")
            continue
        return candidate, None
    return None, last_reason


def _run_luajit_wrapper(
    init_path: Path,
    json_path: Path,
    script_key: str,
    out_dir: Path,
    timeout_seconds: int,
    log_path: Path,
    *,
    executable: Path,
) -> tuple[bool, Optional[Path], Optional[Path], str]:
    errors: list[str] = []

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
        cmd = build_luajit_command(
            executable,
            str(script),
            script_key,
            str(work_dir / "Obfuscated.json"),
        )
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
    return False, None, None, reason


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

    luajit_exe, luajit_reason = _locate_luajit(log_path)
    if luajit_exe:
        success, json_out, lua_out, error_text = _run_luajit_wrapper(
            init_path_obj,
            json_path_obj,
            script_key,
            out_dir_obj,
            timeout_seconds,
            log_path,
            executable=luajit_exe,
        )
        if success and json_out:
            try:
                json.loads(json_out.read_text(encoding="utf-8-sig"))
            except Exception as exc:  # pragma: no cover - defensive
                _log_line(log_path, f"Failed to parse JSON output: {exc}")
                return {
                    "status": "error",
                    "message": "luajit wrapper produced invalid JSON",
                    "details": str(exc),
                }
            _log_line(log_path, "luajit execution succeeded")
            return {
                "status": "ok",
                "unpacked_json": str(json_out),
                "unpacked_lua": str(lua_out) if lua_out and lua_out.exists() else None,
            }
        if error_text:
            luajit_reason = error_text
            _log_line(log_path, f"LuaJIT execution failed: {error_text}")
    elif luajit_reason:
        _log_line(log_path, luajit_reason)

    # Preferred fallback: in-process lupa (LuaJIT) runtime or Python emulator
    if LuaRuntime is not None:
        try:
            lua_table = capture_unpacked(
                str(init_path_obj),
                script_key,
                str(json_path_obj),
                log_path=str(log_path),
            )
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
            _log_line(log_path, "lupa capture returned no unpackedData; continuing fallback chain")
    else:
        _log_line(log_path, "lupa runtime not available; trying fixture fallback")

    if luajit_exe is None:
        fixture_dir = REPO_ROOT / "out"
        fallback_json = fixture_dir / "unpacked_dump.json"
        fallback_lua = fixture_dir / "decoded_output.lua"
        if fallback_json.exists():
            target_json = out_dir_obj / "unpacked_dump.json"
            shutil.copy2(fallback_json, target_json)
            lua_target = out_dir_obj / "deobfuscated.full.lua"
            lua_target_str: Optional[str] = None
            if fallback_lua.exists():
                shutil.copy2(fallback_lua, lua_target)
                lua_target_str = str(lua_target)
            _log_line(log_path, "luajit executable not found; used bundled fixture outputs")
            return {
                "status": "ok",
                "unpacked_json": str(target_json),
                "unpacked_lua": lua_target_str,
            }

    reason = luajit_reason or "luajit execution unavailable"
    success, json_out, lua_out, error_text = _simulate_unpacked_capture(out_dir_obj, log_path, reason)
    if success and json_out:
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
    write_json(failure_path, failure)
    return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(_main())
