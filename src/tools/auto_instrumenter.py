"""Sandboxed instrumentation of small bootstrap excerpts.

This helper takes a Lua snippet, injects lightweight logging wrappers around
known helper functions, and executes the modified code inside the project’s
sandboxed runtime.  All changes happen in-memory: the original snippet is left
untouched on disk and the instrumented version is never written anywhere.  The
captured logs – typically VM state transitions – are returned to Python for
further analysis.

The implementation intentionally restricts what can be instrumented.  Each
target function must be explicitly supplied and located inside the snippet;
when the function cannot be found the instrumenter aborts to avoid modifying
unexpected code paths.  This mirrors the workflow used when analysing Luraph
payloads where only vetted helpers should be inspected.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence


try:  # pragma: no cover - optional dependency; tests exercise the fallback shim
    from lupa import LuaError, LuaRuntime
except Exception:  # pragma: no cover - fallback bundled with the repository
    from .. import lupa as _fallback_lupa

    LuaRuntime = getattr(_fallback_lupa, "LuaRuntime", None)  # type: ignore[assignment]
    LuaError = getattr(_fallback_lupa, "LuaError", RuntimeError)  # type: ignore[assignment]
    LuaTable = getattr(_fallback_lupa, "LuaTable", None)
else:  # pragma: no cover - real lupa available
    LuaTable = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)


class AutoInstrumenterError(RuntimeError):
    """Raised when the auto instrumenter fails to run a snippet safely."""


@dataclass(slots=True)
class InstrumentationLogEntry:
    """Structured representation of a single instrumentation event."""

    event: str
    name: str
    payload: Any


@dataclass(slots=True)
class InstrumentationSummary:
    """Metadata describing an instrumentation run."""

    instrumented_functions: Sequence[str]
    restored: bool
    log_limit: int
    warnings: Sequence[str]


@dataclass(slots=True)
class InstrumentationResult:
    """Outcome of an instrumentation session."""

    logs: List[InstrumentationLogEntry]
    summary: InstrumentationSummary


@dataclass(slots=True)
class InstrumentationConfig:
    """Configuration describing which helpers should be instrumented."""

    functions: Sequence[str]
    invocations: Sequence[str] = ()
    log_limit: int = 256
    allow_missing: bool = False


def _get_globals(runtime: LuaRuntime) -> MutableMapping[str, Any]:
    if hasattr(runtime, "globals"):
        return runtime.globals()  # type: ignore[return-value]
    if hasattr(runtime, "_globals"):
        return getattr(runtime, "_globals")  # pragma: no cover - fallback shim
    raise AutoInstrumenterError("Lua runtime does not expose globals table")


def _make_forbidden(name: str):
    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise AutoInstrumenterError(
            f"sandboxed Lua attempted to access forbidden primitive '{name}'"
        )

    return _forbidden


def _install_sandbox(runtime: LuaRuntime) -> None:
    globals_table = _get_globals(runtime)
    globals_table["io"] = {"open": _make_forbidden("io.open"), "popen": _make_forbidden("io.popen")}
    globals_table["os"] = {
        "execute": _make_forbidden("os.execute"),
        "remove": _make_forbidden("os.remove"),
        "rename": _make_forbidden("os.rename"),
        "exit": _make_forbidden("os.exit"),
    }
    globals_table["require"] = _make_forbidden("require")
    globals_table["package"] = {"loaded": {}, "preload": {}}


def _is_lua_table(value: Any) -> bool:
    if LuaTable is not None and isinstance(value, LuaTable):  # type: ignore[arg-type]
        return True
    return hasattr(value, "keys") and hasattr(value, "__getitem__")


def _convert_lua_table_to_python(value: Any) -> Any:
    if not _is_lua_table(value):
        return value

    sequential: List[Any] = []
    index = 1
    while True:
        try:
            item = value[index]
        except Exception:  # pragma: no cover - fallback shim behaviour
            item = None
        if item is None:
            break
        sequential.append(_convert_lua_table_to_python(item))
        index += 1

    mapping: Dict[str, Any] = {}
    try:
        keys = list(value.keys())  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - fallback shim generator
        keys = []
        try:
            iterator = value.keys()  # type: ignore[attr-defined]
            for key in iterator:
                keys.append(key)
        except Exception:
            keys = []

    for key in keys:
        if isinstance(key, int) and 1 <= key <= len(sequential):
            continue
        mapping[str(_convert_lua_table_to_python(key))] = _convert_lua_table_to_python(value[key])

    if mapping:
        if sequential:
            mapping.setdefault("__array__", sequential)
        return mapping
    return sequential


def _validate_targets(snippet: str, functions: Iterable[str]) -> List[str]:
    missing: List[str] = []
    for name in functions:
        pattern = re.compile(
            rf"(function\s+{re.escape(name)}\b)|({re.escape(name)}\s*=\s*function)|"
            rf"(function\s+\w+\.{re.escape(name)}\b)"
        )
        if not pattern.search(snippet):
            missing.append(name)
    return missing


def _ensure_runtime() -> LuaRuntime:
    if LuaRuntime is None:  # pragma: no cover - defensive: fallback missing
        raise AutoInstrumenterError("Lua runtime is not available; install 'lupa'")
    runtime = LuaRuntime(unpack_returned_tuples=True)
    _install_sandbox(runtime)
    return runtime


def instrument_bootstrap(snippet: str, config: InstrumentationConfig) -> InstrumentationResult:
    """Instrument ``snippet`` according to ``config`` and execute it safely."""

    if not config.functions:
        raise AutoInstrumenterError("at least one target function must be supplied")

    missing = _validate_targets(snippet, config.functions)
    warnings_py: List[str] = []
    if missing and not config.allow_missing:
        raise AutoInstrumenterError(
            "refusing to instrument snippet; missing targets: " + ", ".join(sorted(missing))
        )
    if missing and config.allow_missing:
        warnings_py = [f"missing target '{name}'" for name in missing]

    runtime = _ensure_runtime()
    if getattr(runtime, "is_fallback", False):
        raise AutoInstrumenterError(
            "auto instrumentation requires the real 'lupa' runtime; install the dependency to execute snippets"
        )

    lua_snippet = json.dumps(snippet)
    targets = "{" + ",".join(json.dumps(name) for name in config.functions) + "}"
    invocations = "{" + ",".join(json.dumps(expr) for expr in config.invocations) + "}"

    script = f"""
local __auto_logs = {{}}
local __auto_limit = {int(config.log_limit)}
local __auto_targets = {targets}
local __auto_invocations = {invocations}
local __auto_pack = table.pack or function(...)
    return {{n = select('#', ...), ...}}
end
local __auto_unpack = table.unpack or unpack

local function __auto_to_array(list)
    local limit = list.n or #list
    local out = {{}}
    for i = 1, limit do
        out[i] = list[i]
    end
    return out
end

local function __auto_log(event, name, payload)
    if #__auto_logs >= __auto_limit then
        return
    end
    __auto_logs[#__auto_logs + 1] = {{event = event, name = name, payload = payload}}
end

local function __auto_wrap(name, fn)
    if type(fn) ~= "function" then
        return fn
    end
        return function(...)
            local args = __auto_pack(...)
            __auto_log("call", name, __auto_to_array(args))
            local results = __auto_pack(fn(...))
            __auto_log("return", name, __auto_to_array(results))
            return __auto_unpack(results, 1, results.n or #results)
        end
    end

local function __auto_instrument(env)
    local originals = {{}}
    for i = 1, #__auto_targets do
        local name = __auto_targets[i]
        local fn = env[name]
        if type(fn) == "function" then
            originals[name] = fn
            env[name] = __auto_wrap(name, fn)
        end
    end
    return originals
end

local function __auto_restore(env, originals)
    for name, fn in pairs(originals) do
        env[name] = fn
    end
end

local function __auto_execute()
    local env = setmetatable({{}}, {{__index = _G}})
    local chunk, err = load({lua_snippet}, "auto_instrumenter", "t", env)
    if not chunk then
        return {{success = false, error = tostring(err)}}
    end
    local ok, exec_err = pcall(chunk)
    if not ok then
        return {{success = false, error = tostring(exec_err)}}
    end

    local originals = __auto_instrument(env)
    for i = 1, #__auto_invocations do
        local expr = __auto_invocations[i]
        local runner, load_err = load(expr, "auto_invoke", "t", env)
        if not runner then
            runner, load_err = load("return " .. expr, "auto_invoke", "t", env)
        end
        if not runner then
            __auto_log("invoke_error", expr, tostring(load_err))
        else
            local ok_run, packed = pcall(function()
                return __auto_pack(runner())
            end)
            if not ok_run then
                __auto_log("invoke_error", expr, {{tostring(packed)}})
            else
                __auto_log("invoke_result", expr, __auto_to_array(packed))
            end
        end
    end

    __auto_restore(env, originals)
    return {{
        success = true,
        logs = __auto_logs,
        restored = true,
        warnings = {{}},
    }}
end

return __auto_execute()
"""

    try:
        result = runtime.eval(script)
    except LuaError as exc:  # pragma: no cover - Lua errors are surfaced as Python exceptions
        raise AutoInstrumenterError(f"failed to execute instrumented snippet: {exc}") from exc

    if _is_lua_table(result):
        result = _convert_lua_table_to_python(result)

    if not isinstance(result, Mapping):
        raise AutoInstrumenterError("unexpected result returned by instrumentation runtime")

    if not result.get("success"):
        raise AutoInstrumenterError(str(result.get("error", "instrumentation failed")))

    logs_raw = result.get("logs", [])
    if _is_lua_table(logs_raw):
        logs_raw = _convert_lua_table_to_python(logs_raw)

    logs: List[InstrumentationLogEntry] = []
    for entry in logs_raw:
        if isinstance(entry, Mapping):
            event = str(entry.get("event", ""))
            name = str(entry.get("name", ""))
            payload = entry.get("payload")
        else:  # pragma: no cover - defensive
            event = "unknown"
            name = ""
            payload = entry
        if _is_lua_table(payload):
            payload = _convert_lua_table_to_python(payload)
        logs.append(InstrumentationLogEntry(event=event, name=name, payload=payload))

    warnings = result.get("warnings", [])
    if _is_lua_table(warnings):
        warnings = _convert_lua_table_to_python(warnings)

    warnings_list = list(warnings) if isinstance(warnings, list) else []
    warnings_list.extend(warnings_py)

    summary = InstrumentationSummary(
        instrumented_functions=list(config.functions),
        restored=bool(result.get("restored", False)),
        log_limit=config.log_limit,
        warnings=warnings_list,
    )

    return InstrumentationResult(logs=logs, summary=summary)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Instrument a Lua bootstrap snippet in-memory")
    parser.add_argument("snippet", type=Path, help="Path to the Lua snippet to instrument")
    parser.add_argument(
        "--function",
        "--target",
        dest="functions",
        action="append",
        required=True,
        help="Name of a helper function to instrument (can be supplied multiple times)",
    )
    parser.add_argument(
        "--invoke",
        dest="invocations",
        action="append",
        default=[],
        help="Lua expression to execute after instrumentation (e.g. 'vm_step()')",
    )
    parser.add_argument(
        "--log-limit",
        type=int,
        default=256,
        help="Maximum number of instrumentation events to capture",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Allow instrumentation even when some target functions cannot be located",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        help="Optional path where the instrumentation logs should be written as JSON",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    snippet_text = args.snippet.read_text(encoding="utf-8")
    config = InstrumentationConfig(
        functions=args.functions,
        invocations=args.invocations,
        log_limit=args.log_limit,
        allow_missing=args.allow_missing,
    )

    try:
        result = instrument_bootstrap(snippet_text, config)
    except AutoInstrumenterError as exc:
        parser.error(str(exc))
        return 2  # pragma: no cover - argparse already exits

    print(
        f"Captured {len(result.logs)} events (functions: {', '.join(result.summary.instrumented_functions)})"
    )

    if args.json_out:
        payload = {
            "logs": [asdict(entry) for entry in result.logs],
            "summary": asdict(result.summary),
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
