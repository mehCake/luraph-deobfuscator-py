"""Sandbox helpers for executing initv4 bootstraps inside LuaJIT via lupa."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    from lupa import LuaRuntime
except Exception:  # pragma: no cover - optional dependency
    LuaRuntime = None  # type: ignore[assignment]


@dataclass
class SandboxResult:
    unpacked: Optional[Any]
    error: Optional[Exception] = None


def capture_unpacked(lua_path: str, *, script_key: Optional[str] = None) -> SandboxResult:
    """Execute the given Lua bootstrapper and attempt to capture `unpackedData`.

    The helper creates a fresh LuaRuntime, injects the script key (if provided),
    runs the bootstrapper, then probes globals for a table that looks like the
    expected VM metadata. We keep the return structure light so callers can
    decide how to serialise the result.
    """

    if LuaRuntime is None:
        return SandboxResult(unpacked=None, error=RuntimeError("lupa is not installed"))

    lua = LuaRuntime(unpack_returned_tuples=True)

    if script_key:
        lua.execute("_G.script_key = ...", script_key)

    with open(lua_path, "r", encoding="utf-8", errors="ignore") as handle:
        source = handle.read()

    try:
        lua.execute(source)
    except Exception as exc:  # pragma: no cover - bootstrap often throws
        bootstrap_error = exc
    else:
        bootstrap_error = None

    globals_table = lua.globals()
    unpack_fn = globals_table.get("LPH_UnpackData")
    if callable(unpack_fn):
        try:
            unpacked = unpack_fn()
            return SandboxResult(unpacked=unpacked, error=bootstrap_error)
        except Exception as exc:  # pragma: no cover - fallback to scan
            bootstrap_error = exc

    for key in globals_table.keys():
        candidate = globals_table[key]
        if not hasattr(candidate, "__getitem__"):
            continue
        try:
            vm_instr = candidate[4]
            vm_consts = candidate[5]
        except Exception:
            continue
        if isinstance(vm_instr, lua.table) and vm_instr[1] and isinstance(vm_consts, lua.table):
            return SandboxResult(unpacked=candidate, error=bootstrap_error)

    return SandboxResult(unpacked=None, error=bootstrap_error)
