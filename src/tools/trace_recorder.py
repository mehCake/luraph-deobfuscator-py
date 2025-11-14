"""Sandboxed Lua trace recorder for lightweight VM instrumentation.

This module executes small Lua snippets inside a constrained runtime and
records calls to a ``trace_emit`` helper injected into the global namespace.
Each call is treated as one VM instruction.  The recorder captures stack depth
information, register usage metadata, and persists the trace as JSON artefacts
for downstream analysis tools.

The implementation favours safety over completeness: the sandbox blocks common
filesystem and operating-system primitives and enforces a hard instruction
limit.  The helper is intended for short, synthetic scenarios that exercise the
analysis pipeline without executing untrusted bootstrap payloads in full.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence


try:  # pragma: no cover - optional dependency; tests exercise the fallback
    from lupa import LuaError, LuaRuntime
except Exception:  # pragma: no cover - fallback shim bundled with the repo
    from .. import lupa as _fallback_lupa

    LuaRuntime = getattr(_fallback_lupa, "LuaRuntime", None)  # type: ignore[assignment]
    LuaError = getattr(_fallback_lupa, "LuaError", RuntimeError)  # type: ignore[assignment]
    LuaTable = getattr(_fallback_lupa, "LuaTable", None)
else:  # pragma: no cover - only executed when real lupa available
    LuaTable = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)


class TraceRecorderError(RuntimeError):
    """Raised when the trace recorder fails to execute the sandboxed snippet."""


@dataclass
class TraceEvent:
    """Represents a single VM instruction observed during sandbox execution."""

    pc: int
    opcode: str
    stack_depth: int
    register_usage: int
    registers: List[Any] = field(default_factory=list)
    extras: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceRecording:
    """Structured trace information for a sandbox run."""

    run_name: str
    events: List[TraceEvent]
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def summary(self) -> Dict[str, Any]:
        """Return aggregate statistics derived from the recorded events."""

        opcode_histogram: Dict[str, int] = {}
        max_stack = 0
        max_registers = 0
        for event in self.events:
            opcode_histogram[event.opcode] = opcode_histogram.get(event.opcode, 0) + 1
            max_stack = max(max_stack, event.stack_depth)
            max_registers = max(max_registers, event.register_usage)
        return {
            "total_instructions": len(self.events),
            "unique_opcodes": len(opcode_histogram),
            "opcode_histogram": opcode_histogram,
            "max_stack_depth": max_stack,
            "max_register_usage": max_registers,
        }


def _get_globals(runtime: LuaRuntime) -> MutableMapping[str, Any]:
    if hasattr(runtime, "globals"):
        return runtime.globals()  # type: ignore[return-value]
    if hasattr(runtime, "_globals"):
        return getattr(runtime, "_globals")  # pragma: no cover - fallback shim
    raise TraceRecorderError("Lua runtime does not expose globals table")


def _new_table(runtime: LuaRuntime) -> Any:
    if hasattr(runtime, "table_from"):
        return runtime.table_from({})  # type: ignore[call-arg]
    if hasattr(runtime, "table"):
        return runtime.table()
    if LuaTable is not None:
        return LuaTable([])  # type: ignore[call-arg]
    return {}


def _convert_python_to_lua(runtime: LuaRuntime, value: Any) -> Any:
    if isinstance(value, Mapping):
        table = _new_table(runtime)
        for key, item in value.items():
            table[key] = _convert_python_to_lua(runtime, item)
        return table
    if isinstance(value, (list, tuple)):
        table = _new_table(runtime)
        for index, item in enumerate(value, start=1):
            table[index] = _convert_python_to_lua(runtime, item)
        return table
    return value


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
        except Exception:  # pragma: no cover - defensive for fallback shim
            item = None
        if item is None:
            break
        sequential.append(_convert_lua_table_to_python(item))
        index += 1
    mapping: Dict[str, Any] = {}
    try:
        keys = list(value.keys())  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover - fallback shim uses generator
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


def _normalise_sequence(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if _is_lua_table(value):
        converted = _convert_lua_table_to_python(value)
        if isinstance(converted, list):
            return converted
        if isinstance(converted, dict) and "__array__" in converted:
            return list(converted["__array__"])
        return [converted]
    return [value]


def _normalise_mapping(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {str(key): val for key, val in value.items()}
    if _is_lua_table(value):
        converted = _convert_lua_table_to_python(value)
        if isinstance(converted, dict):
            return {str(key): val for key, val in converted.items() if key != "__array__"}
    return {"value": value}


def _make_forbidden(name: str):
    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise TraceRecorderError(f"sandboxed Lua attempted to access forbidden primitive '{name}'")

    return _forbidden


def _install_sandbox(runtime: LuaRuntime) -> None:
    globals_table = _get_globals(runtime)
    # Allow basic maths/string helpers while blocking filesystem/network primitives.
    globals_table["io"] = {"open": _make_forbidden("io.open"), "popen": _make_forbidden("io.popen")}
    globals_table["os"] = {
        "execute": _make_forbidden("os.execute"),
        "remove": _make_forbidden("os.remove"),
        "rename": _make_forbidden("os.rename"),
        "exit": _make_forbidden("os.exit"),
    }
    globals_table["require"] = _make_forbidden("require")
    globals_table["dofile"] = _make_forbidden("dofile")
    globals_table["loadfile"] = _make_forbidden("loadfile")
    globals_table["package"] = globals_table.get("package", {})
    globals_table["package"]["loadlib"] = _make_forbidden("package.loadlib")
    globals_table["package"]["searchpath"] = _make_forbidden("package.searchpath")
    globals_table["print"] = lambda *args, **kwargs: None


def record_trace(
    lua_source: str,
    *,
    entry_point: str = "run",
    run_name: str = "trace",
    input_data: Optional[Mapping[str, Any]] = None,
    max_instructions: int = 4096,
    timeout: float = 3.0,
) -> TraceRecording:
    """Execute *lua_source* and capture runtime trace events.

    Parameters
    ----------
    lua_source:
        Lua source defining the VM snippet to execute.  The chunk must expose
        ``entry_point`` in the global scope.
    entry_point:
        Global Lua function invoked after loading the chunk.
    run_name:
        Identifier used for file naming and metadata.
    input_data:
        Optional Python mapping converted to a Lua table and passed to the entry
        function.
    max_instructions:
        Hard limit for the number of ``trace_emit`` calls recorded.
    timeout:
        Soft execution limit in seconds.  The sandbox aborts when exceeded.
    """

    if LuaRuntime is None:  # pragma: no cover - exercised only when lupa missing entirely
        raise TraceRecorderError("lupa is not available; cannot record runtime trace")

    runtime = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    if getattr(runtime, "is_fallback", False):  # pragma: no cover - exercised in tests
        events = _parse_static_trace(lua_source, max_instructions)
        metadata = {
            "entry_point": entry_point,
            "max_instructions": max_instructions,
            "timeout": timeout,
            "mode": "static",
        }
        return TraceRecording(run_name=run_name, events=events, metadata=metadata)

    _install_sandbox(runtime)
    globals_table = _get_globals(runtime)

    trace_events: List[TraceEvent] = []
    start_time = time.monotonic()

    def _emit(pc: Any, opcode: Any, registers: Any = None, stack_depth: Any = None, extras: Any = None) -> bool:
        if (time.monotonic() - start_time) > timeout:
            raise TraceRecorderError("trace execution exceeded timeout")
        if len(trace_events) >= max_instructions:
            raise TraceRecorderError("instruction limit exceeded during trace capture")
        regs = _normalise_sequence(registers)
        depth = int(stack_depth) if stack_depth is not None else len(regs)
        extras_map = _normalise_mapping(extras)
        event = TraceEvent(
            pc=int(pc),
            opcode=str(opcode),
            stack_depth=depth,
            register_usage=sum(1 for item in regs if item is not None),
            registers=regs,
            extras=extras_map,
        )
        trace_events.append(event)
        return True

    globals_table["trace_emit"] = _emit

    try:
        runtime.execute(lua_source)
    except LuaError as exc:  # pragma: no cover - depends on runtime availability
        raise TraceRecorderError(f"failed to execute Lua source: {exc}") from exc

    entry = globals_table.get(entry_point)
    if entry is None:
        raise TraceRecorderError(f"entry point '{entry_point}' not defined in Lua source")

    lua_input = _convert_python_to_lua(runtime, input_data or {})

    try:
        entry(lua_input)
    except LuaError as exc:  # pragma: no cover - depends on runtime availability
        raise TraceRecorderError(f"error while executing entry point: {exc}") from exc

    metadata = {
        "entry_point": entry_point,
        "max_instructions": max_instructions,
        "timeout": timeout,
        "mode": "runtime",
    }
    return TraceRecording(run_name=run_name, events=trace_events, metadata=metadata)


def _parse_static_trace(lua_source: str, max_instructions: int) -> List[TraceEvent]:
    marker = re.search(r"--\s*trace\s*:\s*\[", lua_source, re.IGNORECASE)
    if not marker:
        raise TraceRecorderError(
            "fallback Lua runtime requires a '-- trace: [...]' JSON annotation to record events"
        )
    start = lua_source.find("[", marker.start())
    depth = 0
    end = None
    index = start
    length = len(lua_source)
    while index < length:
        ch = lua_source[index]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
        elif ch in "\"'":
            quote = ch
            index += 1
            while index < length:
                current = lua_source[index]
                if current == "\\":
                    index += 2
                    continue
                if current == quote:
                    break
                index += 1
        index += 1
    if end is None:
        raise TraceRecorderError("unterminated trace JSON annotation")
    json_blob = lua_source[start:end]
    try:
        payload = json.loads(json_blob)
    except json.JSONDecodeError as exc:
        raise TraceRecorderError(f"invalid trace JSON annotation: {exc}") from exc
    events: List[TraceEvent] = []
    for item in payload:
        regs = _normalise_sequence(item.get("registers"))
        depth = int(item.get("stack", len(regs)))
        event = TraceEvent(
            pc=int(item.get("pc", len(events) + 1)),
            opcode=str(item.get("opcode", "UNKNOWN")),
            stack_depth=depth,
            register_usage=sum(1 for value in regs if value is not None),
            registers=regs,
            extras=_normalise_mapping(item.get("extras")),
        )
        events.append(event)
        if len(events) > max_instructions:
            raise TraceRecorderError("instruction limit exceeded during static trace parsing")
    return events


def write_trace(recording: TraceRecording, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{recording.run_name}.json"
    payload = {
        "run": recording.run_name,
        "metadata": recording.metadata,
        "summary": recording.summary,
        "events": [
            {
                "pc": event.pc,
                "opcode": event.opcode,
                "stack_depth": event.stack_depth,
                "register_usage": event.register_usage,
                "registers": event.registers,
                "extras": event.extras,
            }
            for event in recording.events
        ],
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return target


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Record sandboxed Lua VM traces")
    parser.add_argument("lua_file", type=Path, help="Path to Lua file containing the VM snippet")
    parser.add_argument("--entry", default="run", help="Entry point function name inside the Lua chunk")
    parser.add_argument("--run-name", default="trace", help="Identifier used for the trace artefact")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/traces"),
        help="Directory where trace JSON files are written (default: out/traces)",
    )
    parser.add_argument(
        "--input-json",
        type=Path,
        help="Optional JSON file converted to a Lua table and passed to the entry point",
    )
    parser.add_argument(
        "--max-instructions",
        type=int,
        default=1024,
        help="Maximum number of instructions to record (default: 1024)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Maximum execution time in seconds before aborting (default: 3.0)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    lua_source = args.lua_file.read_text(encoding="utf-8")
    input_data = None
    if args.input_json:
        input_data = json.loads(args.input_json.read_text(encoding="utf-8"))

    recording = record_trace(
        lua_source,
        entry_point=args.entry,
        run_name=args.run_name,
        input_data=input_data,
        max_instructions=args.max_instructions,
        timeout=args.timeout,
    )
    target = write_trace(recording, args.output_dir)
    LOGGER.info("Trace written to %s", target)
    print(target)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI helper
    raise SystemExit(main())
