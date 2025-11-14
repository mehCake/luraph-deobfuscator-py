"""Verification harness for inline-emitted pseudo Lua snippets."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Mapping, Optional, Sequence

try:  # pragma: no cover - optional dependency
    from lupa import LuaError, LuaRuntime
except Exception:  # pragma: no cover - fallback when lupa missing
    LuaRuntime = None  # type: ignore[assignment]
    LuaError = Exception  # type: ignore[assignment]

from src.vm.inline_emitter import emit_inline_from_dict


@dataclass
class VerificationOutcome:
    name: str
    passed: bool
    details: str = ""
    registers: Sequence[Any] = ()
    constants: Sequence[Any] = ()


def _require_lupa() -> None:
    if LuaRuntime is None:  # pragma: no cover - environment without lupa
        raise RuntimeError(
            "lupa is required to run mapping verification; install lupa>=1.8"
        )


def _to_lua_sequence(runtime: "LuaRuntime", values: Iterable[Any]):
    table = runtime.table_from({})
    for index, value in enumerate(values, 1):
        table[index] = value
    return table


def _from_lua_sequence(table: Any) -> List[Any]:
    result: List[Any] = []
    if table is None:
        return result
    index = 1
    while True:
        try:
            value = table[index]
        except Exception:  # pragma: no cover - defensive
            break
        if value is None:
            break
        result.append(value)
        index += 1
    return result


def _table_value(table: Any, key: Any, default: Any = None) -> Any:
    try:
        value = table[key]
    except Exception:  # pragma: no cover - defensive
        return default
    if value is None:
        return default
    return value


def _indent_source(source: str, prefix: str = "    ") -> str:
    lines = source.splitlines()
    if not lines:
        return prefix.rstrip()
    return "\n".join(prefix + line if line else prefix.rstrip() for line in lines)


def _build_runner_source(inline_source: str) -> str:
    indented = _indent_source(inline_source)
    return (
        "local function make_runner()\n"
        "  return function(state)\n"
        "    local regs = state.regs or {}\n"
        "    local consts = state.consts or {}\n"
        "    local pc = state.pc or 0\n"
        f"{indented}\n"
        "    state.regs = regs\n"
        "    state.consts = consts\n"
        "    state.pc = pc\n"
        "    return state\n"
        "  end\n"
        "end\n"
        "return make_runner()"
    )


def verify_inline_snippet(inline_source: str, tests: Sequence[Mapping[str, Any]]) -> List[VerificationOutcome]:
    _require_lupa()
    runtime = LuaRuntime(unpack_returned_tuples=True)  # type: ignore[misc]
    if not hasattr(runtime, "globals"):
        return _python_fallback(inline_source, tests)
    loader = runtime.eval(
        "return function(src) local chunk, err = load(src, 'inline', 't') if not chunk then error(err) end return chunk end"
    )
    chunk = loader(_build_runner_source(inline_source))
    runner = chunk()

    outcomes: List[VerificationOutcome] = []
    for index, test in enumerate(tests):
        name = str(test.get("name", f"test_{index}"))
        state = runtime.table_from({})
        state["regs"] = _to_lua_sequence(runtime, test.get("registers", []))
        state["consts"] = _to_lua_sequence(runtime, test.get("constants", []))
        state["pc"] = test.get("pc", 0)

        try:
            result_state = runner(state)
        except LuaError as exc:  # pragma: no cover - depends on runtime
            outcomes.append(
                VerificationOutcome(
                    name=name,
                    passed=False,
                    details=f"runtime error: {exc}",
                )
            )
            continue

        result_regs = _from_lua_sequence(result_state["regs"])
        result_consts = _from_lua_sequence(result_state["consts"])
        expected = test.get("expect", {})

        mismatch: Optional[str] = None
        expected_regs = expected.get("registers")
        if expected_regs is not None and list(expected_regs) != result_regs[: len(expected_regs)]:
            mismatch = f"registers {result_regs} != {list(expected_regs)}"

        expected_pc = expected.get("pc")
        if mismatch is None and expected_pc is not None:
            pc_value = _table_value(result_state, "pc")
            if pc_value != expected_pc:
                mismatch = f"pc {pc_value} != {expected_pc}"

        outcomes.append(
            VerificationOutcome(
                name=name,
                passed=mismatch is None,
                details=mismatch or "",
                registers=result_regs,
                constants=result_consts,
            )
        )

    return outcomes


def _python_fallback(source: str, tests: Sequence[Mapping[str, Any]]) -> List[VerificationOutcome]:
    outcomes: List[VerificationOutcome] = []

    for index, test in enumerate(tests):
        name = str(test.get("name", f"test_{index}"))
        registers = list(test.get("registers", []))
        constants = list(test.get("constants", []))
        for line in source.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("--"):
                continue
            code = stripped.split("--", 1)[0].strip()
            if not code.startswith("regs["):
                continue
            dest, expr = code.split("=", 1)
            dest_name = dest.strip()
            index_start = dest_name.find("[") + 1
            index_end = dest_name.find("]", index_start)
            dest_index = int(dest_name[index_start:index_end])
            value = _evaluate_expression(expr.strip(), registers, constants)
            _set_register(registers, dest_index, value)

        expected = test.get("expect", {})
        mismatch: Optional[str] = None
        expected_regs = expected.get("registers")
        if expected_regs is not None and list(expected_regs) != registers[: len(expected_regs)]:
            mismatch = f"registers {registers} != {list(expected_regs)}"
        expected_pc = expected.get("pc")
        if mismatch is None and expected_pc is not None and test.get("pc", 0) != expected_pc:
            mismatch = f"pc {test.get('pc', 0)} != {expected_pc}"

        outcomes.append(
            VerificationOutcome(
                name=name,
                passed=mismatch is None,
                details=mismatch or "",
                registers=registers,
                constants=constants,
            )
        )

    return outcomes


class _IndexProxy:
    def __init__(self, backing: List[Any]):
        self._backing = backing

    def __getitem__(self, index: int) -> Any:
        idx = int(index)
        if idx <= 0:
            raise IndexError("indices must be positive")
        if idx > len(self._backing):
            return None
        return self._backing[idx - 1]


def _set_register(registers: List[Any], index: int, value: Any) -> None:
    if index <= 0:
        raise IndexError("indices must be positive")
    while len(registers) < index:
        registers.append(None)
    registers[index - 1] = value


def _evaluate_expression(expr: str, registers: List[Any], constants: List[Any]) -> Any:
    prepared = expr.replace("^", "**").replace("true", "True").replace("false", "False").replace("nil", "None")
    context = {"regs": _IndexProxy(registers), "consts": _IndexProxy(constants)}
    try:
        return eval(prepared, {"__builtins__": {}}, context)
    except Exception as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"failed to evaluate expression {expr!r}: {exc}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify inline emitted Lua snippets against test vectors")
    parser.add_argument("lift_result", type=Path, help="Lift result JSON file")
    parser.add_argument("tests", type=Path, help="JSON file containing verification vectors")
    parser.add_argument("--output", type=Path, help="Optional path to store verification summary JSON")
    args = parser.parse_args(argv)

    payload = json.loads(args.lift_result.read_text(encoding="utf-8"))
    inline_source = emit_inline_from_dict(payload, wrap=False)
    tests_payload = json.loads(args.tests.read_text(encoding="utf-8"))
    outcomes = verify_inline_snippet(inline_source, tests_payload)

    summary = {
        "total": len(outcomes),
        "passed": sum(1 for outcome in outcomes if outcome.passed),
        "failed": [outcome.name for outcome in outcomes if not outcome.passed],
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    else:
        print(json.dumps(summary, indent=2))

    return 0


__all__ = ["VerificationOutcome", "verify_inline_snippet"]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
