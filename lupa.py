"""Minimal fallback implementation of the :mod:`lupa` API used in tests."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator, List


class LuaError(RuntimeError):
    """Raised when the fallback runtime cannot evaluate the provided source."""


@dataclass
class LuaTable:
    """Lightweight representation of a Lua array-style table."""

    values: List[Any]

    def __len__(self) -> int:  # pragma: no cover - trivial forwarding
        return len(self.values)

    def __getitem__(self, index: int) -> Any:
        if not isinstance(index, int):
            raise TypeError("LuaTable indices must be integers")
        if index <= 0:
            raise IndexError("LuaTable uses 1-based indexing")
        return self.values[index - 1]

    def __iter__(self) -> Iterator[Any]:  # pragma: no cover - iteration helper
        return iter(self.values)


def _translate_table_literal(source: str) -> str:
    # Replace Lua table braces with ``LuaTable([...])`` constructors.  The
    # transformation preserves nested structures well enough for the fixtures
    # exercised by the tests where tables are simple arrays.
    result: List[str] = []
    for ch in source:
        if ch == "{":
            result.append("LuaTable([")
        elif ch == "}":
            result.append("])")
        else:
            result.append(ch)
    return "".join(result)


def _translate_literals(source: str) -> str:
    translated = _translate_table_literal(source)
    translated = re.sub(r"\bnil\b", "None", translated)
    translated = re.sub(r"\btrue\b", "True", translated)
    translated = re.sub(r"\bfalse\b", "False", translated)
    return translated


def _lua_type(value: Any) -> str:
    if isinstance(value, LuaTable):
        return "table"
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _lua_len(value: Any) -> int:
    if isinstance(value, LuaTable):
        return len(value)
    try:
        return len(value)  # type: ignore[arg-type]
    except TypeError as exc:  # pragma: no cover - defensive
        raise LuaError(str(exc)) from exc


class LuaRuntime:
    """Subset of :class:`lupa.LuaRuntime` sufficient for the tests."""

    def __init__(self, *_, **__):
        self._globals: dict[str, Any] = {}

    def execute(self, source: str) -> None:
        python_source = _translate_literals(source)
        try:
            exec(python_source, {"LuaTable": LuaTable}, self._globals)
        except Exception as exc:  # pragma: no cover - error handling
            raise LuaError(str(exc)) from exc

    def eval(self, expr: str) -> Any:
        expr = expr.strip()
        if expr.startswith("#"):
            python_expr = f"_lua_len({expr[1:]})"
        else:
            python_expr = expr
        python_expr = python_expr.replace("type(", "_lua_type(")
        python_expr = _translate_literals(python_expr)
        try:
            return eval(
                python_expr,
                {"LuaTable": LuaTable, "_lua_type": _lua_type, "_lua_len": _lua_len},
                self._globals,
            )
        except Exception as exc:  # pragma: no cover - defensive
            raise LuaError(str(exc)) from exc


__all__ = ["LuaRuntime", "LuaTable", "LuaError"]
