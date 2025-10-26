from __future__ import annotations

from typing import Any, Dict, Tuple

import pytest

from src import sandbox


class _FakeTable(dict):
    """Dictionary-based stand-in for Lua tables used in tests."""


class _FakeRuntime:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        self.is_fallback = False
        self._pcalled = False
        self._globals: Dict[str, Any] = {
            "pcall": self._pcall,
            "load": self._load,
            "string": {"upper": lambda value: str(value).upper()},
            "table": {"concat": lambda seq, sep="": sep.join(seq)},
            "bit32": {},
            "bit": {},
            "tonumber": int,
            "tostring": str,
            "pairs": lambda tbl: iter(tbl.items()),
            "ipairs": lambda tbl: ((idx, value) for idx, value in enumerate(tbl, 1)),
            "type": lambda value: type(value).__name__,
            "error": RuntimeError,
            "next": lambda tbl, key=None: None,
        }

    def globals(self) -> Dict[str, Any]:
        return self._globals

    def table(self) -> _FakeTable:
        return _FakeTable()

    def _pcall(self, func: Any, *args: Any) -> Tuple[Any, ...]:
        self._pcalled = True
        try:
            result = func(*args)
        except Exception as exc:  # pragma: no cover - defensive
            return (False, exc)
        if isinstance(result, tuple):
            return (True, *result)
        if result is None:
            return (True,)
        return (True, result)

    def _load(self, source: str, *_args: Any) -> Tuple[Any, None]:
        text = source.strip()
        if "return" not in text:
            return None, "no return statement"

        _, expr = text.split("return", 1)
        expr = expr.strip()

        if expr == '"HELLO"':
            return (lambda: "HELLO"), None
        if expr == "string.upper('world')":
            return (lambda env=None: self._globals["string"]["upper"]("world")), None
        if expr == "...":
            return (lambda *args: args[0]), None

        raise RuntimeError(f"unsupported expression: {expr}")


def test_run_fragment_safely_uses_restricted_environment(monkeypatch):
    runtime = _FakeRuntime()

    def _runtime_factory(*_args: Any, **_kwargs: Any) -> _FakeRuntime:
        return runtime

    monkeypatch.setattr(sandbox, "LuaRuntime", _runtime_factory)

    result = sandbox.run_fragment_safely("return \"HELLO\"", expected=["HELLO"])

    assert result["success"] is True
    assert result["values"] == ["HELLO"]
    assert result["matches_expected"] is True
    # Ensure sandboxed environment blanks unsafe modules
    assert result["environment"]["os"] is True
    assert result["environment"]["io"] is True
    assert runtime._pcalled is True


def test_run_fragment_safely_handles_argument_roundtrip(monkeypatch):
    runtime = _FakeRuntime()

    def _runtime_factory(*_args: Any, **_kwargs: Any) -> _FakeRuntime:
        return runtime

    monkeypatch.setattr(sandbox, "LuaRuntime", _runtime_factory)

    result = sandbox.run_fragment_safely("return ...", inputs=["payload"], expected=["payload"])

    assert result["success"] is True
    assert result["values"] == ["payload"]
    assert result["matches_expected"] is True


def test_run_fragment_safely_reports_compile_failure(monkeypatch):
    runtime = _FakeRuntime()

    def _runtime_factory(*_args: Any, **_kwargs: Any) -> _FakeRuntime:
        return runtime

    monkeypatch.setattr(sandbox, "LuaRuntime", _runtime_factory)

    result = sandbox.run_fragment_safely("local x = 1", expected=[None])

    assert result["success"] is False
    assert "return" in str(result["error"])
    assert result["matches_expected"] is False
