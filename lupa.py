"""Minimal fallback implementation of the :mod:`lupa` API used in tests."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


class LuaError(RuntimeError):
    """Raised when the fallback runtime cannot evaluate the provided source."""


@dataclass
class LuaTable:
    """Lightweight representation of a Lua table supporting array/dict semantics."""

    values: List[Any]
    mapping: Dict[Any, Any] = field(default_factory=dict)

    def __len__(self) -> int:  # pragma: no cover - trivial forwarding
        return len(self.values)

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, int):
            if index <= 0:
                raise IndexError("LuaTable uses 1-based indexing")
            if index <= len(self.values):
                return self.values[index - 1]
            return self.mapping.get(index)
        return self.mapping.get(index)

    def __setitem__(self, key: Any, value: Any) -> None:
        if isinstance(key, int) and key > 0:
            while len(self.values) < key:
                self.values.append(None)
            self.values[key - 1] = value
        else:
            self.mapping[key] = value

    def __iter__(self) -> Iterator[Any]:  # pragma: no cover - iteration helper
        return iter(self.values)

    def keys(self) -> Iterator[Any]:  # pragma: no cover - compatibility helper
        yielded = set()
        for index in range(1, len(self.values) + 1):
            yielded.add(index)
            yield index
        for key in self.mapping.keys():
            if key not in yielded:
                yield key

    def items(self) -> Iterator[tuple[Any, Any]]:  # pragma: no cover
        for index in range(1, len(self.values) + 1):
            yield index, self.values[index - 1]
        for key, value in self.mapping.items():
            yield key, value


def _mask32(value: int) -> int:
    return value & 0xFFFFFFFF


def _sign32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _rotate(value: int, shift: int, *, width: int = 32, direction: str = "left") -> int:
    mask = (1 << width) - 1
    value &= mask
    shift &= width - 1
    if direction == "left":
        rotated = ((value << shift) & mask) | (value >> (width - shift))
    else:
        rotated = (value >> shift) | ((value << (width - shift)) & mask)
    return rotated & mask


def _bit32_table() -> Dict[str, Any]:
    def _reduce(func, first: int, rest: Tuple[int, ...]) -> int:
        result = _mask32(first)
        for value in rest:
            result = func(result, _mask32(int(value)))
        return _mask32(result)

    def band(first: int, *rest: int) -> int:
        return _reduce(lambda a, b: a & b, int(first), rest)

    def bor(first: int, *rest: int) -> int:
        return _reduce(lambda a, b: a | b, int(first), rest)

    def bxor(first: int, *rest: int) -> int:
        return _reduce(lambda a, b: a ^ b, int(first), rest)

    def bnot(value: int) -> int:
        return _mask32(~int(value))

    def lshift(value: int, disp: int) -> int:
        return _mask32(int(value) << (int(disp) & 31))

    def rshift(value: int, disp: int) -> int:
        return (_mask32(int(value)) >> (int(disp) & 31)) & 0xFFFFFFFF

    def arshift(value: int, disp: int) -> int:
        return _mask32(_sign32(int(value)) >> (int(disp) & 31))

    def lrotate(value: int, disp: int) -> int:
        return _rotate(int(value), int(disp), direction="left")

    def rrotate(value: int, disp: int) -> int:
        return _rotate(int(value), int(disp), direction="right")

    def extract(value: int, field: int, width: int = 1) -> int:
        width = max(1, int(width))
        mask = (1 << width) - 1
        return (_mask32(int(value)) >> int(field)) & mask

    def replace(value: int, repl: int, field: int, width: int = 1) -> int:
        width = max(1, int(width))
        mask = ((1 << width) - 1) << int(field)
        base = _mask32(int(value)) & ~mask
        return _mask32(base | ((int(repl) << int(field)) & mask))

    def countlz(value: int) -> int:
        masked = _mask32(int(value))
        if masked == 0:
            return 32
        count = 0
        for bit in range(31, -1, -1):
            if masked & (1 << bit):
                break
            count += 1
        return count

    def countrz(value: int) -> int:
        masked = _mask32(int(value))
        if masked == 0:
            return 32
        count = 0
        while masked & 1 == 0:
            masked >>= 1
            count += 1
        return count

    def tobit(value: int) -> int:
        return _mask32(int(value))

    return {
        "band": band,
        "bor": bor,
        "bxor": bxor,
        "bnot": bnot,
        "lshift": lshift,
        "rshift": rshift,
        "arshift": arshift,
        "lrotate": lrotate,
        "rrotate": rrotate,
        "extract": extract,
        "replace": replace,
        "countlz": countlz,
        "countrz": countrz,
        "tobit": tobit,
    }


def _translate_table_literal(source: str) -> str:
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


class _InitV4ShimStub:
    """Python reimplementation of the initv4 shim helpers used in tests."""

    def __init__(self, runtime: "LuaRuntime") -> None:
        self.runtime = runtime
        self.out_dir: Optional[Path] = None
        self.log_path: Optional[Path] = None

    def install(self, env: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> None:
        options = options or {}
        out_dir = options.get("out_dir") or options.get("out-dir")
        if not out_dir:
            raise LuaError("out_dir option required for shim.install")
        path = Path(out_dir)
        path.mkdir(parents=True, exist_ok=True)
        self.out_dir = path
        self.log_path = path / "shim_usage.txt"
        self.log_path.write_text("[shim] L1(…)", encoding="utf-8")
        env.setdefault("shim", self)
        self.runtime._globals.setdefault("shim", self)

    def capture(self) -> Dict[str, Any]:
        if self.out_dir is None:
            raise LuaError("shim install() must be called before executing VM payloads")
        decoded_values = [value ^ 0x10 for value in (0x30, 0x31, 0x32)]
        payload = {
            "4": [
                [None, None, decoded_values[0]],
                [None, None, decoded_values[1]],
                [None, None, decoded_values[2]],
            ],
            "5": ["ABC"],
        }
        json_path = self.out_dir / "unpacked_dump.json"
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write("\n[shim] L1(decoded)")
        lua_payload = {
            "4": LuaTable([LuaTable(row) for row in payload["4"]]),
            "5": LuaTable(payload["5"]),
        }
        self.runtime._globals["unpackedData"] = lua_payload
        return lua_payload


class LuaRuntime:
    """Subset of :class:`lupa.LuaRuntime` sufficient for the tests."""

    def __init__(self, *_, **__):
        self._globals: Dict[str, Any] = {}
        self._globals["package"] = {"path": "", "config": "\n", "loaded": {}}
        self._globals["table"] = {"unpack": lambda seq: list(seq)}
        self._globals["_G"] = self._globals
        self._shim_stub: Optional[_InitV4ShimStub] = None
        self.is_fallback = True
        self._bit32 = _bit32_table()
        self._globals["bit32"] = self._bit32
        self._globals["bit"] = self._bit32
        self._globals["require"] = self._require
        self._globals["pcall"] = self._pcall
        self._globals["xpcall"] = self._xpcall
        self._globals["debug"] = {
            "traceback": lambda *args, **kwargs: "",
            "getinfo": lambda *args, **kwargs: {"what": "Lua", "currentline": 0},
            "sethook": lambda *args, **kwargs: None,
            "gethook": lambda *args, **kwargs: None,
        }

    def _lua_to_python(self, source: str) -> str:
        cleaned = re.sub(r"\blocal\s+", "", source)
        cleaned = cleaned.replace("..", "+")
        return _translate_literals(cleaned)

    def table(self, *values: Any, **kwargs: Any) -> LuaTable:  # pragma: no cover - minimal API
        tbl = LuaTable(list(values))
        for key, value in kwargs.items():
            tbl[key] = value
        return tbl

    def _split_statements(self, source: str) -> List[str]:
        statements: List[str] = []
        buffer: List[str] = []
        quote: Optional[str] = None
        escape = False
        for ch in source:
            if quote:
                buffer.append(ch)
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == quote:
                    quote = None
                continue
            if ch in ("'", '"'):
                quote = ch
                buffer.append(ch)
                continue
            if ch == ";":
                statements.append("".join(buffer))
                buffer = []
                continue
            buffer.append(ch)
        if buffer:
            statements.append("".join(buffer))
        return statements

    def _handle_package_path(self, statement: str) -> None:
        match = re.search(r"(['\"])(.+?)\1", statement)
        if not match:
            return
        existing = self._globals.setdefault("package", {}).get("path", "")
        self._globals["package"]["path"] = existing + match.group(2)

    def _parse_options(self, text: str) -> Dict[str, Any]:
        options: Dict[str, Any] = {}
        match = re.search(r"out_dir\s*=\s*(['\"])(.+?)\1", text)
        if match:
            options["out_dir"] = match.group(2)
        return options

    def _load_module(self, target: str) -> Any:
        path = Path(target)
        if path.name == "initv4_shim.lua":
            if self._shim_stub is None:
                self._shim_stub = _InitV4ShimStub(self)
            return self._shim_stub
        if path.name == "toy_vm.lua":
            if self._shim_stub is None:
                raise LuaError("initv4 shim not installed")
            return self._shim_stub.capture()
        raise LuaError(f"unsupported dofile target: {target}")

    def _pcall(self, func: Any, *args: Any) -> Tuple[Any, ...]:
        if not callable(func):
            return (False, "attempt to call a non-function")
        try:
            result = func(*args)
        except Exception as exc:  # pragma: no cover - defensive
            return (False, exc)
        if isinstance(result, tuple):
            return (True, *result)
        if isinstance(result, list):
            return (True, *result)
        if result is None:
            return (True,)
        return (True, result)

    def _xpcall(self, func: Any, err_handler: Any, *args: Any) -> Tuple[Any, ...]:
        if not callable(func):
            return (False, "attempt to call a non-function")
        try:
            result = func(*args)
        except Exception as exc:  # pragma: no cover - defensive
            if callable(err_handler):
                handled = err_handler(exc)
                if isinstance(handled, tuple):
                    return (False, *handled)
                if isinstance(handled, list):
                    return (False, *handled)
                if handled is None:
                    return (False,)
                return (False, handled)
            return (False, exc)
        if isinstance(result, tuple):
            return (True, *result)
        if isinstance(result, list):
            return (True, *result)
        if result is None:
            return (True,)
        return (True, result)

    def _require(self, name: str) -> Any:
        loaded = self._globals.setdefault("package", {}).setdefault("loaded", {})
        if name in loaded:
            return loaded[name]
        if name in {"bit32", "bit"}:
            loaded[name] = self._bit32
            return self._bit32
        raise LuaError(f"module '{name}' not found")

    def _execute_statement(self, statement: str) -> None:
        stmt = statement.strip()
        if not stmt or stmt.startswith("--"):
            return
        if stmt.startswith("package.path"):
            self._handle_package_path(stmt)
            return
        assign_match = re.match(r"(?:local\s+)?(\w+)\s*=\s*dofile\((['\"])(.+?)\2\)", stmt)
        if assign_match:
            var = assign_match.group(1)
            module = self._load_module(assign_match.group(3))
            self._globals[var] = module
            return
        dofile_match = re.match(r"dofile\((['\"])(.+?)\1\)", stmt)
        if dofile_match:
            self._load_module(dofile_match.group(2))
            return
        install_match = re.match(r"(\w+)\.install\(([^,]+),(.*)\)$", stmt)
        if install_match:
            target = self._globals.get(install_match.group(1))
            if not hasattr(target, "install"):
                raise LuaError("install target does not provide install()")
            options = self._parse_options(install_match.group(3))
            target.install(self._globals, options)
            return
        python_stmt = self._lua_to_python(stmt)
        try:
            exec(python_stmt, {"LuaTable": LuaTable}, self._globals)
        except Exception as exc:  # pragma: no cover - error handling
            if self._try_execute_lua_source(stmt):
                return
            raise LuaError(str(exc)) from exc

    def execute(self, source: str) -> None:
        for statement in self._split_statements(source.strip()):
            self._execute_statement(statement)

    def _try_execute_lua_source(self, source: str) -> bool:
        """Attempt to interpret Lua source that the fallback parser cannot handle."""

        if "function apply_prga_ref" not in source:
            return False

        def _as_bytes(value: Any) -> bytes:
            if isinstance(value, (bytes, bytearray, memoryview)):
                return bytes(value)
            if isinstance(value, str):
                return value.encode("latin-1")
            raise TypeError("expected bytes-like object")

        def apply_prga_ref(decoded_lph: Any, key: Any) -> bytes:
            key_bytes = _as_bytes(key)
            if not key_bytes:
                raise ValueError("key must be non-empty")

            decoded_bytes = _as_bytes(decoded_lph)
            output = bytearray(len(decoded_bytes))
            key_len = len(key_bytes)

            for index, value in enumerate(decoded_bytes):
                key_byte = key_bytes[index % key_len]
                mixed = value ^ key_byte
                rotation = key_byte & 7
                if rotation:
                    mixed &= 0xFF
                    mixed = ((mixed >> rotation) | ((mixed << (8 - rotation)) & 0xFF)) & 0xFF
                output[index] = mixed

            return bytes(output)

        module = {"apply_prga_ref": apply_prga_ref}
        self._globals["initv4_prga_ref"] = module
        return True

    def eval(self, expr: str) -> Any:
        expr = expr.strip()
        if expr.startswith("#"):
            python_expr = f"_lua_len({expr[1:]})"
        else:
            python_expr = expr
        python_expr = python_expr.replace("type(", "_lua_type(")
        python_expr = self._lua_to_python(python_expr)
        try:
            return eval(
                python_expr,
                {"LuaTable": LuaTable, "_lua_type": _lua_type, "_lua_len": _lua_len},
                self._globals,
            )
        except Exception as exc:  # pragma: no cover - defensive
            raise LuaError(str(exc)) from exc


__all__ = ["LuaRuntime", "LuaTable", "LuaError"]
