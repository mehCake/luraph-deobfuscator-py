"""Safe evaluation helpers for simple Lua-like expressions."""
from __future__ import annotations

import ast
import math as _math
from typing import Any, Dict

__all__ = ["eval_expr"]


class _StringLib:
    __slots__ = ()

    @staticmethod
    def char(*values: Any) -> str:
        """Return a byte string from the provided numeric code points."""

        output = bytearray()
        for value in values:
            if isinstance(value, str):
                if len(value) != 1:
                    raise ValueError("string.char expects single character strings")
                output.append(ord(value))
                continue

            if isinstance(value, (float, bool)):
                value = int(value)
            elif not isinstance(value, int):
                raise TypeError(f"unsupported value for string.char: {type(value)!r}")

            output.append(int(value) & 0xFF)
        return output.decode("latin-1")


class _MathLib:
    __slots__ = ()

    _ALLOWED: Dict[str, Any] = {
        name: getattr(_math, name)
        for name in dir(_math)
        if not name.startswith("_")
    }
    _ALLOWED.update({
        "abs": abs,
        "max": max,
        "min": min,
        "pow": pow,
        "huge": _math.inf,
    })

    def __getattr__(self, name: str) -> Any:  # pragma: no cover - accessor
        try:
            return self._ALLOWED[name]
        except KeyError as exc:  # pragma: no cover - error path
            raise AttributeError(name) from exc


class _Bit32Lib:
    __slots__ = ()

    @staticmethod
    def _to_32bit(value: int) -> int:
        return value & 0xFFFFFFFF

    @classmethod
    def _binary(cls, func, *values: int) -> int:
        if not values:
            raise ValueError("bit32 operations expect at least one argument")
        result = cls._to_32bit(int(values[0]))
        for val in values[1:]:
            result = cls._to_32bit(func(result, int(val)))
        return result

    @classmethod
    def band(cls, *values: int) -> int:
        return cls._binary(lambda a, b: a & b, *values)

    @classmethod
    def bor(cls, *values: int) -> int:
        return cls._binary(lambda a, b: a | b, *values)

    @classmethod
    def bxor(cls, *values: int) -> int:
        return cls._binary(lambda a, b: a ^ b, *values)

    @classmethod
    def bnot(cls, value: int) -> int:
        return cls._to_32bit(~int(value))

    @classmethod
    def lshift(cls, value: int, shift: int) -> int:
        return cls._to_32bit(int(value) << int(shift))

    @classmethod
    def rshift(cls, value: int, shift: int) -> int:
        return cls._to_32bit(int(value) >> int(shift))

    @classmethod
    def arshift(cls, value: int, shift: int) -> int:
        value = cls._to_32bit(int(value))
        shift = max(0, min(int(shift), 31))
        if value & 0x80000000:
            return cls._to_32bit((value >> shift) | (0xFFFFFFFF << (32 - shift)))
        return cls._to_32bit(value >> shift)

    @classmethod
    def extract(cls, value: int, field: int, width: int = 1) -> int:
        value = cls._to_32bit(int(value))
        field = int(field)
        width = max(0, int(width))
        if width == 0:
            return 0
        if width > 32:
            raise ValueError("width cannot exceed 32 bits")
        mask = ((1 << width) - 1) << field
        return (value & mask) >> field

    @classmethod
    def replace(cls, value: int, repl: int, field: int, width: int = 1) -> int:
        value = cls._to_32bit(int(value))
        field = int(field)
        width = max(0, int(width))
        if width > 32:
            raise ValueError("width cannot exceed 32 bits")
        repl = cls._to_32bit(int(repl)) & ((1 << width) - 1 if width else 0)
        if width == 0:
            return value
        mask = ((1 << width) - 1) << field
        cleared = value & ~mask
        return cls._to_32bit(cleared | (repl << field))


_STRING_LIB = _StringLib()
_MATH_LIB = _MathLib()
_BIT32_LIB = _Bit32Lib()

_SAFE_GLOBALS: Dict[str, Any] = {
    "string": _STRING_LIB,
    "math": _MATH_LIB,
    "bit32": _BIT32_LIB,
}

_ALLOWED_ROOT_ATTRS = {
    "string": {"char"},
    "math": set(_MathLib._ALLOWED.keys()),
    "bit32": {
        "band",
        "bor",
        "bxor",
        "bnot",
        "lshift",
        "rshift",
        "arshift",
        "extract",
        "replace",
    },
}

_ALLOWED_NODES = (
    ast.Expression,
    ast.BoolOp,
    ast.BinOp,
    ast.UnaryOp,
    ast.Compare,
    ast.Call,
    ast.Constant,
    ast.Name,
    ast.Attribute,
    ast.Subscript,
    ast.Slice,
    ast.Tuple,
    ast.List,
    ast.Dict,
    ast.Set,
    ast.IfExp,
    ast.Load,
)

_ALLOWED_UNARY = (ast.UAdd, ast.USub, ast.Not, ast.Invert)
_ALLOWED_BINOPS = (
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.FloorDiv,
    ast.Mod,
    ast.Pow,
    ast.BitAnd,
    ast.BitOr,
    ast.BitXor,
    ast.LShift,
    ast.RShift,
)
_ALLOWED_BOOL = (ast.And, ast.Or)
_ALLOWED_CMP = (
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
)


class UnsafeExpressionError(ValueError):
    """Raised when the user attempts to evaluate an unsafe expression."""


def _ensure_allowed(node: ast.AST) -> None:
    if not isinstance(node, _ALLOWED_NODES):
        raise UnsafeExpressionError(f"unsupported syntax: {type(node).__name__}")

    if isinstance(node, ast.UnaryOp) and not isinstance(node.op, _ALLOWED_UNARY):
        raise UnsafeExpressionError(f"unsupported unary operator: {type(node.op).__name__}")

    if isinstance(node, ast.BinOp) and not isinstance(node.op, _ALLOWED_BINOPS):
        raise UnsafeExpressionError(f"unsupported binary operator: {type(node.op).__name__}")

    if isinstance(node, ast.BoolOp) and not isinstance(node.op, _ALLOWED_BOOL):
        raise UnsafeExpressionError(f"unsupported boolean operator: {type(node.op).__name__}")

    if isinstance(node, ast.Compare):
        for op in node.ops:
            if not isinstance(op, _ALLOWED_CMP):
                raise UnsafeExpressionError(f"unsupported comparison: {type(op).__name__}")

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id not in _SAFE_GLOBALS:
                raise UnsafeExpressionError(f"call to unsupported function: {node.func.id}")
        elif isinstance(node.func, ast.Attribute):
            _validate_attribute(node.func)
        else:
            raise UnsafeExpressionError("call must target a name or attribute")

        for keyword in node.keywords:
            if keyword.arg is None:
                raise UnsafeExpressionError("keyword splatting is not allowed")

    if isinstance(node, ast.Name):
        if node.id not in _SAFE_GLOBALS:
            raise UnsafeExpressionError(f"use of unknown identifier: {node.id}")

    if isinstance(node, ast.Attribute):
        _validate_attribute(node)

    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id not in _SAFE_GLOBALS:
            raise UnsafeExpressionError(f"subscript on unsupported object: {node.value.id}")

    if isinstance(node, ast.Dict):
        for key in node.keys:
            if key is None:
                raise UnsafeExpressionError("dictionary unpacking is not permitted")


def _validate_attribute(node: ast.Attribute) -> None:
    value = node.value
    if not isinstance(value, ast.Name):
        raise UnsafeExpressionError("attribute access must originate from a module name")

    root = value.id
    allowed = _ALLOWED_ROOT_ATTRS.get(root)
    if not allowed or node.attr not in allowed:
        raise UnsafeExpressionError(f"attribute '{root}.{node.attr}' is not allowed")


def _visit(node: ast.AST) -> None:
    _ensure_allowed(node)
    for child in ast.iter_child_nodes(node):
        _visit(child)


def eval_expr(expr: str) -> Any:
    """Evaluate *expr* using a heavily sandboxed environment."""

    if not isinstance(expr, str):
        raise TypeError("expression must be a string")

    parsed = ast.parse(expr, mode="eval")
    _visit(parsed)
    compiled = compile(parsed, filename="<safe-eval>", mode="eval")
    return eval(compiled, {"__builtins__": {}}, _SAFE_GLOBALS.copy())
