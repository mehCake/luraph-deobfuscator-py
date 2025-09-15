from __future__ import annotations

from dataclasses import dataclass
from typing import Union


class SymbolicExpression:
    """Base class for all symbolic expressions."""

    def simplify(self) -> "SymbolicExpression":
        return self

    def __str__(self) -> str:
        raise NotImplementedError


@dataclass
class SymbolicValue(SymbolicExpression):
    value: Union[int, str]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.value}"


@dataclass
class SymbolicAdd(SymbolicExpression):
    left: SymbolicExpression
    right: SymbolicExpression

    def simplify(self) -> SymbolicExpression:
        left_s = self.left.simplify()
        right_s = self.right.simplify()
        if isinstance(left_s, SymbolicValue) and isinstance(right_s, SymbolicValue):
            try:
                return SymbolicValue(left_s.value + right_s.value)  # type: ignore[operator]
            except Exception:
                pass
        if left_s is not self.left or right_s is not self.right:
            return SymbolicAdd(left_s, right_s)
        return self

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"({self.left} + {self.right})"


@dataclass
class SymbolicXor(SymbolicExpression):
    left: SymbolicExpression
    right: SymbolicExpression

    def simplify(self) -> SymbolicExpression:
        left_s = self.left.simplify()
        right_s = self.right.simplify()
        if str(left_s) == str(right_s):
            return SymbolicValue(0)
        if isinstance(left_s, SymbolicValue) and isinstance(right_s, SymbolicValue):
            try:
                return SymbolicValue(left_s.value ^ right_s.value)  # type: ignore[operator]
            except Exception:
                pass
        if left_s is not self.left or right_s is not self.right:
            return SymbolicXor(left_s, right_s)
        return self

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"({self.left} ^ {self.right})"


__all__ = [
    "SymbolicExpression",
    "SymbolicValue",
    "SymbolicAdd",
    "SymbolicXor",
]
