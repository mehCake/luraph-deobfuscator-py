from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class Expr:
    """Base class for expressions."""


@dataclass
class Number(Expr):
    value: int


@dataclass
class String(Expr):
    value: str


class Stmt:
    """Base class for statements."""


@dataclass
class Assign(Stmt):
    target: str
    value: Expr


@dataclass
class Return(Stmt):
    value: Optional[Expr] = None


@dataclass
class Chunk:
    body: List[Stmt] = field(default_factory=list)


__all__ = [
    "Expr",
    "Number",
    "String",
    "Stmt",
    "Assign",
    "Return",
    "Chunk",
]
