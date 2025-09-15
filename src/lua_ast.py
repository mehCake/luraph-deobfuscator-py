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


@dataclass
class Name(Expr):
    ident: str


@dataclass
class BinOp(Expr):
    left: Expr
    op: str
    right: Expr


@dataclass
class Call(Expr):
    func: Expr
    args: List[Expr]


class Stmt:
    """Base class for statements."""


@dataclass
class LocalAssign(Stmt):
    targets: List[str]
    values: List[Expr]


@dataclass
class Assign(Stmt):
    targets: List[Expr]
    values: List[Expr]


@dataclass
class CallStmt(Stmt):
    call: Call


@dataclass
class Return(Stmt):
    values: List[Expr] = field(default_factory=list)


@dataclass
class If(Stmt):
    test: Expr
    body: List[Stmt]
    orelse: List[Stmt] = field(default_factory=list)


@dataclass
class While(Stmt):
    test: Expr
    body: List[Stmt]


@dataclass
class ForNumeric(Stmt):
    var: str
    start: Expr
    stop: Expr
    step: Expr
    body: List[Stmt]


@dataclass
class Chunk:
    body: List[Stmt] = field(default_factory=list)


def _render_expr(expr: Expr) -> str:
    if isinstance(expr, Number):
        return str(expr.value)
    if isinstance(expr, String):
        return repr(expr.value)
    if isinstance(expr, Name):
        return expr.ident
    if isinstance(expr, BinOp):
        return f"{_render_expr(expr.left)} {expr.op} {_render_expr(expr.right)}"
    if isinstance(expr, Call):
        args = ", ".join(_render_expr(arg) for arg in expr.args)
        return f"{_render_expr(expr.func)}({args})"
    raise TypeError(f"Unsupported expression: {expr!r}")


def _render_stmt(stmt: Stmt, indent: int = 0) -> str:
    pad = " " * indent
    if isinstance(stmt, LocalAssign):
        targets = ", ".join(stmt.targets)
        values = ", ".join(_render_expr(expr) for expr in stmt.values)
        return f"{pad}local {targets} = {values}"
    if isinstance(stmt, Assign):
        targets = ", ".join(_render_expr(expr) for expr in stmt.targets)
        values = ", ".join(_render_expr(expr) for expr in stmt.values)
        return f"{pad}{targets} = {values}"
    if isinstance(stmt, CallStmt):
        return f"{pad}{_render_expr(stmt.call)}"
    if isinstance(stmt, Return):
        if not stmt.values:
            return f"{pad}return"
        values = ", ".join(_render_expr(expr) for expr in stmt.values)
        return f"{pad}return {values}"
    if isinstance(stmt, If):
        header = f"{pad}if {_render_expr(stmt.test)} then"
        body = [ _render_stmt(s, indent + 4) for s in stmt.body ]
        orelse = [ _render_stmt(s, indent + 4) for s in stmt.orelse ]
        result = [header, *body]
        if orelse:
            result.append(f"{pad}else")
            result.extend(orelse)
        result.append(f"{pad}end")
        return "\n".join(result)
    if isinstance(stmt, While):
        header = f"{pad}while {_render_expr(stmt.test)} do"
        body = [ _render_stmt(s, indent + 4) for s in stmt.body ]
        return "\n".join([header, *body, f"{pad}end"])
    if isinstance(stmt, ForNumeric):
        header = (
            f"{pad}for {stmt.var} = {_render_expr(stmt.start)}, "
            f"{_render_expr(stmt.stop)}, {_render_expr(stmt.step)} do"
        )
        body = [ _render_stmt(s, indent + 4) for s in stmt.body ]
        return "\n".join([header, *body, f"{pad}end"])
    raise TypeError(f"Unsupported statement: {stmt!r}")


def render_chunk(chunk: Chunk) -> str:
    return "\n".join(_render_stmt(stmt) for stmt in chunk.body)


__all__ = [
    "Expr",
    "Number",
    "String",
    "Name",
    "BinOp",
    "Call",
    "Stmt",
    "LocalAssign",
    "Assign",
    "CallStmt",
    "Return",
    "If",
    "While",
    "ForNumeric",
    "Chunk",
    "render_chunk",
]
