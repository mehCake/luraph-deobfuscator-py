"""Lightweight Lua AST nodes and pretty-printer utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Sequence


# ---------------------------------------------------------------------------
# Expression nodes


class Expr:
    """Base class for all Lua expression nodes."""


@dataclass(slots=True)
class Literal(Expr):
    value: object
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        if self.value is None:
            return "nil"
        if isinstance(self.value, bool):
            return "true" if self.value else "false"
        if isinstance(self.value, str):
            return repr(self.value)
        return str(self.value)


@dataclass(slots=True)
class Name(Expr):
    ident: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        return self.ident


@dataclass(slots=True)
class BinOp(Expr):
    left: Expr
    op: str
    right: Expr
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        return f"{render_expr(self.left)} {self.op} {render_expr(self.right)}"


@dataclass(slots=True)
class UnOp(Expr):
    op: str
    operand: Expr
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        operand = render_expr(self.operand)
        if self.op == "not":
            return f"not {operand}"
        return f"{self.op}{operand}"


@dataclass(slots=True)
class Call(Expr):
    func: Expr
    args: List[Expr] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        args = ", ".join(render_expr(arg) for arg in self.args)
        return f"{render_expr(self.func)}({args})"


@dataclass(slots=True)
class TableAccess(Expr):
    table: Expr
    key: Expr
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        return f"{render_expr(self.table)}[{render_expr(self.key)}]"


@dataclass(slots=True)
class TableConstructor(Expr):
    fields: List[tuple[Expr | None, Expr]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        if not self.fields:
            return "{}"
        parts: List[str] = []
        for key, value in self.fields:
            if key is None:
                parts.append(render_expr(value))
            else:
                parts.append(f"[{render_expr(key)}] = {render_expr(value)}")
        return "{" + ", ".join(parts) + "}"


# ---------------------------------------------------------------------------
# Statement nodes


class Stmt:
    """Base class for Lua statements."""


@dataclass(slots=True)
class Assignment(Stmt):
    targets: List[Expr]
    values: List[Expr]
    is_local: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CallStmt(Stmt):
    call: Call
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Return(Stmt):
    values: List[Expr] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class If(Stmt):
    test: Expr
    body: List[Stmt] = field(default_factory=list)
    orelse: List[Stmt] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class While(Stmt):
    test: Expr
    body: List[Stmt]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NumericFor(Stmt):
    var: str
    start: Expr
    stop: Expr
    step: Expr
    body: List[Stmt]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GenericFor(Stmt):
    vars: List[str]
    iterables: List[Expr]
    body: List[Stmt]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DoBlock(Stmt):
    body: List[Stmt] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class FunctionDef(Stmt):
    name: Expr | None
    params: List[str]
    body: List[Stmt]
    is_local: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Chunk:
    body: List[Stmt] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pretty printer helpers


def render_expr(expr: Expr) -> str:
    if isinstance(expr, Literal):
        return expr.render()
    if isinstance(expr, Name):
        return expr.render()
    if isinstance(expr, BinOp):
        return expr.render()
    if isinstance(expr, UnOp):
        return expr.render()
    if isinstance(expr, Call):
        return expr.render()
    if isinstance(expr, TableAccess):
        return expr.render()
    if isinstance(expr, TableConstructor):
        return expr.render()
    raise TypeError(f"Unsupported expression: {expr!r}")


def _render_block(statements: Sequence[Stmt], indent: str, level: int) -> List[str]:
    lines: List[str] = []
    pad = indent * level
    for stmt in statements:
        if isinstance(stmt, Assignment):
            prefix = "local " if stmt.is_local else ""
            targets = ", ".join(render_expr(expr) for expr in stmt.targets)
            values = ", ".join(render_expr(expr) for expr in stmt.values)
            lines.append(f"{pad}{prefix}{targets} = {values}")
        elif isinstance(stmt, CallStmt):
            lines.append(f"{pad}{render_expr(stmt.call)}")
        elif isinstance(stmt, Return):
            if stmt.values:
                rendered = ", ".join(render_expr(expr) for expr in stmt.values)
                lines.append(f"{pad}return {rendered}")
            else:
                lines.append(f"{pad}return")
        elif isinstance(stmt, If):
            header = f"{pad}if {render_expr(stmt.test)} then"
            body_lines = _render_block(stmt.body, indent, level + 1)
            lines.append(header)
            lines.extend(body_lines)
            if stmt.orelse:
                lines.append(f"{pad}else")
                lines.extend(_render_block(stmt.orelse, indent, level + 1))
            lines.append(f"{pad}end")
        elif isinstance(stmt, While):
            lines.append(f"{pad}while {render_expr(stmt.test)} do")
            lines.extend(_render_block(stmt.body, indent, level + 1))
            lines.append(f"{pad}end")
        elif isinstance(stmt, NumericFor):
            header = (
                f"{pad}for {stmt.var} = {render_expr(stmt.start)}, "
                f"{render_expr(stmt.stop)}, {render_expr(stmt.step)} do"
            )
            lines.append(header)
            lines.extend(_render_block(stmt.body, indent, level + 1))
            lines.append(f"{pad}end")
        elif isinstance(stmt, GenericFor):
            header = (
                f"{pad}for {', '.join(stmt.vars)} in "
                f"{', '.join(render_expr(expr) for expr in stmt.iterables)} do"
            )
            lines.append(header)
            lines.extend(_render_block(stmt.body, indent, level + 1))
            lines.append(f"{pad}end")
        elif isinstance(stmt, DoBlock):
            lines.append(f"{pad}do")
            lines.extend(_render_block(stmt.body, indent, level + 1))
            lines.append(f"{pad}end")
        elif isinstance(stmt, FunctionDef):
            name = render_expr(stmt.name) if stmt.name is not None else ""
            params = ", ".join(stmt.params)
            prefix = "local " if stmt.is_local else ""
            header = f"{pad}{prefix}function {name}({params})"
            lines.append(header)
            lines.extend(_render_block(stmt.body, indent, level + 1))
            lines.append(f"{pad}end")
        else:
            raise TypeError(f"Unsupported statement: {stmt!r}")
    return lines


def to_source(chunk: Chunk, *, indent: str = "    ") -> str:
    """Render *chunk* into pretty-printed Lua source."""

    lines = _render_block(chunk.body, indent, 0)
    return "\n".join(lines)


__all__ = [
    "Assignment",
    "BinOp",
    "Call",
    "CallStmt",
    "Chunk",
    "Expr",
    "FunctionDef",
    "If",
    "Literal",
    "Name",
    "NumericFor",
    "GenericFor",
    "DoBlock",
    "Return",
    "Stmt",
    "TableAccess",
    "TableConstructor",
    "While",
    "render_expr",
    "to_source",
]

