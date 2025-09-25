from __future__ import annotations

"""AST-based variable renaming for devirtualized Lua chunks."""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple, Set

from ..utils_pkg import ast as lua_ast


# Reserved identifiers that must never be used as replacement names.
_RESERVED_WORDS: Set[str] = {
    "and",
    "break",
    "do",
    "else",
    "elseif",
    "end",
    "false",
    "for",
    "function",
    "if",
    "in",
    "local",
    "nil",
    "not",
    "or",
    "repeat",
    "return",
    "then",
    "true",
    "until",
    "while",
    # Common globals
    "_G",
    "assert",
    "error",
    "getmetatable",
    "ipairs",
    "load",
    "loadstring",
    "next",
    "pairs",
    "pcall",
    "print",
    "rawequal",
    "rawget",
    "rawset",
    "require",
    "select",
    "setmetatable",
    "tonumber",
    "tostring",
    "type",
}

_CANDIDATE_RE = re.compile(r"^(?:R|T|UPVAL)\d+$")
_REGISTER_RE = re.compile(r"^(?:R|T)(\d+)$")
_UPVAL_RE = re.compile(r"^UPVAL(\d+)$")
_SORT_RE = re.compile(r"^([A-Z]+)(\d+)$")


def _register_name(index: int) -> str:
    """Convert ``index`` into a base-26 alphabetical identifier."""

    chars: List[str] = []
    current = index
    while True:
        chars.append(chr(ord("a") + (current % 26)))
        current //= 26
        if current == 0:
            break
        current -= 1
    return "".join(reversed(chars))


def _candidate_sort_key(name: str) -> Tuple[int, int, str]:
    match = _SORT_RE.match(name)
    if match:
        prefix, number = match.groups()
        prefix_order = {"UPVAL": 0, "R": 1, "T": 2}.get(prefix, 3)
        return (prefix_order, int(number), "")
    return (4, 0, name)


@dataclass
class ScopeState:
    """Book-keeping for a lexical scope."""

    parent: ScopeState | None = None
    path: Tuple[int, ...] = ()
    used: Set[str] = field(default_factory=set)
    bindings: Dict[str, str] = field(default_factory=dict)
    register_candidates: Set[str] = field(default_factory=set)
    upvalue_candidates: Set[str] = field(default_factory=set)
    candidate_rank: Dict[str, int] = field(default_factory=dict)
    next_dynamic_index: int = 0
    upvalue_index: int = 0
    child_index: int = 0

    def child(self) -> "ScopeState":
        return ScopeState(parent=self, path=self.path + (self.child_index,))

    def reserve(self, name: str) -> None:
        if name and name not in _RESERVED_WORDS:
            self.used.add(name)

    def remember(self, original: str, alias: str) -> None:
        self.bindings[original] = alias
        self.used.add(alias)

    def lookup(self, name: str) -> Optional[str]:
        state: Optional[ScopeState] = self
        while state is not None:
            alias = state.bindings.get(name)
            if alias is not None:
                return alias
            state = state.parent
        return None

    def is_taken(self, alias: str) -> bool:
        return alias in _RESERVED_WORDS or alias in self.used

    def finalise(self) -> None:
        ordered = sorted(self.register_candidates, key=_candidate_sort_key)
        self.candidate_rank = {name: idx for idx, name in enumerate(ordered)}
        self.next_dynamic_index = len(self.candidate_rank)


class ASTVariableRenamer:
    """Rename pseudo registers within a :class:`lua_ast.Chunk`."""

    def __init__(self) -> None:
        self._scope_map: Dict[Tuple[int, str], ScopeState] = {}
        self._scope_for_func: Dict[int, ScopeState] = {}
        self._replacements = 0
        self._mapping: List[Dict[str, object]] = []

    def rename_chunk(self, chunk: lua_ast.Chunk) -> Dict[str, object]:
        root = ScopeState()
        self._seed_scope(chunk.body, root)
        self._rename_block(chunk.body, root)
        return {
            "replacements": self._replacements,
            "mapping": self._mapping,
        }

    # ------------------------------------------------------------------
    # Seeding phase – discover identifiers and scope structure

    def _seed_scope(self, block: Sequence[lua_ast.Stmt], scope: ScopeState) -> None:
        for stmt in block:
            self._seed_stmt(stmt, scope)
        scope.finalise()

    def _seed_stmt(self, stmt: lua_ast.Stmt, scope: ScopeState) -> None:
        if isinstance(stmt, lua_ast.Assignment):
            for expr in stmt.targets:
                self._seed_expr(expr, scope)
            for expr in stmt.values:
                self._seed_expr(expr, scope)
        elif isinstance(stmt, lua_ast.CallStmt):
            self._seed_expr(stmt.call, scope)
        elif isinstance(stmt, lua_ast.Return):
            for expr in stmt.values:
                self._seed_expr(expr, scope)
        elif isinstance(stmt, lua_ast.If):
            self._seed_expr(stmt.test, scope)
            body_scope = scope.child()
            self._scope_map[(id(stmt), "body")] = body_scope
            self._seed_scope(stmt.body, body_scope)
            if stmt.orelse:
                else_scope = scope.child()
                self._scope_map[(id(stmt), "orelse")] = else_scope
                self._seed_scope(stmt.orelse, else_scope)
        elif isinstance(stmt, lua_ast.While):
            self._seed_expr(stmt.test, scope)
            body_scope = scope.child()
            self._scope_map[(id(stmt), "body")] = body_scope
            self._seed_scope(stmt.body, body_scope)
        elif isinstance(stmt, lua_ast.NumericFor):
            if _CANDIDATE_RE.fullmatch(stmt.var):
                scope.register_candidates.add(stmt.var)
            else:
                scope.reserve(stmt.var)
            self._seed_expr(stmt.start, scope)
            self._seed_expr(stmt.stop, scope)
            self._seed_expr(stmt.step, scope)
            loop_scope = scope.child()
            if _CANDIDATE_RE.fullmatch(stmt.var):
                loop_scope.register_candidates.add(stmt.var)
            else:
                loop_scope.reserve(stmt.var)
            self._scope_map[(id(stmt), "body")] = loop_scope
            self._seed_scope(stmt.body, loop_scope)
        elif isinstance(stmt, lua_ast.GenericFor):
            loop_scope = scope.child()
            for var in stmt.vars:
                if _CANDIDATE_RE.fullmatch(var):
                    scope.register_candidates.add(var)
                    loop_scope.register_candidates.add(var)
                else:
                    scope.reserve(var)
                    loop_scope.reserve(var)
            for expr in stmt.iterables:
                self._seed_expr(expr, scope)
            self._scope_map[(id(stmt), "body")] = loop_scope
            self._seed_scope(stmt.body, loop_scope)
        elif isinstance(stmt, lua_ast.DoBlock):
            block_scope = scope.child()
            self._scope_map[(id(stmt), "body")] = block_scope
            self._seed_scope(stmt.body, block_scope)
        elif isinstance(stmt, lua_ast.FunctionDef):
            if stmt.name is not None:
                self._seed_expr(stmt.name, scope)
            func_scope = scope.child()
            self._scope_for_func[id(stmt)] = func_scope
            for param in stmt.params:
                if _CANDIDATE_RE.fullmatch(param):
                    func_scope.register_candidates.add(param)
                else:
                    func_scope.reserve(param)
            self._seed_scope(stmt.body, func_scope)
        else:  # pragma: no cover - defensive guard for new stmt types
            raise TypeError(f"Unsupported statement type: {type(stmt)!r}")

    def _seed_expr(self, expr: lua_ast.Expr, scope: ScopeState) -> None:
        if isinstance(expr, lua_ast.Name):
            self._seed_name(expr.ident, scope)
        elif isinstance(expr, lua_ast.BinOp):
            self._seed_expr(expr.left, scope)
            self._seed_expr(expr.right, scope)
        elif isinstance(expr, lua_ast.UnOp):
            self._seed_expr(expr.operand, scope)
        elif isinstance(expr, lua_ast.Call):
            self._seed_expr(expr.func, scope)
            for arg in expr.args:
                self._seed_expr(arg, scope)
        elif isinstance(expr, lua_ast.TableAccess):
            self._seed_expr(expr.table, scope)
            self._seed_expr(expr.key, scope)
        elif isinstance(expr, lua_ast.TableConstructor):
            for key, value in expr.fields:
                if key is not None:
                    self._seed_expr(key, scope)
                self._seed_expr(value, scope)
        elif isinstance(expr, lua_ast.Literal):
            return
        else:  # pragma: no cover - defensive guard for new expr types
            raise TypeError(f"Unsupported expression type: {type(expr)!r}")

    def _seed_name(self, name: str, scope: ScopeState) -> None:
        if _REGISTER_RE.match(name):
            scope.register_candidates.add(name)
        elif _UPVAL_RE.match(name):
            scope.upvalue_candidates.add(name)
        elif _CANDIDATE_RE.fullmatch(name):
            scope.register_candidates.add(name)
        else:
            scope.reserve(name)

    # ------------------------------------------------------------------
    # Renaming phase

    def _rename_block(self, block: Sequence[lua_ast.Stmt], scope: ScopeState) -> None:
        for stmt in block:
            self._rename_stmt(stmt, scope)

    def _rename_stmt(self, stmt: lua_ast.Stmt, scope: ScopeState) -> None:
        if isinstance(stmt, lua_ast.Assignment):
            for target in stmt.targets:
                self._rename_expr(target, scope)
            for value in stmt.values:
                self._rename_expr(value, scope)
        elif isinstance(stmt, lua_ast.CallStmt):
            self._rename_expr(stmt.call, scope)
        elif isinstance(stmt, lua_ast.Return):
            for expr in stmt.values:
                self._rename_expr(expr, scope)
        elif isinstance(stmt, lua_ast.If):
            self._rename_expr(stmt.test, scope)
            body_scope = self._scope_map.get((id(stmt), "body"), scope.child())
            self._rename_block(stmt.body, body_scope)
            if stmt.orelse:
                else_scope = self._scope_map.get((id(stmt), "orelse"), scope.child())
                self._rename_block(stmt.orelse, else_scope)
        elif isinstance(stmt, lua_ast.While):
            self._rename_expr(stmt.test, scope)
            body_scope = self._scope_map.get((id(stmt), "body"), scope.child())
            self._rename_block(stmt.body, body_scope)
        elif isinstance(stmt, lua_ast.NumericFor):
            body_scope = self._scope_map.get((id(stmt), "body"), scope.child())
            alias = self._alias_register(body_scope, stmt.var)
            if alias != stmt.var:
                stmt.var = alias
                self._replacements += 1
            self._rename_expr(stmt.start, scope)
            self._rename_expr(stmt.stop, scope)
            self._rename_expr(stmt.step, scope)
            self._rename_block(stmt.body, body_scope)
        elif isinstance(stmt, lua_ast.GenericFor):
            body_scope = self._scope_map.get((id(stmt), "body"), scope.child())
            for idx, var in enumerate(stmt.vars, start=1):
                alias = self._alias_register(body_scope, var)
                if alias != var:
                    stmt.vars[idx - 1] = alias
                    self._replacements += 1
            for expr in stmt.iterables:
                self._rename_expr(expr, scope)
            self._rename_block(stmt.body, body_scope)
        elif isinstance(stmt, lua_ast.DoBlock):
            block_scope = self._scope_map.get((id(stmt), "body"), scope.child())
            self._rename_block(stmt.body, block_scope)
        elif isinstance(stmt, lua_ast.FunctionDef):
            func_scope = self._scope_for_func.get(id(stmt), scope.child())
            if stmt.name is not None:
                self._rename_expr(stmt.name, scope)
            for position, param in enumerate(stmt.params, start=1):
                if _CANDIDATE_RE.fullmatch(param):
                    alias = self._alias_parameter(func_scope, param, position)
                    if alias != param:
                        stmt.params[position - 1] = alias
                        self._replacements += 1
                else:
                    func_scope.reserve(param)
            self._rename_block(stmt.body, func_scope)
        else:  # pragma: no cover - defensive guard
            raise TypeError(f"Unsupported statement type: {type(stmt)!r}")

    def _rename_expr(self, expr: lua_ast.Expr, scope: ScopeState) -> None:
        if isinstance(expr, lua_ast.Name):
            alias = scope.lookup(expr.ident)
            if alias is not None:
                if alias != expr.ident:
                    expr.ident = alias
                    self._replacements += 1
                return
            if _UPVAL_RE.match(expr.ident):
                alias = self._alias_upvalue(scope, expr.ident)
            elif _REGISTER_RE.match(expr.ident):
                alias = self._alias_register(scope, expr.ident)
            elif _CANDIDATE_RE.fullmatch(expr.ident):
                alias = self._alias_register(scope, expr.ident)
            else:
                return
            if alias != expr.ident:
                expr.ident = alias
                self._replacements += 1
        elif isinstance(expr, lua_ast.BinOp):
            self._rename_expr(expr.left, scope)
            self._rename_expr(expr.right, scope)
        elif isinstance(expr, lua_ast.UnOp):
            self._rename_expr(expr.operand, scope)
        elif isinstance(expr, lua_ast.Call):
            self._rename_expr(expr.func, scope)
            for arg in expr.args:
                self._rename_expr(arg, scope)
        elif isinstance(expr, lua_ast.TableAccess):
            self._rename_expr(expr.table, scope)
            self._rename_expr(expr.key, scope)
        elif isinstance(expr, lua_ast.TableConstructor):
            for key, value in expr.fields:
                if key is not None:
                    self._rename_expr(key, scope)
                self._rename_expr(value, scope)
        elif isinstance(expr, lua_ast.Literal):
            return
        else:  # pragma: no cover - defensive guard
            raise TypeError(f"Unsupported expression type: {type(expr)!r}")

    # ------------------------------------------------------------------
    # Alias helpers

    def _alias_register(self, scope: ScopeState, name: str) -> str:
        existing = scope.lookup(name)
        if existing is not None:
            return existing
        index = scope.candidate_rank.get(name)
        if index is None:
            index = scope.next_dynamic_index
            scope.candidate_rank[name] = index
            scope.next_dynamic_index += 1
        alias = _register_name(index)
        while scope.is_taken(alias):
            index += 1
            alias = _register_name(index)
        scope.remember(name, alias)
        self._mapping.append({"scope": scope.path, "original": name, "alias": alias})
        return alias

    def _alias_upvalue(self, scope: ScopeState, name: str) -> str:
        existing = scope.lookup(name)
        if existing is not None:
            return existing
        match = _UPVAL_RE.match(name)
        base = int(match.group(1)) + 1 if match else scope.upvalue_index + 1
        alias = f"uv{base}"
        while scope.is_taken(alias):
            base += 1
            alias = f"uv{base}"
        scope.upvalue_index = max(scope.upvalue_index, base)
        scope.remember(name, alias)
        self._mapping.append({"scope": scope.path, "original": name, "alias": alias})
        return alias

    def _alias_parameter(self, scope: ScopeState, name: str, position: int) -> str:
        existing = scope.lookup(name)
        if existing is not None:
            return existing
        base = f"arg{position}"
        alias = base
        suffix = 1
        while scope.is_taken(alias):
            alias = f"{base}_{suffix}"
            suffix += 1
        scope.remember(name, alias)
        self._mapping.append({"scope": scope.path, "original": name, "alias": alias})
        return alias


def rename_chunk(chunk: lua_ast.Chunk) -> Dict[str, object]:
    """Rename pseudo registers within *chunk* and return metadata."""

    renamer = ASTVariableRenamer()
    return renamer.rename_chunk(chunk)


__all__ = ["rename_chunk", "ASTVariableRenamer"]
