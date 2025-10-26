"""AST-driven renamer for legacy Lua helper tables.

The historic implementation relied exclusively on regular-expression
substitutions which routinely renamed identifiers that appeared in strings,
comments or property lookups.  It also lacked scope-awareness, meaning shadowed
locals would be rewritten to the same name as their outer counterparts.  The
updated module leverages :mod:`luaparser` to walk the AST, track scopes, and
apply renames only where it is semantically safe to do so.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import DefaultDict, Dict, Optional, Set

from .utils import safe_read_file, safe_write_file


def _render_with_preserved_literals(tree, indent: int = 4) -> str:
    """Render ``tree`` back to Lua while keeping raw literal spellings."""

    from luaparser import astnodes, printers  # type: ignore import-not-found

    class _PreservingVisitor(printers.LuaOutputVisitor):
        pass

    @_PreservingVisitor.visit.register
    def _(self, node: astnodes.String) -> str:  # type: ignore[misc]
        token = getattr(node, "first_token", None)
        text = getattr(token, "text", None)
        if text:
            return text
        return super(_PreservingVisitor, self).visit(node)

    _.__annotations__["node"] = astnodes.String

    printer = _PreservingVisitor(indent_size=indent)
    return printer.visit(tree)


@dataclass
class _Scope:
    """Scope frame storing local bindings for renamed identifiers."""

    parent: Optional["_Scope"]
    bindings: Dict[str, str]

    def lookup(self, name: str) -> Optional[str]:
        scope: Optional["_Scope"] = self
        while scope is not None:
            if name in scope.bindings:
                return scope.bindings[name]
            scope = scope.parent
        return None

    def get_local(self, name: str) -> Optional[str]:
        return self.bindings.get(name)

    def define(self, name: str, replacement: str) -> None:
        self.bindings.setdefault(name, replacement)


class LuaVariableRenamer:
    """Renames obfuscated identifiers using an AST-driven strategy."""

    _LOOP_HINT = "loop"
    _ARG_HINT = "arg"

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self.variable_map: DefaultDict[str, Set[str]] = defaultdict(set)
        self.function_map: DefaultDict[str, Set[str]] = defaultdict(set)
        self.lua_keywords: Set[str] = {
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
        }
        self._used_names: Set[str] = set(self.lua_keywords)
        self._base_counters: DefaultDict[str, int] = defaultdict(int)

    # -- Public API -------------------------------------------------
    def rename_variables(self, code: str) -> str:
        """Return ``code`` with obfuscated identifiers renamed safely."""

        try:
            from luaparser import ast, astnodes
        except ImportError:
            self.logger.warning("luaparser is required for AST-driven renaming")
            return code

        self.variable_map.clear()
        self.function_map.clear()
        self._used_names = set(self.lua_keywords)
        self._base_counters.clear()

        try:
            tree = ast.parse(code)
        except Exception as exc:  # pragma: no cover - parse errors rare
            self.logger.error("Failed to parse Lua source: %s", exc)
            return code

        visitor = self._RenameVisitor(self, astnodes)
        visitor.visit(tree)

        try:
            rendered = _render_with_preserved_literals(tree)
            comments: list[str] = []
            seen: Set[str] = set()
            for node in ast.walk(tree):
                node_comments = getattr(node, "comments", None)
                if not node_comments:
                    continue
                for text in node_comments:
                    text_obj = getattr(text, "s", text)
                    if text_obj is None:
                        continue
                    text_str = str(text_obj)
                    if not text_str:
                        continue
                    stripped = text_str.rstrip()
                    if stripped in seen:
                        continue
                    seen.add(stripped)
                    comments.append(stripped)
            if comments:
                rendered = "\n".join((*comments, rendered))
            return rendered
        except Exception as exc:  # pragma: no cover - fallback on formatting issues
            self.logger.error("Failed to render renamed Lua source: %s", exc)
            return code

    # -- Helper utilities -------------------------------------------
    def _make_unique(self, base: str) -> str:
        index = self._base_counters[base]
        while True:
            candidate = base if index == 0 else f"{base}_{index}"
            index += 1
            if candidate not in self._used_names and candidate not in self.lua_keywords:
                self._base_counters[base] = index
                self._used_names.add(candidate)
                return candidate

    def _allocate_function_name(self, original: str) -> str:
        new_name = self._make_unique("function")
        self.function_map[original].add(new_name)
        return new_name

    def _allocate_variable_name(self, original: str, hint: Optional[str]) -> str:
        base = self._determine_variable_base(original, hint)
        new_name = self._make_unique(base)
        self.variable_map[original].add(new_name)
        return new_name

    def _determine_variable_base(self, name: str, hint: Optional[str]) -> str:
        if hint == self._LOOP_HINT:
            return "index"
        if hint == self._ARG_HINT:
            return "arg"
        context = self._determine_variable_context(name)
        if context:
            return context
        return "var"

    def _determine_variable_context(self, var_name: str) -> Optional[str]:
        if len(var_name) == 1 and var_name in "ijk":
            return "index"
        lower = var_name.lower()
        if any(token in lower for token in ("txt", "str", "msg", "content")):
            return "text"
        if any(token in lower for token in ("num", "cnt", "val", "total", "length", "size")):
            return "value"
        if any(token in lower for token in ("is_", "has_", "flag", "enabled", "active")):
            return "flag"
        if any(token in lower for token in ("list", "array", "table", "dict", "map", "collection")):
            return "items"
        return None

    @staticmethod
    def _is_obfuscated_name(name: Optional[str]) -> bool:
        if not name:
            return False
        if len(name) == 1 and name not in {"i", "j", "k"}:
            return True
        if len(name) <= 3:
            return not name.islower()
        if any(char.isdigit() for char in name):
            return True
        if not name.islower() and not name.isupper():
            return True
        return False

    # -- AST visitor ------------------------------------------------
    class _RenameVisitor:
        def __init__(self, owner: "LuaVariableRenamer", astnodes) -> None:
            from luaparser import ast

            self._owner = owner
            self._astnodes = astnodes
            self._stack: list[object] = []
            self._scopes: list[_Scope] = []
            self._skip_blocks: Set[int] = set()

        # Public entry point ---------------------------------------
        def visit(self, node):  # type: ignore[override]
            method = getattr(self, f"visit_{type(node).__name__}", None)
            if method:
                return method(node)
            return self._generic_visit(node)

        def _generic_visit(self, node):
            if isinstance(node, list):
                for child in node:
                    self.visit(child)
                return node
            if node is None:
                return node
            self._stack.append(node)
            try:
                for child in self._iter_child_nodes(node):
                    self.visit(child)
            finally:
                self._stack.pop()
            return node

        def _iter_child_nodes(self, node):
            if isinstance(node, list):
                for child in node:
                    yield from self._iter_child_nodes(child)
                return
            astnodes = self._astnodes
            node_cls = getattr(astnodes, "Node", None)
            if node_cls is not None and isinstance(node, node_cls):
                for key, value in vars(node).items():
                    if key.startswith("_"):
                        continue
                    yield from self._coerce_children(value)

        def _coerce_children(self, value):
            astnodes = self._astnodes
            node_cls = getattr(astnodes, "Node", None)
            if node_cls is not None and isinstance(value, node_cls):
                yield value
            elif isinstance(value, (list, tuple)):
                for item in value:
                    yield from self._coerce_children(item)
            elif isinstance(value, dict):
                for item in value.values():
                    yield from self._coerce_children(item)

        # Scope helpers --------------------------------------------
        def _push_scope(self) -> None:
            parent = self._scopes[-1] if self._scopes else None
            self._scopes.append(_Scope(parent=parent, bindings={}))

        def _pop_scope(self) -> None:
            if self._scopes:
                self._scopes.pop()

        def _current_scope(self) -> _Scope:
            if not self._scopes:
                raise RuntimeError("scope stack is empty")
            return self._scopes[-1]

        # Node visitors --------------------------------------------
        def visit_Chunk(self, node):  # noqa: D401 - public API required
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, self._astnodes.Block):
                self._skip_blocks.add(id(body))
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_Block(self, node):
            block_id = id(node)
            if block_id in self._skip_blocks:
                self._skip_blocks.discard(block_id)
                return self._generic_visit(node)
            self._push_scope()
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_Function(self, node):
            name = getattr(node, "name", None)
            if isinstance(name, self._astnodes.Name):
                self._rename_binding(name, is_function=True, hint=None)
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, self._astnodes.Block):
                self._skip_blocks.add(id(body))
            for arg in getattr(node, "args", []) or []:
                if isinstance(arg, self._astnodes.Name):
                    self._rename_binding(arg, is_function=False, hint=LuaVariableRenamer._ARG_HINT)
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_LocalFunction(self, node):
            name = getattr(node, "name", None)
            if isinstance(name, self._astnodes.Name):
                self._rename_binding(name, is_function=True, hint=None)
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, self._astnodes.Block):
                self._skip_blocks.add(id(body))
            for arg in getattr(node, "args", []) or []:
                if isinstance(arg, self._astnodes.Name):
                    self._rename_binding(arg, is_function=False, hint=LuaVariableRenamer._ARG_HINT)
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_AnonymousFunction(self, node):
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, self._astnodes.Block):
                self._skip_blocks.add(id(body))
            for arg in getattr(node, "args", []) or []:
                if isinstance(arg, self._astnodes.Name):
                    self._rename_binding(arg, is_function=False, hint=LuaVariableRenamer._ARG_HINT)
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_LocalAssign(self, node):
            for target in getattr(node, "targets", []) or []:
                if isinstance(target, self._astnodes.Name):
                    self._rename_binding(target, is_function=False, hint=None)
            self._generic_visit(node)
            return node

        def visit_Assign(self, node):
            for target in getattr(node, "targets", []) or []:
                if isinstance(target, self._astnodes.Name):
                    self._rename_binding(target, is_function=False, hint=None)
            self._generic_visit(node)
            return node

        def visit_Fornum(self, node):
            target = getattr(node, "target", None)
            if isinstance(target, self._astnodes.Name):
                self._rename_binding(target, is_function=False, hint=LuaVariableRenamer._LOOP_HINT)
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, self._astnodes.Block):
                self._skip_blocks.add(id(body))
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_Forin(self, node):
            for target in getattr(node, "targets", []) or []:
                if isinstance(target, self._astnodes.Name):
                    self._rename_binding(target, is_function=False, hint=LuaVariableRenamer._LOOP_HINT)
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, self._astnodes.Block):
                self._skip_blocks.add(id(body))
            self._generic_visit(node)
            self._pop_scope()
            return node

        def visit_Name(self, node):
            identifier = getattr(node, "id", None)
            if not identifier:
                return node
            if self._is_dot_property(node):
                return node
            replacement = self._lookup(identifier)
            if replacement:
                node.id = replacement
            return node

        # Support helpers ------------------------------------------
        def _lookup(self, identifier: str) -> Optional[str]:
            if not self._scopes:
                return None
            return self._scopes[-1].lookup(identifier)

        def _rename_binding(self, name_node, *, is_function: bool, hint: Optional[str]) -> None:
            identifier = getattr(name_node, "id", None)
            if not identifier:
                return
            if identifier in self._owner.lua_keywords:
                return
            scope = self._current_scope()
            existing = scope.get_local(identifier)
            if existing:
                name_node.id = existing
                return
            if not self._owner._is_obfuscated_name(identifier):
                scope.define(identifier, identifier)
                return
            if is_function:
                replacement = self._owner._allocate_function_name(identifier)
            else:
                replacement = self._owner._allocate_variable_name(identifier, hint)
            scope.define(identifier, replacement)
            name_node.id = replacement

        def _is_dot_property(self, node) -> bool:
            if len(self._stack) < 1:
                return False
            parent = self._stack[-1]
            if isinstance(parent, self._astnodes.Index):
                notation = getattr(parent, "notation", None)
                if notation == self._astnodes.IndexNotation.DOT and parent.idx is node:
                    return True
            return False

    # -- Reporting --------------------------------------------------
    def get_mapping_report(self) -> str:
        """Generate a human-readable report for performed renames."""

        report = ["Variable and Function Renaming Report", "=" * 40]

        if self.function_map:
            report.append("\nFunctions:")
            for original, replacements in sorted(self.function_map.items()):
                for replacement in sorted(replacements):
                    report.append(f"  {original} -> {replacement}")

        if self.variable_map:
            report.append("\nVariables:")
            for original, replacements in sorted(self.variable_map.items()):
                for replacement in sorted(replacements):
                    report.append(f"  {original} -> {replacement}")

        return "\n".join(report)


def rename_in_file(input_path: str, output_path: str) -> bool:
    """Rename variables in ``input_path`` and write to ``output_path``."""

    content = safe_read_file(input_path)
    if content is None:
        return False
    renamer = LuaVariableRenamer()
    out = renamer.rename_variables(content)
    return safe_write_file(output_path, out)
