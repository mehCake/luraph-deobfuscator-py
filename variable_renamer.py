"""Scope-aware renaming heuristics for pseudo-Lua registers.

The devirtualiser emits readable but still machine-oriented identifiers such
as ``R0``/``R1`` for temporaries and ``UPVAL0`` for captured variables.  This
module rewrites those placeholders into deterministic, human friendly names
while respecting Lua scoping rules.  The implementation operates purely on the
Lua source text so it can be used as a final pretty-printing pass without
needing a full parser.

Key design goals:

* Stable output – running the renamer multiple times on the same source must
  always yield identical names.
* Shadowing safety – nested functions receive their own namespace so reused
  registers do not collide with outer scopes.
* Role aware naming – loop counters become ``idx``/``idx2``, length
  temporaries become ``len``/``len2`` and generic ``for`` iterator variables
  map to ``key``/``value`` pairs.  Function parameters follow the familiar
  ``arg1``/``arg2`` pattern while upvalues turn into ``uv1``/``uv2``.

The heuristics intentionally remain conservative; identifiers that do not
match the recognised register patterns are left untouched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from collections import defaultdict
import logging
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple, cast


_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CANDIDATE_RE = re.compile(r"\b(?:R|T|UPVAL)\d+\b")
_NUMERIC_FOR_RE = re.compile(r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s*=")
_GENERIC_FOR_RE = re.compile(
    r"for\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?\s+in"
)
_LENGTH_RE = re.compile(r"#\s*([A-Za-z_][A-Za-z0-9_]*)")
_INDEX_RE = re.compile(r"\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]")
_LOCAL_DECL_RE = re.compile(r"\blocal\s+(?!function)([RT]\d+(?:\s*,\s*[RT]\d+)*)")
_LOCAL_FUNC_RE = re.compile(r"\blocal\s+function\s+([RT]\d+)")
_FUNCTION_DECL_RE = re.compile(r"\bfunction\s+([RT]\d+)\s*\(")
_FUNCTION_ASSIGN_RE = re.compile(r"\b([RT]\d+)\s*=\s*function\b")

_HEADER_RE = re.compile(
    r"function\s*(?P<name>(?:[A-Za-z_][A-Za-z0-9_]*)(?:[:.][A-Za-z_][A-Za-z0-9_]*)?)?\s*\((?P<params>[^)]*)\)",
    re.S,
)


LUA_KEYWORDS: Set[str] = {
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


LUA_GLOBALS: Set[str] = {
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


def _register_name(index: int) -> str:
    """Return an alphabetical identifier for ``index`` (0 → ``a``)."""

    chars: List[str] = []
    current = index
    while True:
        chars.append(chr(ord("a") + (current % 26)))
        current //= 26
        if current == 0:
            break
        current -= 1
    return "".join(reversed(chars))


@dataclass
class HeaderInfo:
    name: Optional[str]
    params: List[str]
    end: int


@dataclass
class FunctionSpan:
    start: int
    end: int
    header: Optional[HeaderInfo]


@dataclass
class SymbolInfo:
    parameter_positions: List[int]
    tags: Set[str]
    defines_local: bool = False

    @classmethod
    def empty(cls) -> "SymbolInfo":
        return cls(parameter_positions=[], tags=set(), defines_local=False)


@dataclass
class ScopeState:
    used_names: Set[str]
    role_counters: Dict[str, int]
    alpha_index: int = 0
    bindings: Dict[str, str] = field(default_factory=dict)
    parent: "ScopeState | None" = None

    @classmethod
    def root(cls) -> "ScopeState":
        return cls(set(), defaultdict(int), 0, {}, None)

    def child(self) -> "ScopeState":
        return ScopeState(set(), defaultdict(int), 0, {}, self)

    def lookup(self, name: str) -> Optional[str]:
        state: Optional["ScopeState"] = self
        while state is not None:
            if name in state.bindings:
                return state.bindings[name]
            state = state.parent
        return None

    def remember(self, name: str, alias: str) -> None:
        self.bindings[name] = alias
        self.used_names.add(alias)


class VariableRenamer:
    """Rename pseudo registers while keeping the code semantically intact."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)
        self._reserved_words = set(LUA_KEYWORDS)
        self._reserved_words.update(LUA_GLOBALS)
        self._replacement_count = 0
        self.last_stats: Dict[str, int] = {}

    # -- Public API -----------------------------------------------------
    def rename_variables(self, lua_src: str) -> str:
        """Return ``lua_src`` with registers renamed to human friendly names."""

        self._replacement_count = 0
        state = ScopeState.root()
        result = self._rename_scope(lua_src, state, header=None)
        self.last_stats = {"replacements": self._replacement_count}
        return result

    # -- Recursive scope processing ------------------------------------
    def _rename_scope(
        self,
        text: str,
        state: ScopeState,
        *,
        header: Optional[HeaderInfo],
    ) -> str:
        children = self._direct_child_functions(text, skip_self=header is not None)
        masked = self._mask_children(text, children)
        self._seed_existing_names(state, masked)
        mapping = self._build_mapping(masked, header, state, children)

        if not children:
            return self._replace_identifiers(text, mapping)

        result: List[str] = []
        cursor = 0
        for child in children:
            segment = text[cursor : child.start]
            result.append(self._replace_identifiers(segment, mapping))
            child_state = state.child()
            child_text = text[child.start : child.end]
            renamed_child = self._rename_scope(child_text, child_state, header=child.header)
            result.append(renamed_child)
            cursor = child.end
        tail = text[cursor:]
        result.append(self._replace_identifiers(tail, mapping))
        return "".join(result)

    # -- Mapping creation ----------------------------------------------
    def _build_mapping(
        self,
        text: str,
        header: Optional[HeaderInfo],
        state: ScopeState,
        children: Sequence[FunctionSpan],
    ) -> Dict[str, str]:
        candidates = sorted({match.group(0) for match in _CANDIDATE_RE.finditer(text)}, key=self._sort_key)
        if not candidates:
            return {}

        info = {name: SymbolInfo.empty() for name in candidates}
        if header is not None:
            if header.name and header.name in info:
                details = info[header.name]
                details.tags.add("function")
                details.defines_local = True
            for position, param in enumerate(header.params, start=1):
                if param in info:
                    details = info[param]
                    details.parameter_positions.append(position)
                    details.tags.add("parameter")
                    details.defines_local = True

        self._apply_role_heuristics(info, text)
        self._mark_definitions(info, text, children)

        mapping: Dict[str, str] = {}
        for candidate in candidates:
            mapping[candidate] = self._assign_name(candidate, info.get(candidate), state)
        return mapping

    def _apply_role_heuristics(self, info: Dict[str, SymbolInfo], text: str) -> None:
        if not info:
            return

        for match in _NUMERIC_FOR_RE.finditer(text):
            name = match.group(1)
            if name in info:
                details = info[name]
                details.tags.add("loop_index")
                details.defines_local = True

        for match in _GENERIC_FOR_RE.finditer(text):
            groups = [g for g in match.groups() if g]
            if not groups:
                continue
            first, *rest = groups
            if first in info:
                details = info[first]
                details.tags.add("key")
                details.defines_local = True
            for name in rest:
                if name in info:
                    details = info[name]
                    details.tags.add("value")
                    details.defines_local = True

        for match in _LENGTH_RE.finditer(text):
            name = match.group(1)
            if name in info:
                info[name].tags.add("length")

        for match in _INDEX_RE.finditer(text):
            name = match.group(1)
            if name in info:
                info[name].tags.add("key")

    def _mark_definitions(
        self,
        info: Dict[str, SymbolInfo],
        text: str,
        children: Sequence[FunctionSpan],
    ) -> None:
        if not info:
            return

        for match in _LOCAL_DECL_RE.finditer(text):
            names = re.findall(r"[RT]\d+", match.group(1))
            for name in names:
                if name in info:
                    info[name].defines_local = True

        for match in _LOCAL_FUNC_RE.finditer(text):
            name = match.group(1)
            if name in info:
                entry = info[name]
                entry.tags.add("function")
                entry.defines_local = True

        for match in _FUNCTION_DECL_RE.finditer(text):
            name = match.group(1)
            if name in info:
                entry = info[name]
                entry.tags.add("function")
                entry.defines_local = True

        for match in _FUNCTION_ASSIGN_RE.finditer(text):
            name = match.group(1)
            if name in info:
                info[name].defines_local = True

        for child in children:
            header = child.header
            if header and header.name and header.name in info:
                entry = info[header.name]
                entry.tags.add("function")
                entry.defines_local = True

    # -- Name allocation ------------------------------------------------
    def _assign_name(self, name: str, details: Optional[SymbolInfo], state: ScopeState) -> str:
        info = details or SymbolInfo.empty()
        existing = state.lookup(name)
        if existing is not None:
            if not (info.defines_local and "function" not in info.tags):
                state.remember(name, existing)
                return existing

        if name.startswith("UPVAL"):
            alias = self._assign_upvalue(name, state)
        elif "parameter" in info.tags:
            alias = self._assign_parameter(info, state)
        elif "loop_index" in info.tags:
            alias = self._assign_role("idx", state, plain_first=True)
        elif "length" in info.tags:
            alias = self._assign_role("len", state, plain_first=True)
        elif "key" in info.tags:
            alias = self._assign_role("key", state, plain_first=True)
        elif "value" in info.tags:
            alias = self._assign_role("value", state, plain_first=True)
        else:
            alias = self._assign_register(state)

        state.remember(name, alias)
        return alias

    def _assign_upvalue(self, name: str, state: ScopeState) -> str:
        try:
            index = int(name[5:]) + 1
        except ValueError:
            index = len([n for n in state.used_names if n.startswith("uv")]) + 1
        candidate = f"uv{index}"
        suffix = 1
        while candidate in state.used_names or candidate in self._reserved_words:
            suffix += 1
            candidate = f"uv{index}_{suffix}"
        return candidate

    def _assign_parameter(self, info: SymbolInfo, state: ScopeState) -> str:
        for position in sorted(set(info.parameter_positions)):
            candidate = f"arg{position}"
            if candidate not in state.used_names and candidate not in self._reserved_words:
                state.used_names.add(candidate)
                return candidate
        return self._assign_role("arg", state, plain_first=False)

    def _assign_role(
        self,
        base: str,
        state: ScopeState,
        *,
        plain_first: bool,
        start_index: int = 1,
    ) -> str:
        counter = state.role_counters.get(base, 0)
        while True:
            if plain_first and counter == 0:
                candidate = base
            else:
                candidate = f"{base}{start_index + counter}"
            if candidate not in state.used_names and candidate not in self._reserved_words:
                state.role_counters[base] = counter + 1
                state.used_names.add(candidate)
                return candidate
            counter += 1

    def _assign_register(self, state: ScopeState) -> str:
        while True:
            candidate = _register_name(state.alpha_index)
            state.alpha_index += 1
            if candidate not in state.used_names and candidate not in self._reserved_words:
                state.used_names.add(candidate)
                return candidate

    # -- Helpers --------------------------------------------------------
    def _sort_key(self, name: str) -> Tuple[int, int, str]:
        match = re.match(r"([A-Z]+)(\d+)", name)
        if match:
            prefix, number = match.groups()
            prefix_order = {"UPVAL": 0, "R": 1, "T": 2}.get(prefix, 3)
            return (prefix_order, int(number), "")
        return (4, 0, name)

    def _seed_existing_names(self, state: ScopeState, text: str) -> None:
        for match in _IDENTIFIER_RE.finditer(text):
            identifier = match.group(0)
            if _CANDIDATE_RE.fullmatch(identifier):
                continue
            if identifier in self._reserved_words:
                continue
            state.used_names.add(identifier)

    def _replace_identifiers(self, text: str, mapping: Dict[str, str]) -> str:
        if not mapping:
            return text

        result: List[str] = []
        i = 0
        length = len(text)
        while i < length:
            if text.startswith("--", i):
                if text.startswith("--[[", i) or text.startswith("--[=", i):
                    end = self._skip_long_bracket(text, i + 2)
                    result.append(text[i:end])
                    i = end
                    continue
                newline = text.find("\n", i)
                if newline == -1:
                    result.append(text[i:])
                    break
                result.append(text[i:newline + 1])
                i = newline + 1
                continue
            if text[i] in {'"', '\''}:
                end = self._skip_short_string(text, i)
                result.append(text[i:end])
                i = end
                continue
            if text.startswith("[[", i) or text.startswith("[=", i):
                end = self._skip_long_bracket(text, i)
                result.append(text[i:end])
                i = end
                continue
            match = _IDENTIFIER_RE.match(text, i)
            if match:
                identifier = match.group(0)
                replacement = mapping.get(identifier)
                if replacement and replacement != identifier:
                    self._replacement_count += 1
                    result.append(replacement)
                else:
                    result.append(identifier)
                i = match.end()
            else:
                result.append(text[i])
                i += 1
        return "".join(result)

    def _direct_child_functions(self, text: str, *, skip_self: bool) -> List[FunctionSpan]:
        spans = sorted(self._scan_functions(text), key=lambda span: span.start)
        direct: List[FunctionSpan] = []
        for span in spans:
            if skip_self and span.start == 0:
                skip_self = False
                continue
            if direct and span.start < direct[-1].end:
                continue
            direct.append(span)
        return direct

    def _mask_children(self, text: str, children: Sequence[FunctionSpan]) -> str:
        if not children:
            return text
        pieces: List[str] = []
        cursor = 0
        for child in children:
            pieces.append(text[cursor:child.start])
            pieces.append(" " * (child.end - child.start))
            cursor = child.end
        pieces.append(text[cursor:])
        return "".join(pieces)

    # -- Token scanning -------------------------------------------------
    def _scan_functions(self, text: str) -> List[FunctionSpan]:
        spans: List[FunctionSpan] = []
        stack: List[Dict[str, object]] = []
        i = 0
        length = len(text)
        while i < length:
            if text.startswith("--", i):
                if text.startswith("--[[", i) or text.startswith("--[=", i):
                    i = self._skip_long_bracket(text, i + 2)
                else:
                    newline = text.find("\n", i)
                    i = length if newline == -1 else newline + 1
                continue
            ch = text[i]
            if ch in {'"', '\''}:
                i = self._skip_short_string(text, i)
                continue
            if text.startswith("[[", i) or text.startswith("[=", i):
                i = self._skip_long_bracket(text, i)
                continue
            if ch.isalpha() or ch == "_":
                j = i + 1
                while j < length and (text[j].isalnum() or text[j] == "_"):
                    j += 1
                word = text[i:j]
                if word == "function":
                    header = self._parse_header(text, i)
                    stack.append(
                        {
                            "kind": "function",
                            "start": i,
                            "header": header,
                        }
                    )
                elif word in {"do", "then"}:
                    stack.append({"kind": word})
                elif word == "repeat":
                    stack.append({"kind": word})
                elif word == "end":
                    while stack:
                        block = stack.pop()
                        kind = block["kind"]
                        if kind == "function":
                            header = cast(Optional[HeaderInfo], block.get("header"))
                            start_idx = cast(int, block.get("start"))
                            spans.append(
                                FunctionSpan(
                                    start=start_idx,
                                    end=j,
                                    header=header,
                                )
                            )
                            break
                        if kind in {"do", "then"}:
                            break
                elif word == "until":
                    while stack:
                        block = stack.pop()
                        if block["kind"] == "repeat":
                            break
                i = j
                continue
            i += 1
        spans.sort(key=lambda span: span.start)
        return spans

    def _parse_header(self, text: str, start: int) -> Optional[HeaderInfo]:
        match = _HEADER_RE.match(text, start)
        if not match:
            return None
        raw_params = match.group("params") or ""
        params = [param.strip() for param in raw_params.split(",") if param.strip()]
        name = match.group("name") or None
        return HeaderInfo(name=name, params=params, end=match.end())

    def _skip_short_string(self, text: str, start: int) -> int:
        quote = text[start]
        i = start + 1
        length = len(text)
        while i < length:
            ch = text[i]
            if ch == "\\" and i + 1 < length:
                i += 2
                continue
            if ch == quote:
                return i + 1
            i += 1
        return length

    def _skip_long_bracket(self, text: str, start: int) -> int:
        # Support [=[ ... ]=] style long strings/comments.
        equals = 0
        i = start + 1
        length = len(text)
        while i < length and text[i] == "=":
            equals += 1
            i += 1
        if i >= length or text[i] != "[":
            return start + 1
        closing = "]" + "=" * equals + "]"
        end = text.find(closing, i + 1)
        return length if end == -1 else end + len(closing)

    # -- End helpers ----------------------------------------------------


__all__ = ["VariableRenamer"]

