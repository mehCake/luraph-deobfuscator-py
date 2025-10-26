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
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple, cast

from utils import benchmark


_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_IDENTIFIER_ONLY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CANDIDATE_RE = re.compile(r"\b(?:R|T|UPVAL)\d+\b")
_NUMERIC_FOR_RE = re.compile(r"for\s+([A-Za-z_][A-Za-z0-9_]*)\s*=")
_GENERIC_FOR_RE = re.compile(
    r"for\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?(?:\s*,\s*([A-Za-z_][A-Za-z0-9_]*))?\s+in"
)
_LENGTH_RE = re.compile(r"#\s*([A-Za-z_][A-Za-z0-9_]*)")
_INDEX_RE = re.compile(r"\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]")
_STRING_BYTE_RE = re.compile(r'string\.byte\s*\(')
_BIT32_CALL_RE = re.compile(r'bit32\.(?:band|bor|bxor|bnot|lshift|rshift|arshift)\s*\(')
_NUMERIC_LITERAL_RE = re.compile(
    r"^(?:0x[0-9a-fA-F]+|0b[01]+|\d+(?:\.\d+)?)(?:[eE][+-]?\d+)?$"
)
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
        self._score_total = 0
        self._score_sum = 0.0
        self.last_stats: Dict[str, float] = {}

    # -- Public API -----------------------------------------------------
    def rename_variables(self, lua_src: str) -> str:
        """Return ``lua_src`` with registers renamed to human friendly names."""

        self._replacement_count = 0
        self._score_total = 0
        self._score_sum = 0.0
        state = ScopeState.root()
        result = self._rename_scope(lua_src, state, header=None)
        readability = 100.0
        if self._score_total:
            readability = round(100.0 * (self._score_sum / self._score_total), 2)
        self.last_stats = {
            "replacements": int(self._replacement_count),
            "readability": readability,
        }
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

        indexed_names: Set[str] = set()
        for match in _INDEX_RE.finditer(text):
            name = match.group(1)
            if name in info:
                info[name].tags.add("key")
                indexed_names.add(name)

        for byte_index in self._scan_string_byte_indices(text):
            if byte_index in info:
                info[byte_index].tags.add("string_byte_arg")

        for name in indexed_names:
            details = info.get(name)
            if details and "string_byte_arg" in details.tags:
                details.tags.add("byte_indexer")

        for mask_name in self._scan_bit_masks(text):
            if mask_name in info:
                info[mask_name].tags.add("mask")

    def _scan_string_byte_indices(self, text: str) -> Set[str]:
        names: Set[str] = set()
        for match in _STRING_BYTE_RE.finditer(text):
            paren_index = text.find("(", match.start())
            if paren_index == -1:
                continue
            args, _ = self._extract_call_arguments(text, paren_index + 1)
            if len(args) < 2:
                continue
            for arg in args[1:]:
                candidate = self._strip_identifier(arg)
                if candidate:
                    names.add(candidate)
        return names

    def _scan_bit_masks(self, text: str) -> Set[str]:
        names: Set[str] = set()
        for match in _BIT32_CALL_RE.finditer(text):
            paren_index = text.find("(", match.start())
            if paren_index == -1:
                continue
            args, _ = self._extract_call_arguments(text, paren_index + 1)
            if not args:
                continue
            numeric_present = any(self._is_numeric_literal(arg) for arg in args)
            if not numeric_present:
                continue
            for arg in args:
                candidate = self._strip_identifier(arg)
                if candidate:
                    names.add(candidate)
        return names

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
        elif "byte_indexer" in info.tags:
            alias = self._assign_role("byte_indexer", state, plain_first=True)
        elif "mask" in info.tags:
            alias = self._assign_role("mask", state, plain_first=True)
        elif "parameter" in info.tags:
            alias = self._assign_parameter(info, state)
        elif "loop_index" in info.tags:
            alias = self._assign_role("i_cnt", state, plain_first=True)
        elif "length" in info.tags:
            alias = self._assign_role("len", state, plain_first=True)
        elif "key" in info.tags:
            alias = self._assign_role("key", state, plain_first=True)
        elif "value" in info.tags:
            alias = self._assign_role("value", state, plain_first=True)
        else:
            alias = self._assign_register(state)

        state.remember(name, alias)
        self._record_alias_quality(alias, info)
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

    def _strip_identifier(self, token: str) -> Optional[str]:
        candidate = token.strip()
        if candidate.startswith("(") and candidate.endswith(")"):
            candidate = candidate[1:-1].strip()
        return candidate if _IDENTIFIER_ONLY_RE.fullmatch(candidate) else None

    def _is_numeric_literal(self, token: str) -> bool:
        candidate = token.strip()
        if candidate.startswith("(") and candidate.endswith(")"):
            candidate = candidate[1:-1].strip()
        return bool(_NUMERIC_LITERAL_RE.fullmatch(candidate))

    def _extract_call_arguments(self, text: str, start: int) -> Tuple[List[str], int]:
        depth = 1
        args: List[str] = []
        current: List[str] = []
        i = start
        length = len(text)
        while i < length:
            ch = text[i]
            if ch in {'"', '\''}:
                end = self._skip_short_string(text, i)
                current.append(text[i:end])
                i = end
                continue
            if text.startswith("[[", i) or text.startswith("[=", i):
                end = self._skip_long_bracket(text, i)
                current.append(text[i:end])
                i = end
                continue
            if text.startswith("--", i):
                newline = text.find("\n", i)
                if newline == -1:
                    break
                current.append(text[i:newline])
                i = newline
                continue
            if ch == "(":
                depth += 1
                current.append(ch)
                i += 1
                continue
            if ch == ")":
                depth -= 1
                if depth == 0:
                    argument = "".join(current).strip()
                    if argument:
                        args.append(argument)
                    return args, i + 1
                current.append(ch)
                i += 1
                continue
            if ch == "," and depth == 1:
                argument = "".join(current).strip()
                if argument:
                    args.append(argument)
                current = []
                i += 1
                continue
            current.append(ch)
            i += 1
        return args, i

    def _record_alias_quality(self, alias: str, details: SymbolInfo) -> None:
        if not alias:
            return
        self._score_total += 1
        self._score_sum += self._alias_score(alias, details)

    def _alias_score(self, alias: str, details: SymbolInfo) -> float:
        if not alias:
            return 0.0
        base = 0.25 if len(alias) == 1 else 0.6
        if "byte_indexer" in details.tags:
            base = 1.0
        elif alias.startswith("mask"):
            base = max(base, 0.9)
        elif alias.startswith("i_cnt"):
            base = max(base, 0.85)
        elif "length" in details.tags or "key" in details.tags or "value" in details.tags:
            base = max(base, 0.75)
        if "_" in alias:
            base = min(1.0, base + 0.1)
        return min(base, 1.0)

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


def safe_rename(src: str, rename_map: Mapping[str, str]) -> str:
    """Rename identifiers in ``src`` according to ``rename_map``.

    The implementation relies on :mod:`luaparser` to build an AST, mutate the
    identifier nodes safely (avoiding strings, comments, or long-bracket
    literals), and then re-render the source using the formatter bundled with
    the parser.
    """

    if not rename_map:
        return src

    try:
        from luaparser import ast
        from luaparser import astnodes
    except ImportError as exc:  # pragma: no cover - import guarded in tests
        raise RuntimeError("safe_rename requires luaparser to be installed") from exc

    _validate_rename_map(rename_map)

    class _ScopeFrame:
        __slots__ = ("locals", "renames")

        def __init__(self) -> None:
            self.locals: Set[str] = set()
            self.renames: Dict[str, str] = {}

    class _SafeRenameVisitor(ast.ASTRecursiveVisitor):
        """AST visitor that applies identifier renames with scope tracking."""

        def __init__(self, rename_map: Mapping[str, str]) -> None:
            super().__init__()
            self._stack: List[object] = []
            self._pending: Dict[str, List[str]] = {
                key: [value]
                for key, value in rename_map.items()
                if value and key
            }
            self._global_defaults: Dict[str, str] = {
                key: value
                for key, value in rename_map.items()
                if value and key
            }
            self._scopes: List[_ScopeFrame] = []
            self._skip_blocks: Set[int] = set()

        # -- Generic traversal helpers ---------------------------------
        def visit(self, node):  # type: ignore[override]
            if isinstance(node, list):
                for child in node:
                    self.visit(child)
                return node
            if node is None:
                return node
            self._stack.append(node)
            result = super().visit(node)
            self._stack.pop()
            return result

        # Scope management ---------------------------------------------
        def _push_scope(self) -> None:
            self._scopes.append(_ScopeFrame())

        def _pop_scope(self) -> None:
            if self._scopes:
                self._scopes.pop()

        def _current_scope(self) -> _ScopeFrame:
            if not self._scopes:
                raise RuntimeError("scope stack is empty")
            return self._scopes[-1]

        def _lookup(self, identifier: str) -> Optional[str]:
            for frame in reversed(self._scopes):
                if identifier in frame.renames:
                    return frame.renames[identifier]
                if identifier in frame.locals:
                    return None
            replacement = self._global_defaults.get(identifier)
            if replacement:
                return replacement
            return None

        def _consume_rename(self, identifier: str) -> Optional[str]:
            values = self._pending.get(identifier)
            if not values:
                return None
            replacement = values.pop(0)
            if not values:
                self._pending.pop(identifier, None)
            return replacement

        def _register_local(self, name_node: astnodes.Name) -> None:
            identifier = getattr(name_node, "id", None)
            if not identifier:
                return
            replacement = self._consume_rename(identifier)
            frame = self._current_scope()
            frame.locals.add(identifier)
            if replacement:
                name_node.id = replacement
                frame.renames[identifier] = replacement

        def _register_locals(self, names: Sequence[object]) -> None:
            for item in names:
                if isinstance(item, astnodes.Name):
                    self._register_local(item)

        def _is_dot_property(self, node: object) -> bool:
            if len(self._stack) < 2:
                return False
            parent = self._stack[-2]
            if isinstance(parent, astnodes.Index):
                notation = getattr(parent, "notation", None)
                if notation == astnodes.IndexNotation.DOT and parent.idx is node:
                    return True
            return False

        def _is_binding_context(self, node: astnodes.Name) -> bool:
            if len(self._stack) < 2:
                return False
            parent = self._stack[-2]
            if isinstance(parent, astnodes.LocalAssign) and node in parent.targets:
                return True
            if isinstance(parent, astnodes.LocalFunction) and parent.name is node:
                return True
            if isinstance(parent, astnodes.Function) and parent.name is node:
                return True
            if isinstance(parent, astnodes.Forin) and node in getattr(parent, "targets", []):
                return True
            if isinstance(parent, astnodes.Fornum) and parent.target is node:
                return True
            if isinstance(parent, astnodes.AnonymousFunction) and node in getattr(parent, "args", []):
                return True
            if isinstance(parent, astnodes.Function) and node in getattr(parent, "args", []):
                return True
            if isinstance(parent, astnodes.LocalFunction) and node in getattr(parent, "args", []):
                return True
            return False

        # Chunk / block scopes ----------------------------------------
        def enter_Chunk(self, node):  # type: ignore[override]
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, astnodes.Block):
                self._skip_blocks.add(id(body))

        def exit_Chunk(self, node):  # type: ignore[override]
            self._pop_scope()

        def enter_Block(self, node):  # type: ignore[override]
            if id(node) in self._skip_blocks:
                return
            self._push_scope()
            self._register_enclosing_bindings(node)

        def exit_Block(self, node):  # type: ignore[override]
            if id(node) in self._skip_blocks:
                self._skip_blocks.discard(id(node))
                return
            self._pop_scope()

        def _register_enclosing_bindings(self, block: astnodes.Block) -> None:
            if len(self._stack) < 2:
                return
            parent = self._stack[-2]
            if isinstance(parent, astnodes.Fornum):
                target = getattr(parent, "target", None)
                if isinstance(target, astnodes.Name):
                    self._register_local(target)
            elif isinstance(parent, astnodes.Forin):
                self._register_locals(getattr(parent, "targets", []))

        # Function scopes ----------------------------------------------
        def enter_Function(self, node):  # type: ignore[override]
            name = getattr(node, "name", None)
            if isinstance(name, astnodes.Name):
                self._register_local(name)
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, astnodes.Block):
                self._skip_blocks.add(id(body))
            self._register_locals(getattr(node, "args", []))

        def exit_Function(self, node):  # type: ignore[override]
            self._pop_scope()

        def enter_LocalFunction(self, node):  # type: ignore[override]
            name = getattr(node, "name", None)
            if isinstance(name, astnodes.Name):
                self._register_local(name)
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, astnodes.Block):
                self._skip_blocks.add(id(body))
            self._register_locals(getattr(node, "args", []))

        def exit_LocalFunction(self, node):  # type: ignore[override]
            self._pop_scope()

        def enter_AnonymousFunction(self, node):  # type: ignore[override]
            self._push_scope()
            body = getattr(node, "body", None)
            if isinstance(body, astnodes.Block):
                self._skip_blocks.add(id(body))
            self._register_locals(getattr(node, "args", []))

        def exit_AnonymousFunction(self, node):  # type: ignore[override]
            self._pop_scope()

        # Local declarations ------------------------------------------
        def enter_LocalAssign(self, node):  # type: ignore[override]
            self._register_locals(getattr(node, "targets", []))

        def enter_Forin(self, node):  # type: ignore[override]
            # The loop variables belong to the block scope handled in _register_enclosing_bindings.
            pass

        def enter_Fornum(self, node):  # type: ignore[override]
            # The control variable is handled when the body block scope is entered.
            pass

        # Identifier rewriting ---------------------------------------
        # pylint: disable=unused-argument
        def enter_Name(self, node):  # type: ignore[override]
            identifier = getattr(node, "id", None)
            if not identifier:
                return
            if self._is_dot_property(node) or self._is_binding_context(node):
                return
            replacement = self._lookup(identifier)
            if replacement:
                node.id = replacement

    with benchmark(
        "ast_transform",
        {"operation": "safe_rename", "renames": len(rename_map)},
    ):
        tree = ast.parse(src)
        visitor = _SafeRenameVisitor(rename_map)
        visitor.visit(tree)
        renamed = ast.to_lua_source(tree)
    return renamed


def _validate_rename_map(rename_map: Mapping[str, str]) -> None:
    invalid_sources: List[str] = []
    invalid_targets: List[str] = []

    for source, target in rename_map.items():
        if source in LUA_KEYWORDS:
            invalid_sources.append(source)
        if target in LUA_KEYWORDS or target in LUA_GLOBALS:
            invalid_targets.append(target)
        if not _IDENTIFIER_RE.fullmatch(target):
            invalid_targets.append(target)

    if invalid_sources:
        raise ValueError(f"Cannot rename reserved identifiers: {sorted(set(invalid_sources))}")
    if invalid_targets:
        raise ValueError(f"Invalid rename targets: {sorted(set(invalid_targets))}")


__all__ = ["VariableRenamer", "safe_rename"]

