"""Static tracing utilities for analysing bootstrap functions without executing them.

This module started life as a lightweight helper for spotting suspect helper
functions inside bootstrap snippets.  Luraph v14.4.x payloads made it clear that
we also need richer tracing for the transform pipelines themselves – being able
to describe, in a deterministic and auditable way, which bitwise and table
manipulations occur in each helper without ever executing the untrusted Lua.

To support that workflow we now provide a symbolic tracer that extracts
transform operations (``xor``, ``rotate``, ``permute`` and friends) from the
function bodies, records any runtime-only constructs that would prevent static
resolution, and optionally emits JSON trace artefacts for downstream tooling.
The original helper functions remain available for compatibility with the
collector pipeline.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
import logging
import re
from pathlib import Path
from typing import Dict, Iterator, List, Mapping, Optional, Sequence

LOGGER = logging.getLogger(__name__)

__all__ = [
    "FunctionTrace",
    "HandlerMatch",
    "TransformOperation",
    "FunctionAnalysis",
    "analyse_transform_snippet",
    "emit_trace_reports",
    "match_handler_patterns",
    "trace_pipeline_functions",
    "main",
]


@dataclass(frozen=True)
class FunctionTrace:
    """Summary describing a function and the calls it makes to pipeline helpers."""

    name: str
    start: int
    end: int
    calls: Sequence[str]


@dataclass(frozen=True)
class HandlerMatch:
    """Represents an ``opcode`` -> handler branch discovered in bootstrap code."""

    opcode: int
    handler: str
    start: int
    end: int
    mnemonics: Sequence[str] = ()
    body: Optional[str] = None


@dataclass(frozen=True)
class TransformOperation:
    """Structured description of a detected transform operation."""

    type: str
    offset: int
    source: str
    args: Dict[str, str]

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "type": self.type,
            "offset": self.offset,
            "source": self.source.strip(),
        }
        if self.args:
            data["args"] = self.args
        return data


@dataclass(frozen=True)
class FunctionAnalysis:
    """A transform-oriented summary for a bootstrap helper function."""

    name: str
    start: int
    end: int
    resolvable: bool
    operations: Sequence[TransformOperation]
    issues: Sequence[str]
    references: Sequence[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "start_offset": self.start,
            "end_offset": self.end,
            "resolvable": self.resolvable,
            "operations": [op.to_dict() for op in self.operations],
            "issues": list(self.issues),
            "references": list(self.references),
        }


_SUSPECT_KEYWORDS = (
    "decode",
    "permute",
    "xor",
    "rot",
    "mask",
    "mix",
    "shuffle",
    "scramble",
    "unmask",
)

_CALL_PATTERN = re.compile(r"\b([A-Za-z_][\w\.:]*)\s*\(")
_BRANCH_PATTERN = re.compile(
    r"\b(if|elseif)\s+([A-Za-z_][\w]*)\s*==\s*(0x[0-9A-Fa-f]+|\d+)\s*then",
    re.MULTILINE,
)
_HANDLER_CALL_PATTERN = re.compile(r"(?:return\s+)?([A-Za-z_][\w\.:]*)\s*\(")

_GENERIC_INVOCATION_PATTERN = re.compile(r"\b([A-Za-z_][\w\.:]*)\s*\(")

_STACK_IDENTIFIERS = r"(?:stack|regs|registers|state\.stack|vm\.stack|_stack|slots)"
_STACK_ASSIGN_PATTERN = re.compile(rf"{_STACK_IDENTIFIERS}\s*\[[^\]]+\]\s*=", re.IGNORECASE)
_STACK_CALL_PATTERN = re.compile(rf"{_STACK_IDENTIFIERS}\s*\[[^\]]+\]\s*\(", re.IGNORECASE)
_STACK_COMPARE_PATTERN = re.compile(
    rf"{_STACK_IDENTIFIERS}\s*\[[^\]]+\]\s*(?:==|~=)", re.IGNORECASE
)
_RETURN_STACK_PATTERN = re.compile(
    rf"\breturn\b[^\n;]*{_STACK_IDENTIFIERS}", re.IGNORECASE
)
_CONSTANT_PATTERN = re.compile(
    r"\b(const(?:ant)?s?|proto\.k|proto\.constants|k\b|k\s*\[)", re.IGNORECASE
)
_PC_TOKEN_PATTERN = re.compile(r"\b(pc|ip|program_counter|instruction_ptr)\b", re.IGNORECASE)
_PC_UPDATE_PATTERN = re.compile(
    r"\b(pc|ip|program_counter|instruction_ptr)\b[^\n;]*([+\-]=|=\s*\1\s*[+\-])",
    re.IGNORECASE,
)
_JUMP_KEYWORD_PATTERN = re.compile(r"\b(jmp|jump|branch|goto)\b", re.IGNORECASE)
_CALL_KEYWORD_PATTERN = re.compile(r"\bcall\b", re.IGNORECASE)
_EQ_KEYWORD_PATTERN = re.compile(r"\b(eq|equal|compare)\b", re.IGNORECASE)
_MNEMONIC_ORDER = ("LOADK", "CALL", "RETURN", "JMP", "EQ")

_TRANSFORM_BINARY_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("xor", re.compile(r"bit32\.bxor\s*\(([^,]+),\s*([^)]+)\)")),
    ("mask", re.compile(r"bit32\.band\s*\(([^,]+),\s*([^)]+)\)")),
    ("merge", re.compile(r"bit32\.bor\s*\(([^,]+),\s*([^)]+)\)")),
    ("shift-left", re.compile(r"bit32\.lshift\s*\(([^,]+),\s*([^)]+)\)")),
    ("shift-right", re.compile(r"bit32\.rshift\s*\(([^,]+),\s*([^)]+)\)")),
)

_TRANSFORM_UNARY_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("invert", re.compile(r"bit32\.bnot\s*\(([^)]+)\)")),
)

_TRANSFORM_ROTATE_PATTERNS: Sequence[tuple[str, str, re.Pattern[str]]] = (
    ("rotate", "left", re.compile(r"bit32\.(?:lrotate|rol)\s*\(([^,]+),\s*([^)]+)\)")),
    ("rotate", "right", re.compile(r"bit32\.(?:rrotate|ror)\s*\(([^,]+),\s*([^)]+)\)")),
)

_TRANSFORM_GENERAL_PATTERNS: Sequence[tuple[str, Optional[str], re.Pattern[str]]] = (
    ("string-char", None, re.compile(r"string\.char\s*\(")),
    ("string-byte", None, re.compile(r"string\.byte\s*\(")),
    ("string-sub", None, re.compile(r"string\.sub\s*\(")),
    ("string-reverse", None, re.compile(r"string\.reverse\s*\(")),
    ("concatenate", None, re.compile(r"table\.concat\s*\(")),
    ("permute", "insert", re.compile(r"table\.insert\s*\(")),
    ("permute", "remove", re.compile(r"table\.remove\s*\(")),
    ("permute", "sort", re.compile(r"table\.sort\s*\(")),
    ("math", None, re.compile(r"math\.[A-Za-z_]\w*\s*\(")),
    ("decode-call", None, re.compile(r"[:.]decode\s*\(")),
    ("permute-call", None, re.compile(r"[:.]permute\s*\(")),
    ("xor-call", None, re.compile(r"[:.]xor\s*\(")),
)

_RUNTIME_ONLY_PATTERNS: Sequence[tuple[str, re.Pattern[str]]] = (
    ("load", re.compile(r"\bload(string)?\b")),
    ("pcall", re.compile(r"\bpcall\b")),
    ("require", re.compile(r"\brequire\b")),
    ("environment", re.compile(r"\b(getfenv|setfenv|_ENV)\b")),
    ("debug", re.compile(r"\bdebug\.[A-Za-z_]\w*")),
    ("io", re.compile(r"\bio\.[A-Za-z_]\w*")),
)
_NAME_HINTS = (
    ("loadk", "LOADK"),
    ("load_k", "LOADK"),
    ("call", "CALL"),
    ("invoke", "CALL"),
    ("ret", "RETURN"),
    ("return", "RETURN"),
    ("jmp", "JMP"),
    ("jump", "JMP"),
    ("eq", "EQ"),
)


def _is_boundary(text: str, index: int) -> bool:
    if index < 0 or index >= len(text):
        return True
    return not (text[index].isalnum() or text[index] == "_")


def _normalise_arg(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _build_binary_operation(
    op_type: str, match: re.Match[str], base_offset: int
) -> TransformOperation:
    left = _normalise_arg(match.group(1))
    right = _normalise_arg(match.group(2))
    return TransformOperation(
        type=op_type,
        offset=base_offset + match.start(),
        source=match.group(0),
        args={"lhs": left, "rhs": right},
    )


def _build_unary_operation(op_type: str, match: re.Match[str], base_offset: int) -> TransformOperation:
    operand = _normalise_arg(match.group(1))
    return TransformOperation(
        type=op_type,
        offset=base_offset + match.start(),
        source=match.group(0),
        args={"value": operand},
    )


def _build_rotate_operation(
    op_type: str, direction: str, match: re.Match[str], base_offset: int
) -> TransformOperation:
    value = _normalise_arg(match.group(1))
    bits = _normalise_arg(match.group(2))
    return TransformOperation(
        type=op_type,
        offset=base_offset + match.start(),
        source=match.group(0),
        args={"value": value, "bits": bits, "direction": direction},
    )


def _build_general_operation(
    op_type: str,
    qualifier: Optional[str],
    match: re.Match[str],
    base_offset: int,
) -> TransformOperation:
    args: Dict[str, str] = {}
    if qualifier:
        args["qualifier"] = qualifier
    return TransformOperation(
        type=op_type,
        offset=base_offset + match.start(),
        source=match.group(0),
        args=args,
    )


def _collect_references(body: str) -> List[str]:
    refs: List[str] = []
    seen: set[str] = set()
    for match in _GENERIC_INVOCATION_PATTERN.finditer(body):
        name = match.group(1)
        lower = name.lower()
        if lower in seen:
            continue
        seen.add(lower)
        refs.append(name)
    return refs


def _detect_runtime_constraints(body: str, *, base_offset: int) -> List[str]:
    issues: List[str] = []
    for label, pattern in _RUNTIME_ONLY_PATTERNS:
        for match in pattern.finditer(body):
            issues.append(
                f"runtime construct '{match.group(0)}' ({label}) at offset {base_offset + match.start()}"
            )
    return issues


def _extract_transform_operations(body: str, *, base_offset: int) -> List[TransformOperation]:
    operations: List[TransformOperation] = []

    for op_type, pattern in _TRANSFORM_BINARY_PATTERNS:
        for match in pattern.finditer(body):
            operations.append(_build_binary_operation(op_type, match, base_offset))

    for op_type, pattern in _TRANSFORM_UNARY_PATTERNS:
        for match in pattern.finditer(body):
            operations.append(_build_unary_operation(op_type, match, base_offset))

    for op_type, direction, pattern in _TRANSFORM_ROTATE_PATTERNS:
        for match in pattern.finditer(body):
            operations.append(_build_rotate_operation(op_type, direction, match, base_offset))

    for op_type, qualifier, pattern in _TRANSFORM_GENERAL_PATTERNS:
        for match in pattern.finditer(body):
            operations.append(_build_general_operation(op_type, qualifier, match, base_offset))

    operations.sort(key=lambda op: op.offset)
    return operations


def _skip_short_string(text: str, index: int) -> int:
    quote = text[index]
    i = index + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(text)


def _match_long_bracket(text: str, index: int) -> int | None:
    if text[index] != "[":
        return None
    depth = 0
    i = index + 1
    while i < len(text) and text[i] == "=":
        depth += 1
        i += 1
    if i < len(text) and text[i] == "[":
        return depth
    return None


def _skip_long_bracket(text: str, index: int, depth: int) -> int:
    closing = "]" + "=" * depth + "]"
    end = text.find(closing, index + 1)
    return len(text) if end == -1 else end + len(closing)


def _skip_comment(text: str, index: int) -> int:
    if text.startswith("--", index):
        index += 2
        if index < len(text) and text[index] == "[":
            depth = _match_long_bracket(text, index)
            if depth is not None:
                return _skip_long_bracket(text, index, depth)
        while index < len(text) and text[index] not in "\r\n":
            index += 1
    return index


def _find_balanced(text: str, index: int) -> int:
    opens = text[index]
    closes = {"(": ")", "[": "]", "{": "}"}.get(opens)
    if closes is None:
        return index
    depth = 1
    i = index + 1
    while i < len(text):
        ch = text[i]
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        if ch in {'"', "'"}:
            i = _skip_short_string(text, i)
            continue
        if ch == "[":
            lb = _match_long_bracket(text, i)
            if lb is not None:
                i = _skip_long_bracket(text, i, lb)
                continue
        if ch == opens:
            depth += 1
        elif ch == closes:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def _find_matching_end(text: str, function_start: int) -> int:
    depth = 0
    i = function_start
    while i < len(text):
        ch = text[i]
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        if ch in {'"', "'"}:
            i = _skip_short_string(text, i)
            continue
        if ch == "[":
            lb = _match_long_bracket(text, i)
            if lb is not None:
                i = _skip_long_bracket(text, i, lb)
                continue
        if text.startswith("function", i) and _is_boundary(text, i - 1) and _is_boundary(text, i + 8):
            depth += 1
            i += 8
            continue
        if text.startswith("end", i) and _is_boundary(text, i - 1) and _is_boundary(text, i + 3):
            depth -= 1
            i += 3
            if depth <= 0:
                return i
            continue
        i += 1
    return len(text)


def _find_branch_terminus(text: str, branch_start: int) -> int:
    depth = 0
    i = branch_start
    while i < len(text):
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        ch = text[i]
        if ch in {'"', "'"}:
            i = _skip_short_string(text, i)
            continue
        if ch == "[":
            lb = _match_long_bracket(text, i)
            if lb is not None:
                i = _skip_long_bracket(text, i, lb)
                continue
        if text.startswith("if", i) and _is_boundary(text, i - 1) and _is_boundary(text, i + 2):
            depth += 1
            i += 2
            continue
        if text.startswith("end", i) and _is_boundary(text, i - 1) and _is_boundary(text, i + 3):
            if depth == 0:
                return i
            depth -= 1
            i += 3
            continue
        if depth == 0:
            if text.startswith("elseif", i) and _is_boundary(text, i - 1) and _is_boundary(text, i + 6):
                return i
            if text.startswith("else", i) and _is_boundary(text, i - 1) and _is_boundary(text, i + 4):
                return i
        i += 1
    return len(text)


def _iter_named_functions(text: str) -> Iterator[tuple[str, int, int, int]]:
    pattern = re.compile(r"(?:local\s+)?function\s+([A-Za-z_][\w\.:]*)\s*\(")
    for match in pattern.finditer(text):
        name = match.group(1)
        func_start = match.start()
        paren_index = text.find("(", match.end() - 1)
        if paren_index == -1:
            continue
        end_index = _find_matching_end(text, match.start())
        yield name, func_start, paren_index, end_index

    assign_pattern = re.compile(r"([A-Za-z_][\w\.:]*)\s*=\s*function\s*\(")
    for match in assign_pattern.finditer(text):
        name = match.group(1)
        func_start = match.start(0)
        paren_index = text.find("(", match.end() - 1)
        if paren_index == -1:
            continue
        end_index = _find_matching_end(text, match.start(0))
        yield name, func_start, paren_index, end_index


def _extract_calls(body: str) -> List[str]:
    calls: List[str] = []
    for match in _CALL_PATTERN.finditer(body):
        name = match.group(1)
        lower = name.lower()
        if any(keyword in lower for keyword in _SUSPECT_KEYWORDS):
            calls.append(name)
    return calls


def _normalise_opcode(value: str) -> Optional[int]:
    try:
        value = value.strip().lower()
        if value.startswith("0x"):
            return int(value, 16)
        return int(value, 10)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return None


def _find_handler_name(body: str) -> Optional[str]:
    depth = 0
    i = 0
    length = len(body)
    while i < length:
        if body.startswith("--", i):
            i = _skip_comment(body, i)
            continue
        ch = body[i]
        if ch in {'"', "'"}:
            i = _skip_short_string(body, i)
            continue
        if ch == "[":
            lb = _match_long_bracket(body, i)
            if lb is not None:
                i = _skip_long_bracket(body, i, lb)
                continue
        if body.startswith("if", i) and _is_boundary(body, i - 1) and _is_boundary(body, i + 2):
            depth += 1
            i += 2
            continue
        if body.startswith("end", i) and _is_boundary(body, i - 1) and _is_boundary(body, i + 3):
            if depth > 0:
                depth -= 1
            i += 3
            continue
        if depth == 0:
            if ch.isspace():
                i += 1
                continue
            match = _HANDLER_CALL_PATTERN.match(body, i)
            if match:
                candidate = match.group(1)
                if candidate.lower() not in {"if", "elseif", "end"}:
                    return candidate
                i = match.end()
                continue
        i += 1
    return None


def _build_function_map(text: str) -> Dict[str, str]:
    """Return a mapping from function name to body text (without the closing ``end``)."""

    mapping: Dict[str, str] = {}
    for name, _start, paren_index, end_index in _iter_named_functions(text):
        body_start = _find_balanced(text, paren_index)
        if body_start <= paren_index or body_start >= end_index:
            body = text[paren_index:end_index]
        else:
            body = text[body_start + 1 : end_index]
        mapping[name] = body
    return mapping


def _analyse_function(
    name: str,
    start: int,
    end: int,
    body: str,
) -> FunctionAnalysis:
    operations = _extract_transform_operations(body, base_offset=start)
    references = _collect_references(body)
    issues = _detect_runtime_constraints(body, base_offset=start)
    resolvable = not issues
    if not operations and resolvable:
        issues = ["no transform operations detected"]
        resolvable = False
    return FunctionAnalysis(
        name=name,
        start=start,
        end=end,
        resolvable=resolvable,
        operations=tuple(operations),
        issues=tuple(issues),
        references=tuple(references),
    )


def analyse_transform_snippet(
    text: str,
    *,
    base_offset: int = 0,
) -> List[FunctionAnalysis]:
    """Analyse a bootstrap snippet and return transform function descriptions."""

    analyses: List[FunctionAnalysis] = []
    function_map = _build_function_map(text)
    for name, start, _paren, end in _iter_named_functions(text):
        body = text[start:end]
        function_body = function_map.get(name, body)
        try:
            analysis = _analyse_function(
                name,
                base_offset + start,
                base_offset + end,
                function_body,
            )
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("failed to analyse function %s: %s", name, exc)
            analysis = FunctionAnalysis(
                name=name,
                start=base_offset + start,
                end=base_offset + end,
                resolvable=False,
                operations=(),
                issues=(f"exception during analysis: {exc}",),
                references=tuple(_collect_references(function_body)),
            )
        analyses.append(analysis)
    return analyses


def _sanitise_name(name: str) -> str:
    collapsed = re.sub(r"[^0-9A-Za-z_.-]+", "_", name)
    return collapsed.strip("._") or "candidate"


def emit_trace_reports(
    candidates: Sequence[Mapping[str, object]],
    *,
    output_dir: Path,
) -> List[Path]:
    """Write transform trace reports for each bootstrap candidate."""

    output_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for index, candidate in enumerate(candidates):
        snippet = candidate.get("snippet") if isinstance(candidate, Mapping) else None
        if not isinstance(snippet, str) or not snippet.strip():
            LOGGER.debug("Skipping candidate %s without snippet text", index)
            continue
        start_offset = int(candidate.get("start_offset", 0)) if isinstance(candidate, Mapping) else 0
        analyses = analyse_transform_snippet(snippet, base_offset=start_offset)
        base_name = (
            candidate.get("note")
            or candidate.get("type")
            or candidate.get("label")
            or f"candidate_{index:03d}"
        )
        file_name = f"{index:03d}_{_sanitise_name(str(base_name)) or 'candidate'}.json"
        payload = {
            "candidate": {
                "type": candidate.get("type"),
                "start_offset": start_offset,
                "end_offset": candidate.get("end_offset"),
                "confidence": candidate.get("confidence"),
                "note": candidate.get("note"),
            },
            "functions": [analysis.to_dict() for analysis in analyses],
        }
        target = output_dir / file_name
        target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(target)
        LOGGER.info("Wrote trace report for %s to %s", base_name, target)
    return written

def _guess_handler_mnemonics(handler: str, body: Optional[str]) -> List[str]:
    """Return mnemonic candidates for a handler based on textual heuristics."""

    candidates: List[str] = []
    observed: set[str] = set()
    name_lower = handler.lower()
    for fragment, mnemonic in _NAME_HINTS:
        if fragment in name_lower:
            observed.add(mnemonic)

    if body:
        lowered = body.lower()
        stack_assign = bool(_STACK_ASSIGN_PATTERN.search(body))
        stack_call = bool(_STACK_CALL_PATTERN.search(body))
        stack_compare = bool(_STACK_COMPARE_PATTERN.search(body))
        return_stack = bool(_RETURN_STACK_PATTERN.search(body))
        has_return = "return" in lowered
        constants = bool(_CONSTANT_PATTERN.search(lowered))
        pc_present = bool(_PC_TOKEN_PATTERN.search(lowered))
        pc_update = bool(_PC_UPDATE_PATTERN.search(lowered))
        jump_keyword = bool(_JUMP_KEYWORD_PATTERN.search(lowered))
        call_keyword = bool(_CALL_KEYWORD_PATTERN.search(lowered)) or "invoke" in lowered
        eq_keyword = bool(_EQ_KEYWORD_PATTERN.search(lowered))
        has_if = "if" in lowered

        if stack_assign and constants:
            observed.add("LOADK")
        if stack_call or call_keyword:
            observed.add("CALL")
        if has_return and (return_stack or stack_call or "nresults" in lowered):
            observed.add("RETURN")
        if pc_present and (pc_update or jump_keyword):
            observed.add("JMP")
        elif jump_keyword and has_if:
            observed.add("JMP")
        if stack_compare and has_if:
            observed.add("EQ")
        elif eq_keyword and has_if:
            observed.add("EQ")

        try:
            from src.vm.compare_handlers import compare_handler_bytes

            comparisons = compare_handler_bytes(body.encode("latin-1", errors="ignore"))
        except Exception:  # pragma: no cover - optional dependency or import failure
            comparisons = []
        for comparison in comparisons:
            if comparison.score >= 0.6:
                observed.add(comparison.mnemonic)

    for mnemonic in _MNEMONIC_ORDER:
        if mnemonic in observed:
            candidates.append(mnemonic)

    return candidates


def match_handler_patterns(text: str, opcode_name: Optional[str] = None) -> List[HandlerMatch]:
    """Locate ``if opcode == N then handler()`` dispatch patterns."""

    matches: List[HandlerMatch] = []
    chosen_var: Optional[str] = opcode_name

    active_branch_end = -1

    function_map = _build_function_map(text)

    for branch in _BRANCH_PATTERN.finditer(text):
        body_start = branch.end()
        body_end = _find_branch_terminus(text, body_start)
        if branch.start() < active_branch_end:
            continue
        active_branch_end = max(active_branch_end, body_end)
        var_name = branch.group(2)
        if chosen_var is None:
            chosen_var = var_name
        elif var_name != chosen_var:
            continue

        opcode_value = _normalise_opcode(branch.group(3))
        if opcode_value is None:
            continue

        handler_name = _find_handler_name(text[body_start:body_end])
        if handler_name is None:
            continue
        body_text = function_map.get(handler_name)
        mnemonic_candidates = tuple(_guess_handler_mnemonics(handler_name, body_text))
        matches.append(
            HandlerMatch(
                opcode=opcode_value,
                handler=handler_name,
                start=branch.start(),
                end=body_end,
                mnemonics=mnemonic_candidates,
                body=body_text,
            )
        )

    return matches


def trace_pipeline_functions(text: str) -> List[FunctionTrace]:
    """Trace bootstrap helper functions and calls to decoding/permute helpers.

    The tracer relies purely on textual analysis.  It recognises named function
    declarations (``function name(...)`` and ``name = function(...)``) and
    searches their bodies for call expressions that reference keywords typically
    used in decode pipelines.  The resulting call list is suitable for feeding
    into higher level heuristics without running the obfuscated payload.
    """

    traces: List[FunctionTrace] = []
    for name, func_start, paren_index, end_index in _iter_named_functions(text):
        body = text[paren_index:end_index]
        calls = _extract_calls(body)
        if not calls:
            continue
        traces.append(FunctionTrace(name=name, start=func_start, end=end_index, calls=calls))

    if not traces:
        LOGGER.debug("No matching functions found during static tracing")

    return traces


def _load_candidate_file(path: Path) -> Sequence[Mapping[str, object]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(f"candidate file not found: {path}")
    data = json.loads(raw)
    if not isinstance(data, list):
        raise SystemExit("expected candidate JSON list")
    return data


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for emitting transform trace reports."""

    parser = argparse.ArgumentParser(description="Trace bootstrap transform functions")
    parser.add_argument("candidates", help="Path to bootstrap_candidates.json")
    parser.add_argument(
        "--output-dir",
        default=Path("out/trace"),
        type=Path,
        help="Directory for trace JSON artefacts (default: out/trace)",
    )
    args = parser.parse_args(argv)

    candidates_path = Path(args.candidates)
    candidates = _load_candidate_file(candidates_path)
    emit_trace_reports(candidates, output_dir=args.output_dir)
    LOGGER.info("Trace reports written to %s", args.output_dir)
    return 0

