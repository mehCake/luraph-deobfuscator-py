"""Collapse adjacent string literals emitted as CONCAT chains."""

from __future__ import annotations

import re
from typing import Dict, List, Tuple, TYPE_CHECKING

from ..utils import parse_escaped_lua_string

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..pipeline import Context


_LITERAL_PATTERN = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
_LITERAL_RE = re.compile(_LITERAL_PATTERN)
_CONCAT_RE = re.compile(
    rf'(?P<seq>(?:{_LITERAL_PATTERN})(?:\s*\.\.\s*(?:{_LITERAL_PATTERN}))+)'
)


def _bytes_to_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin1", errors="replace")


def _decode_literal(token: str) -> Tuple[str, str] | None:
    if len(token) < 2 or token[0] not in {'"', "'"}:
        return None
    quote = token[0]
    body = token[1:-1]
    needs_decode = body.startswith(("LPH!", "lph!", "LPH@", "lph@", "LPH_", "lph_")) or "\\" in body
    if needs_decode:
        try:
            raw = parse_escaped_lua_string(body)
        except Exception:
            raw = body.encode("latin1", errors="ignore")
    else:
        raw = body.encode("latin1", errors="ignore")
    if isinstance(raw, str):  # pragma: no cover - defensive fallback
        value = raw
    else:
        value = _bytes_to_text(bytes(raw))
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return value, quote


def _encode_literal(value: str, quote: str) -> str:
    preferred = quote if quote in {'"', "'"} else '"'
    escaped = (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    if preferred == "'":
        escaped = escaped.replace("'", "\\'")
    else:
        escaped = escaped.replace('"', '\\"')
    return f"{preferred}{escaped}{preferred}"


def _extract_literals(sequence: str) -> List[str]:
    literals: List[str] = []
    idx = 0
    length = len(sequence)
    while idx < length:
        match = _LITERAL_RE.match(sequence, idx)
        if not match:
            idx += 1
            continue
        literals.append(match.group(0))
        idx = match.end()
        while idx < length and sequence[idx].isspace():
            idx += 1
        if sequence.startswith("..", idx):
            idx += 2
        while idx < length and sequence[idx].isspace():
            idx += 1
    return literals


def _collapse_concatenations(source: str) -> Tuple[str, int, int]:
    collapsed = 0
    decoded_segments = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal collapsed, decoded_segments
        seq = match.group("seq")
        parts = _extract_literals(seq)
        if len(parts) < 2:
            return match.group(0)
        decoded_values: List[str] = []
        quotes: List[str] = []
        for part in parts:
            decoded = _decode_literal(part)
            if decoded is None:
                return match.group(0)
            value, quote = decoded
            if _encode_literal(value, quote) != part:
                decoded_segments += 1
            decoded_values.append(value)
            quotes.append(quote)
        collapsed += len(parts) - 1
        base_quote = quotes[0]
        combined = "".join(decoded_values)
        return _encode_literal(combined, base_quote)

    updated = _CONCAT_RE.sub(repl, source)
    return updated, collapsed, decoded_segments


def run(ctx: "Context") -> Dict[str, object]:
    text = ctx.stage_output or ctx.working_text or ctx.raw_input
    if not text:
        ctx.stage_output = ""
        return {"empty": True}

    metadata: Dict[str, object] = {"input_length": len(text)}

    folded, collapsed, decoded = _collapse_concatenations(text)
    metadata["collapsed_concats"] = collapsed
    metadata["decoded_segments"] = decoded
    metadata["changed"] = folded != text
    metadata["output_length"] = len(folded)

    ctx.stage_output = folded
    return metadata


__all__ = ["run"]
