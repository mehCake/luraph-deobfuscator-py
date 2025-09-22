"""Reconstruct readable Lua fragments from obfuscated string literals."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Dict, List, Tuple, TYPE_CHECKING

from .. import utils

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..pipeline import Context


_LITERAL_PATTERN = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
_LITERAL_RE = re.compile(_LITERAL_PATTERN)
_CONCAT_RE = re.compile(
    rf'(?P<seq>(?:{_LITERAL_PATTERN})(?:\s*\.\.\s*(?:{_LITERAL_PATTERN}))+)'
)
_DECIMAL_RE = re.compile(r"(?<!\\)\\(\d{2,3})")
_HEX_RE = re.compile(r"(?<!\\)\\x([0-9A-Fa-f]{2})")
_UNICODE_RE = re.compile(r"\\u\{([0-9A-Fa-f]+)\}")
_HEX_BODY_RE = re.compile(r"^[0-9A-Fa-f]{8,}$")
_BASE64_BODY_RE = re.compile(r"^[A-Za-z0-9+/=_-]{12,}$")
_LIKELY_CODE_TOKENS = (
    "function",
    "local ",
    "return",
    "for ",
    "while ",
    "if ",
    "then",
    "end",
)


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text)


def _decode_decimal_sequences(value: str) -> Tuple[str, bool]:
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        payload = match.group(1)
        try:
            number = int(payload, 10)
        except ValueError:
            return match.group(0)
        if number < 0 or number > 0x10FFFF:
            return match.group(0)
        changed = True
        try:
            return chr(number)
        except ValueError:
            return chr(number & 0x10FFFF)

    return _DECIMAL_RE.sub(repl, value), changed


def _decode_hex_sequences(value: str) -> Tuple[str, bool]:
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        payload = match.group(1)
        try:
            number = int(payload, 16)
        except ValueError:
            return match.group(0)
        changed = True
        return chr(number)

    return _HEX_RE.sub(repl, value), changed


def _decode_unicode_sequences(value: str) -> Tuple[str, bool]:
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        payload = match.group(1)
        try:
            number = int(payload, 16)
        except ValueError:
            return match.group(0)
        if number < 0 or number > 0x10FFFF:
            return match.group(0)
        changed = True
        return chr(number)

    return _UNICODE_RE.sub(repl, value), changed


def _decode_escape_sequences(value: str) -> Tuple[str, bool]:
    replacements = 0
    pieces: List[str] = []
    i = 0
    length = len(value)
    escape_map = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "\n": "",
        "\r": "",
        "\\": "\\",
        '"': '"',
        "'": "'",
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "v": "\v",
        "0": "\0",
    }

    while i < length:
        ch = value[i]
        if ch != "\\":
            pieces.append(ch)
            i += 1
            continue
        if i + 1 >= length:
            pieces.append("\\")
            break
        nxt = value[i + 1]
        if nxt in escape_map:
            pieces.append(escape_map[nxt])
            i += 2
            replacements += 1
            continue
        if nxt.lower() == "x" and i + 3 < length:
            candidate = value[i + 2 : i + 4]
            if all(char in "0123456789abcdefABCDEF" for char in candidate):
                pieces.append(chr(int(candidate, 16)))
                i += 4
                replacements += 1
                continue
        if nxt == "u" and i + 3 < length and value[i + 2] == "{":
            j = i + 3
            hex_digits: List[str] = []
            while j < length and value[j] != "}":
                hex_digits.append(value[j])
                j += 1
            if j < length and hex_digits:
                try:
                    pieces.append(chr(int("".join(hex_digits), 16)))
                    replacements += 1
                    i = j + 1
                    continue
                except ValueError:
                    pass
        if nxt.isdigit():
            j = i + 1
            digits: List[str] = []
            while j < length and value[j].isdigit() and len(digits) < 3:
                digits.append(value[j])
                j += 1
            if digits:
                try:
                    pieces.append(chr(int("".join(digits), 10)))
                    replacements += 1
                    i = j
                    continue
                except ValueError:
                    pass
        pieces.append(ch)
        i += 1

    return "".join(pieces), replacements > 0


def _decode_literal_content(body: str) -> Tuple[str, bool]:
    content, changed = _decode_escape_sequences(body)
    decimal_decoded, decimal_changed = _decode_decimal_sequences(content)
    if decimal_changed:
        content = decimal_decoded
        changed = True
    hex_decoded, hex_changed = _decode_hex_sequences(content)
    if hex_changed:
        content = hex_decoded
        changed = True
    unicode_decoded, unicode_changed = _decode_unicode_sequences(content)
    if unicode_changed:
        content = unicode_decoded
        changed = True
    return content, changed


def _looks_like_base64(candidate: str) -> bool:
    if len(candidate) < 16:
        return False
    if not _BASE64_BODY_RE.fullmatch(candidate):
        return False
    if any(ch in "+/=" for ch in candidate):
        return True
    if any(ch.isdigit() for ch in candidate):
        return True
    if any(ch.isupper() for ch in candidate):
        return True
    return False


def _decode_high_entropy(value: str) -> Tuple[str, bool]:
    stripped = value.strip()
    compact = "".join(ch for ch in stripped if not ch.isspace())
    if len(compact) < 8:
        return value, False
    if _HEX_BODY_RE.fullmatch(compact) and len(compact) % 2 == 0:
        try:
            decoded = bytes.fromhex(compact)
        except (ValueError, binascii.Error):
            decoded = b""
        if decoded:
            text = decoded.decode("utf-8", errors="replace")
            if _printable_ratio(text) >= 0.85:
                return text, True
    if _looks_like_base64(compact):
        padded = compact + "=" * (-len(compact) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
        except (ValueError, binascii.Error):
            decoded = b""
        if decoded:
            text = decoded.decode("utf-8", errors="replace")
            if _printable_ratio(text) >= 0.85:
                return text, True
    return value, False


def _choose_long_brackets(text: str) -> Tuple[str, str] | None:
    eq_count = 0
    while eq_count < 10:
        delim = "=" * eq_count
        closing = f"]{delim}]"
        if closing not in text:
            opening = f"[{delim}["
            return opening, closing
        eq_count += 1
    return None


def _looks_like_code(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 16:
        return False
    if stripped.startswith("--"):
        return True
    return any(token in stripped for token in _LIKELY_CODE_TOKENS)


def _encode_literal(value: str, original_quote: str) -> Tuple[str, bool]:
    multiline = "\n" in value or "\r" in value
    looks_like_code = _looks_like_code(value)
    if multiline or looks_like_code:
        brackets = _choose_long_brackets(value)
        if brackets is not None:
            opening, closing = brackets
            return f"{opening}{value}{closing}", True
    quote = original_quote if original_quote in "'\"" else '"'
    escaped = (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    if quote == "'":
        escaped = escaped.replace("'", "\\'")
    else:
        escaped = escaped.replace('"', '\\"')
    return f"{quote}{escaped}{quote}", False


def _collapse_concatenations(source: str) -> Tuple[str, int, int]:
    count = 0
    decoded_segments = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal count, decoded_segments
        seq = match.group("seq")
        parts = [m.group(0) for m in _LITERAL_RE.finditer(seq)]
        decoded: List[str] = []
        for part in parts:
            value, changed = _decode_literal_content(part[1:-1])
            if changed:
                decoded_segments += 1
            decoded.append(value)
        if len(decoded) < 2:
            return match.group(0)
        count += len(decoded) - 1
        combined = "".join(decoded)
        encoded, _ = _encode_literal(combined, parts[0][0])
        return encoded

    updated = _CONCAT_RE.sub(repl, source)
    return updated, count, decoded_segments


def _rewrite_literals(source: str) -> Tuple[str, Dict[str, int]]:
    result: List[str] = []
    last = 0
    stats = {
        "decoded_literals": 0,
        "entropy_literals": 0,
        "promoted_literals": 0,
    }

    for match in _LITERAL_RE.finditer(source):
        start, end = match.span()
        result.append(source[last:start])
        literal = match.group(0)
        quote = literal[0]
        body = literal[1:-1]
        value, decoded = _decode_literal_content(body)
        entropy_value, entropy_changed = _decode_high_entropy(value)
        if entropy_changed:
            value = entropy_value
        encoded, promoted = _encode_literal(value, quote)
        if decoded:
            stats["decoded_literals"] += 1
        if entropy_changed:
            stats["entropy_literals"] += 1
        if promoted:
            stats["promoted_literals"] += 1
        result.append(encoded)
        last = end

    result.append(source[last:])
    return "".join(result), stats


def run(ctx: "Context") -> Dict[str, object]:
    ctx.ensure_raw_input()
    text = ctx.stage_output or ctx.working_text or ctx.raw_input
    if not text:
        ctx.stage_output = ""
        return {"empty": True}

    metadata: Dict[str, object] = {"input_length": len(text)}

    collapsed, concatenations, collapsed_decoded = _collapse_concatenations(text)
    metadata["concatenations_collapsed"] = concatenations

    rewritten, stats = _rewrite_literals(collapsed)
    stats["decoded_literals"] += collapsed_decoded
    metadata.update(stats)

    cleaned = utils.strip_non_printable(rewritten)
    metadata["output_length"] = len(cleaned)
    metadata["changed"] = cleaned != text

    ctx.stage_output = cleaned

    return metadata


__all__ = ["run"]

