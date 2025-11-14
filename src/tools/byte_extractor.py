"""Helpers for converting extracted payload fragments into raw bytes."""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import logging
import re
from pathlib import Path
from typing import List, Sequence

from .heuristics import detect_endianness
from .safe_eval_stub import eval_expr

__all__ = [
    "decode_candidate_snippet",
    "extract_bytes",
    "from_escaped_string",
    "from_numeric_table",
    "from_string_char",
    "generate_candidate_bytes",
    "main",
]

LOGGER = logging.getLogger(__name__)

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_BASE32_RE = re.compile(r"^[A-Z2-7=\s]+$", re.IGNORECASE)
_BASE85_RE = re.compile(r"^[\x21-\x7E\s]+$")

_SIMPLE_ESCAPES = {
    "\\": b"\\",
    '"': b'"',
    "'": b"'",
    "n": b"\n",
    "r": b"\r",
    "t": b"\t",
    "a": b"\a",
    "b": b"\b",
    "f": b"\f",
    "v": b"\v",
    "0": b"\0",
}


def _strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] in {'"', "'"} and text[-1] == text[0]:
        return text[1:-1]
    return text


def from_escaped_string(text: str) -> bytes:
    """Decode common escape sequences found in Lua string literals."""

    text = _strip_quotes(text)
    result = bytearray()
    i = 0
    length = len(text)
    while i < length:
        char = text[i]
        if char != "\\":
            result.append(ord(char))
            i += 1
            continue

        i += 1
        if i >= length:
            raise ValueError("dangling escape sequence")
        esc = text[i]

        if esc in _SIMPLE_ESCAPES:
            result.extend(_SIMPLE_ESCAPES[esc])
            i += 1
            continue

        if esc in {"x", "X"}:
            if i + 2 > length:
                raise ValueError("incomplete hex escape")
            hex_digits = text[i + 1 : i + 3]
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", hex_digits):
                raise ValueError(f"invalid hex escape: {hex_digits!r}")
            result.append(int(hex_digits, 16))
            i += 3
            continue

        if esc.isdigit():
            digits = esc
            i += 1
            while i < length and len(digits) < 3 and text[i].isdigit():
                digits += text[i]
                i += 1
            result.append(int(digits, 10) & 0xFF)
            continue

        # Unknown escapes are treated literally to mirror Lua's permissive parser
        result.append(ord(esc))
        i += 1

    return bytes(result)


def from_string_char(expression: str) -> bytes:
    """Evaluate a ``string.char`` expression into raw bytes."""

    expression = _expand_table_unpack(expression)
    value = eval_expr(expression)
    if isinstance(value, str):
        return value.encode("latin-1")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, Sequence):
        return bytes(int(item) & 0xFF for item in value)
    raise TypeError("string.char expression did not resolve to a string or sequence")


def _parse_numeric(value: str) -> int:
    value = value.strip()
    if not value:
        raise ValueError("empty element in numeric table")
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    if value.startswith("0b") or value.startswith("0B"):
        return int(value, 2)
    if value.startswith("0o") or value.startswith("0O"):
        return int(value, 8)
    return int(value, 10)


def _split_top_level(text: str, separator: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    depth_paren = depth_brace = depth_bracket = 0
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch in {'"', "'"}:
            end = _skip_string(text, i)
            current.append(text[i:end])
            i = end
            continue
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "{":
            depth_brace += 1
        elif ch == "}":
            depth_brace = max(0, depth_brace - 1)
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket = max(0, depth_bracket - 1)

        if (
            separator == ".."
            and ch == "."
            and i + 1 < length
            and text[i + 1] == "."
            and depth_paren == depth_brace == depth_bracket == 0
        ):
            parts.append("".join(current).strip())
            current = []
            i += 2
            continue

        if (
            separator == ","
            and ch == ","
            and depth_paren == depth_brace == depth_bracket == 0
        ):
            parts.append("".join(current).strip())
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _skip_string(text: str, start: int) -> int:
    quote = text[start]
    i = start + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(text)


def _find_matching(text: str, index: int, open_char: str, close_char: str) -> int:
    depth = 0
    i = index
    while i < len(text):
        ch = text[i]
        if ch in {'"', "'"}:
            i = _skip_string(text, i)
            continue
        if ch == open_char:
            depth += 1
        elif ch == close_char:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _expand_table_unpack(expression: str) -> str:
    result: List[str] = []
    index = 0
    while True:
        match = re.search(r"(?:(?:table\.)?unpack)\s*\(", expression[index:])
        if not match:
            result.append(expression[index:])
            break
        start = index + match.start()
        paren_index = start + match.group(0).rfind("(")
        end = _find_matching(expression, paren_index, "(", ")")
        if end == -1:
            result.append(expression[index:])
            break
        result.append(expression[index:start])
        args_text = expression[paren_index + 1 : end]
        replacement = _convert_unpack_args(args_text)
        if replacement is None:
            result.append(expression[start : end + 1])
        else:
            result.append(replacement)
        index = end + 1
    return "".join(result)


def _convert_unpack_args(args_text: str) -> str | None:
    parts = _split_top_level(args_text, ",")
    if not parts:
        return None
    table_text = parts[0].strip()
    if not table_text.startswith("{") or not table_text.endswith("}"):
        return None
    try:
        values = list(from_numeric_table(table_text))
    except ValueError:
        return None

    start_index = 1
    end_index = len(values)
    if len(parts) >= 2:
        try:
            start_index = max(1, _parse_numeric(parts[1]))
        except ValueError:
            start_index = 1
    if len(parts) >= 3:
        try:
            end_index = max(start_index, _parse_numeric(parts[2]))
        except ValueError:
            end_index = len(values)

    # Lua indices are 1-based and the end argument is inclusive.
    start_idx = max(0, start_index - 1)
    end_idx = min(len(values), end_index)
    sliced = values[start_idx:end_idx]
    return ",".join(str(num) for num in sliced)


def from_numeric_table(table_literal: str) -> bytes:
    """Convert a Lua-like numeric table literal to raw bytes."""

    inner = table_literal.strip()
    if not (inner.startswith("{") and inner.endswith("}")):
        raise ValueError("numeric table must be wrapped in braces")
    inner = inner[1:-1]

    if not inner.strip():
        return b""

    parts = re.split(r",|;", inner)
    values = []
    for part in parts:
        number = _parse_numeric(part)
        if number < 0 or number > 0xFF:
            raise ValueError(f"table element out of byte range: {number}")
        values.append(number & 0xFF)
    return bytes(values)


def _try_base_decoders(text: str) -> bytes | None:
    compact = re.sub(r"\s+", "", text)
    if not compact:
        return b""

    if _BASE64_RE.fullmatch(compact) and len(compact) % 4 == 0:
        try:
            return base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            pass

    if _BASE32_RE.fullmatch(compact):
        try:
            return base64.b32decode(compact, casefold=True)
        except (binascii.Error, ValueError):
            pass

    if _BASE85_RE.fullmatch(compact):
        for decoder in (base64.a85decode, base64.b85decode):
            try:
                return decoder(compact)
            except (binascii.Error, ValueError):
                continue
    return None


def extract_bytes(text: str) -> bytes:
    """Attempt to decode *text* using the supported formats."""

    stripped = text.strip()
    if stripped.startswith("string.char"):
        return from_string_char(stripped)

    if stripped.startswith("{") and stripped.endswith("}"):
        return from_numeric_table(stripped)

    if "\\x" in stripped or "\\" in stripped:
        try:
            return from_escaped_string(stripped)
        except ValueError:
            pass

    base = _try_base_decoders(stripped)
    if base is not None:
        return base

    # Fallback: treat as a plain quoted string or raw text.
    try:
        return stripped.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise ValueError("unable to interpret payload as bytes") from exc


def _slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^0-9a-z]+", "-", text)
    text = text.strip("-")
    return text or "chunk"


def _extract_payload_expression(snippet: str) -> str | None:
    snippet = snippet.strip()
    if not snippet:
        return None
    for func in ("loadstring", "load"):
        pattern = re.compile(rf"{func}\s*\(", re.IGNORECASE)
        match = pattern.search(snippet)
        if not match:
            continue
        paren_index = match.end() - 1
        end = _find_matching(snippet, paren_index, "(", ")")
        if end == -1:
            continue
        return snippet[paren_index + 1 : end]
    return snippet


def _decode_concatenated_expression(expr: str) -> bytes:
    parts = _split_top_level(expr, "..") or [expr]
    output = bytearray()
    for part in parts:
        if not part:
            continue
        output.extend(extract_bytes(part))
    return bytes(output)


def decode_candidate_snippet(snippet: str) -> bytes:
    expression = _extract_payload_expression(snippet)
    if expression is None:
        raise ValueError("snippet did not contain a decodable expression")
    return _decode_concatenated_expression(expression)


def generate_candidate_bytes(
    candidates_path: str | Path,
    output_dir: str | Path,
    *,
    meta_filename: str = "meta.json",
) -> list[dict]:
    path = Path(candidates_path)
    out_root = Path(output_dir)
    bytes_dir = out_root / "bytes"
    bytes_dir.mkdir(parents=True, exist_ok=True)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - invalid input
        raise ValueError(f"failed to parse {path}: {exc}") from exc

    if not isinstance(data, list):
        raise TypeError("bootstrap candidate report must be a list")

    metadata: list[dict] = []
    for index, candidate in enumerate(data):
        if not isinstance(candidate, dict):
            continue
        snippet = str(candidate.get("snippet", ""))
        name = _slugify(str(candidate.get("type", "candidate")))
        file_name = f"{index:03d}_{name}.bin"
        file_path = bytes_dir / file_name

        try:
            payload = decode_candidate_snippet(snippet)
        except Exception as exc:  # pragma: no cover - logging path
            LOGGER.debug("Failed to decode snippet %s: %s", name, exc)
            payload = b""

        file_path.write_bytes(payload)
        endian_kind, endian_score = detect_endianness(payload)

        entry = {
            "name": file_name,
            "type": candidate.get("type", "unknown"),
            "path": str(file_path),
            "size": len(payload),
            "endianness_hint": endian_kind,
            "endianness_score": round(float(endian_score), 4),
            "start_offset": candidate.get("start_offset"),
            "end_offset": candidate.get("end_offset"),
            "confidence": candidate.get("confidence"),
        }
        metadata.append(entry)
        LOGGER.info(
            "Wrote %s (%d bytes, endianness=%s)",
            file_path,
            len(payload),
            endian_kind,
        )

    meta_path = bytes_dir / meta_filename
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode bootstrap candidate payloads")
    parser.add_argument(
        "candidates",
        help="Path to bootstrap_candidates.json",
    )
    parser.add_argument(
        "--output-dir",
        default=Path("out"),
        type=Path,
        help="Destination directory (default: out)",
    )
    parser.add_argument(
        "--meta-name",
        default="meta.json",
        help="Name of the metadata file (default: meta.json)",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        generate_candidate_bytes(args.candidates, args.output_dir, meta_filename=args.meta_name)
    except Exception as exc:  # pragma: no cover - CLI error path
        LOGGER.error("Failed to generate candidate bytes: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
