"""High level helpers for collapsing layered string obfuscation.

Luraph payloads routinely nest several simple ciphers: hex encoded blobs that
are base64 wrapped, XORed with rolling keys, finally executed via
``loadstring`` or hand written closures.  The :class:`StringDecryptor` class
walks a piece of Lua source code and gradually replaces those constructions
with plain literals so later passes can operate on the simplified program.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Callable, List, Optional, Sequence

from lua_literal_parser import LuaTable, parse_lua_expression


def _looks_printable(value: str) -> bool:
    printable = sum(ch.isprintable() for ch in value)
    return printable / max(len(value), 1) > 0.85


def _split_args(arguments: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(arguments):
        ch = arguments[i]
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(arguments[start:i].strip())
            start = i + 1
        i += 1
    tail = arguments[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _split_concat(expr: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "." and i + 1 < len(expr) and expr[i + 1] == "." and depth == 0:
            segment = expr[start:i].strip()
            if segment:
                parts.append(segment)
            i += 2
            start = i
            continue
        i += 1
    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _unwrap_parentheses(expr: str) -> str:
    expr = expr.strip()
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        balanced = True
        for i, ch in enumerate(expr):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(expr) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            expr = expr[1:-1].strip()
        else:
            break
    return expr


def _decode_hex_literal(value: str) -> Optional[str]:
    if len(value) % 2:
        return None
    try:
        decoded = bytes.fromhex(value)
        text = decoded.decode("utf-8", errors="replace")
        return text if _looks_printable(text) else None
    except (ValueError, binascii.Error):
        return None


def _decode_base64_literal(value: str) -> Optional[str]:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode("utf-8", errors="replace")
    except (ValueError, binascii.Error):
        return None
    return text if _looks_printable(text) else None


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _rotl(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) & 0xFF) | (value >> (8 - shift))


def _rotr(value: int, shift: int) -> int:
    shift &= 7
    return ((value >> shift) | ((value << (8 - shift)) & 0xFF)) & 0xFF


def _decode_stream(op: str, payload: str, key: str) -> Optional[str]:
    data = payload.encode("latin-1", errors="ignore")
    key_bytes = key.encode("latin-1", errors="ignore")
    if not data or not key_bytes:
        return None
    if "xor" in op:
        result = _xor_bytes(data, key_bytes)
    elif "add" in op:
        key_ints = [kb for kb in key_bytes]
        result = bytes((b - key_ints[i % len(key_ints)]) & 0xFF for i, b in enumerate(data))
    elif "rol" in op:
        shift = key_bytes[0]
        result = bytes(_rotr(b, shift) for b in data)
    elif "ror" in op:
        shift = key_bytes[0]
        result = bytes(_rotl(b, shift) for b in data)
    else:
        return None
    text = result.decode("utf-8", errors="replace")
    return text if _looks_printable(text) else None


def _evaluate_expression(expr: str) -> Optional[str]:
    expr = _unwrap_parentheses(expr)
    concat_parts = _split_concat(expr)
    if len(concat_parts) > 1:
        pieces: List[str] = []
        for part in concat_parts:
            evaluated = _evaluate_expression(part)
            if evaluated is None:
                return None
            pieces.append(evaluated)
        return "".join(pieces)

    if expr.startswith("string.char") and expr.endswith(")"):
        args = _split_args(expr[len("string.char(") : -1])
        chars: List[str] = []
        for arg in args:
            try:
                value = parse_lua_expression(arg)
            except ValueError:
                return None
            if not isinstance(value, (int, float)):
                return None
            chars.append(chr(int(value) & 0xFF))
        text = "".join(chars)
        return text if _looks_printable(text) else None

    if expr.startswith("table.concat") and expr.endswith(")"):
        args = _split_args(expr[len("table.concat(") : -1])
        if not args:
            return None
        try:
            table_value = parse_lua_expression(args[0])
        except ValueError:
            return None
        if not isinstance(table_value, LuaTable):
            return None
        sep = ""
        if len(args) > 1:
            sep_value = _evaluate_expression(args[1])
            if sep_value is not None:
                sep = sep_value
        strings: List[str] = []
        for idx in range(1, len(table_value.array) + 1):
            try:
                value = table_value.get(idx)
            except KeyError:
                continue
            literal = _evaluate_table_value(value)
            if literal is None:
                return None
            strings.append(literal)
        text = sep.join(strings)
        return text if _looks_printable(text) else None

    try:
        literal = parse_lua_expression(expr)
    except ValueError:
        return None
    if isinstance(literal, str):
        return literal
    return None


def _evaluate_table_value(value: object) -> Optional[str]:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return chr(int(value) & 0xFF)
    if isinstance(value, LuaTable):
        joined = []
        for idx in range(1, len(value.array) + 1):
            try:
                joined.append(_evaluate_table_value(value.get(idx)) or "")
            except KeyError:
                continue
        candidate = "".join(joined)
        return candidate if candidate else None
    return None


class StringDecryptor:
    """Apply a series of heuristics to simplify encrypted string blobs."""

    def __init__(self) -> None:
        self._passes: Sequence[Callable[[str], str]] = (
            self._decode_hex_chunks,
            self._decode_base64_chunks,
            self._decode_stream_calls,
            self._decode_escape_sequences,
            self._fold_inline_closures,
            self._decode_load_wrappers,
        )

    def decrypt(self, code: str) -> str:
        previous = None
        current = code
        while previous != current:
            previous = current
            for func in self._passes:
                try:
                    updated = func(current)
                except Exception:
                    continue
                current = updated
        return current

    # Individual passes -------------------------------------------------
    def _decode_hex_chunks(self, code: str) -> str:
        pattern = re.compile(r'(\b[0-9A-Fa-f]{8,}\b)')

        def repl(match: re.Match[str]) -> str:
            candidate = match.group(1)
            decoded = _decode_hex_literal(candidate)
            return decoded if decoded is not None else candidate

        return pattern.sub(repl, code)

    def _decode_base64_chunks(self, code: str) -> str:
        literal_pattern = re.compile(r'(["\'])([A-Za-z0-9+/=_-]{12,})\1')

        def decode_literal(match: re.Match[str]) -> str:
            quote, payload = match.groups()
            decoded = _decode_base64_literal(payload)
            if decoded is None:
                return match.group(0)
            escaped = decoded.replace("\\", "\\\\").replace(quote, f"\\{quote}")
            return f"{quote}{escaped}{quote}"

        code = literal_pattern.sub(decode_literal, code)

        call_pattern = re.compile(
            r'(?:base64|b64)[._]?(?:decode|dec|Decode)\s*\(\s*(["\'])(.*?)\1\s*\)'
        )

        def decode_call(match: re.Match[str]) -> str:
            quote, payload = match.groups()
            decoded = _decode_base64_literal(payload)
            if decoded is None:
                return match.group(0)
            escaped = decoded.replace("\\", "\\\\").replace(quote, f"\\{quote}")
            return f"{quote}{escaped}{quote}"

        return call_pattern.sub(decode_call, code)

    def _decode_stream_calls(self, code: str) -> str:
        pattern = re.compile(
            r'([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(["\'])(.*?)\2\s*,\s*(["\'])(.*?)\4\s*\)'
        )

        def repl(match: re.Match[str]) -> str:
            func_name, _, payload, __, key = match.groups()
            lowered = func_name.lower()
            decoded = _decode_stream(lowered, payload, key)
            if decoded is None:
                return match.group(0)
            escaped = decoded.replace("\\", "\\\\").replace("\"", "\\\"")
            return f'"{escaped}"'

        return pattern.sub(repl, code)

    def _decode_escape_sequences(self, code: str) -> str:
        def replace_hex(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        def replace_octal(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 8))
            except ValueError:
                return match.group(0)

        def replace_unicode(match: re.Match[str]) -> str:
            try:
                return chr(int(match.group(1), 16))
            except ValueError:
                return match.group(0)

        code = re.sub(r'\\x([0-9A-Fa-f]{2})', replace_hex, code)
        code = re.sub(r'\\([0-7]{1,3})', replace_octal, code)
        code = re.sub(r'\\u\{([0-9A-Fa-f]+)\}', replace_unicode, code)
        return code

    def _fold_inline_closures(self, code: str) -> str:
        pattern = re.compile(r'\(function\s*\(\s*\)\s*(.*?)end\)\s*\(\s*\)', re.DOTALL)

        def repl(match: re.Match[str]) -> str:
            body = match.group(1)
            ret_idx = body.find("return")
            if ret_idx == -1:
                return match.group(0)
            expr_start = ret_idx + len("return")
            depth = 0
            i = expr_start
            expr_end = len(body)
            while i < len(body):
                ch = body[i]
                if ch in "({[":
                    depth += 1
                elif ch in ")}]":
                    depth -= 1
                elif depth == 0 and body.startswith("end", i):
                    expr_end = i
                    break
                elif depth == 0 and body[i] == ";":
                    expr_end = i
                    break
                i += 1
            expr = body[expr_start:expr_end].strip()
            evaluated = _evaluate_expression(expr)
            if evaluated is None:
                return match.group(0)
            escaped = evaluated.replace("\\", "\\\\").replace("\"", "\\\"")
            return f'"{escaped}"'

        return pattern.sub(repl, code)

    def _decode_load_wrappers(self, code: str) -> str:
        pattern = re.compile(
            r'(?:loadstring|load)\s*\(\s*(["\'])(.*?)\1\s*(?:,\s*[^)]*)?\)\s*\(\s*\)'
        )

        def repl(match: re.Match[str]) -> str:
            quote, payload = match.groups()
            try:
                inner = payload.encode("utf-8").decode("unicode_escape")
            except UnicodeDecodeError:
                inner = payload
            decrypted = self.decrypt(inner)
            escaped = decrypted.replace("\\", "\\\\").replace(quote, f"\\{quote}")
            return f"{quote}{escaped}{quote}"

        return pattern.sub(repl, code)


__all__ = ["StringDecryptor"]

