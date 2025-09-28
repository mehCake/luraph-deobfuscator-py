"""Utilities for decoding Luraph ``LPH_String`` payloads."""

from __future__ import annotations

import re
import string
from typing import Optional

__all__ = ["parse_escaped_lua_string", "try_xor", "decode_lph_payload"]

# Matches numeric escape sequences like "\57" or "\166"
_NUMERIC_ESCAPE = re.compile(r"\\(\d{1,3})")
# Matches repeater syntax such as "3AF" meaning repeat byte 0xAF three times
_REPEATER_PAIR = re.compile(r"(\d+)([0-9A-Fa-f]{2})")
# Generic hexadecimal byte pairs
_HEX_PAIR = re.compile(r"([0-9A-Fa-f]{2})")


def _strip_lph_prefix(literal: str) -> str:
    """Return ``literal`` without the ``LPH!`` prefix if present."""

    prefix_candidates = ("LPH!", "lph!", "LPH_", "lph_")
    for prefix in prefix_candidates:
        if literal.startswith(prefix):
            return literal[len(prefix) :]
    return literal


def decode_lph_payload(literal: str) -> bytes:
    """Decode the repeater-style payload used by ``LPH_String`` entries."""

    payload = _strip_lph_prefix(literal)
    payload = payload.strip()
    if not payload:
        return b""

    hexdigits = set(string.hexdigits)
    out = bytearray()
    length = len(payload)
    index = 0

    while index < length:
        ch = payload[index]
        if ch.isspace():
            index += 1
            continue

        # Handle repeater syntax such as "3AF" (repeat AF three times).
        if ch.isdigit():
            repeat_end = index
            while repeat_end < length and payload[repeat_end].isdigit():
                repeat_end += 1
            if repeat_end < length - 1:
                repeat_count = int(payload[index:repeat_end])
                candidate = payload[repeat_end : repeat_end + 2]
                if len(candidate) == 2 and set(candidate) <= hexdigits:
                    byte = int(candidate, 16)
                    out.extend([byte] * repeat_count)
                    index = repeat_end + 2
                    continue
            # Fall through to treat the digit as part of a hex pair.

        # Parse standard hexadecimal byte pairs.
        candidate = payload[index : index + 2]
        if len(candidate) == 2 and set(candidate) <= hexdigits:
            out.append(int(candidate, 16))
            index += 2
            continue

        # Fallback: copy raw ASCII byte to avoid data loss.
        out.append(ord(payload[index]) & 0xFF)
        index += 1

    return bytes(out)


def parse_escaped_lua_string(literal: str) -> bytes:
    """Return raw bytes decoded from a Lua string literal body.

    The bootstrapper encodes payloads using decimal escape sequences (``\57``)
    as well as printable hexadecimal runs with an optional repeater prefix such
    as ``3AF`` meaning ``0xAF`` repeated three times.  This helper mirrors those
    encodings.  When the input does not contain recognised escape sequences the
    literal bytes are returned unchanged so callers can chain additional
    decoding passes.
    """

    literal = literal or ""

    # Handle dedicated LPH payloads before considering generic escaping.
    if literal.startswith(("LPH!", "lph!", "LPH_", "lph_")):
        return decode_lph_payload(literal)

    # Fast-path: decimal / octal escape sequences like ``\57`` or ``\166``.
    if _NUMERIC_ESCAPE.search(literal):
        parts = _NUMERIC_ESCAPE.split(literal)
        out = bytearray()
        idx = 0
        while idx < len(parts):
            chunk = parts[idx]
            if chunk:
                out.extend(chunk.encode("latin1", errors="ignore"))
            if idx + 1 < len(parts):
                number = parts[idx + 1]
                try:
                    out.append(int(number, 10) & 0xFF)
                except ValueError:
                    # Some payloads still use octal; fall back to base-8.
                    out.append(int(number, 8) & 0xFF)
            idx += 2
        return bytes(out)

    # Otherwise treat the string as a packed hexadecimal payload potentially
    # containing repeater segments (e.g. ``3AF`` -> ``0xAF`` repeated thrice).
    compact = "".join(literal.split())
    out = bytearray()
    pos = 0
    length = len(compact)

    while pos < length:
        repeat_match = _REPEATER_PAIR.match(compact, pos)
        if repeat_match:
            count = int(repeat_match.group(1))
            byte_value = int(repeat_match.group(2), 16)
            out.extend([byte_value] * count)
            pos = repeat_match.end()
            continue

        hex_match = _HEX_PAIR.match(compact, pos)
        if hex_match:
            out.append(int(hex_match.group(1), 16))
            pos = hex_match.end()
            continue

        # Unknown token: preserve the original ASCII byte to avoid data loss.
        out.append(ord(compact[pos]) & 0xFF)
        pos += 1

    return bytes(out)


def try_xor(data: bytes, key: Optional[bytes]) -> bytes:
    """XOR *data* against ``key`` repeating the key as necessary."""

    if not key:
        return data
    key_len = len(key)
    return bytes((b ^ key[i % key_len]) & 0xFF for i, b in enumerate(data))
