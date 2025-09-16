"""Utility helpers for decoding layered Luraph constant pools."""

from __future__ import annotations

import base64
import binascii
import string
from typing import Iterable, Optional

_PRINTABLE = set(string.printable) | {"\t", "\n", "\r"}
_BASE64_ALPHABET = set(string.ascii_letters + string.digits + "+/=")
_BASE64_URLSAFE = set(string.ascii_letters + string.digits + "-_=")
_ALLOWED_KEY_CHARS = set(string.ascii_letters + string.digits + "-_@$")


def maybe_base64(text: str) -> Optional[bytes]:
    """Return decoded bytes if *text* looks like base64, otherwise ``None``."""

    cleaned = "".join(text.split())
    if len(cleaned) < 8:
        return None
    trimmed = cleaned.rstrip("=")
    if not trimmed:
        return None
    alphabet = set(trimmed)
    if not (alphabet <= _BASE64_ALPHABET or alphabet <= _BASE64_URLSAFE):
        return None
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        try:
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return None


def maybe_hex(text: str) -> Optional[bytes]:
    """Attempt to interpret *text* as hexadecimal bytes."""

    stripped = text.strip().replace(" ", "")
    if len(stripped) < 4 or len(stripped) % 2:
        return None
    if any(ch not in string.hexdigits for ch in stripped):
        return None
    try:
        return bytes.fromhex(stripped)
    except ValueError:
        return None


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rotate_left_bytes(data: bytes, amount: int) -> bytes:
    if not amount:
        return data
    shift = amount % 8
    if not shift:
        return data
    return bytes(((b << shift) & 0xFF) | (b >> (8 - shift)) for b in data)


def decode_utf8(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def is_probably_text(text: str) -> bool:
    if not text:
        return False
    length = len(text)
    printable = sum(1 for ch in text if ch in _PRINTABLE)
    if printable / length < 0.9:
        return False
    letters = sum(1 for ch in text if ch.isalpha())
    spaces = text.count(" ")
    digits = sum(1 for ch in text if ch.isdigit())
    # Reject extremely high entropy blobs
    unique_ratio = len(set(text)) / length
    if length > 12 and unique_ratio > 0.92:
        return False
    score = (letters + spaces) / length
    if length > 6 and score < 0.35:
        return False
    if digits and digits / length > 0.6:
        return False
    return True


def text_score(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    printable = sum(1 for ch in text if ch in _PRINTABLE)
    letters = sum(1 for ch in text if ch.isalpha())
    spaces = text.count(" ")
    punctuation = sum(1 for ch in text if ch in string.punctuation)
    digits = sum(1 for ch in text if ch.isdigit())
    return (
        printable / length
        + letters / length
        + 0.2 * spaces / length
        + 0.05 * punctuation / max(length, 1)
        - 0.1 * digits / length
    )


def sanitise_key_candidate(value: str) -> Optional[bytes]:
    candidate = value.strip()
    if not (4 <= len(candidate) <= 64):
        return None
    if not all(ch in _ALLOWED_KEY_CHARS for ch in candidate):
        return None
    return candidate.encode("utf-8")


def unique_preserving(items: Iterable[bytes]) -> list[bytes]:
    seen: set[bytes] = set()
    ordered: list[bytes] = []
    for entry in items:
        if entry in seen:
            continue
        seen.add(entry)
        ordered.append(entry)
    return ordered


__all__ = [
    "maybe_base64",
    "maybe_hex",
    "xor_bytes",
    "rotate_left_bytes",
    "decode_utf8",
    "is_probably_text",
    "text_score",
    "sanitise_key_candidate",
    "unique_preserving",
]
