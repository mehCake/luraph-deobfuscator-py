"""Custom ``LPH-85`` decoder used by the initv4 bootstrap."""

from __future__ import annotations

import math
import re
import struct
from typing import Iterable

_PREFIXES = ("LPH!", "LPH~", "LPH@", "lph!", "lph~", "lph@")
_WHITESPACE_RE = re.compile(r"\s+")


def strip_lph_prefix(text: str) -> str:
    """Return *text* without a recognised ``LPH`` prefix."""

    if not text:
        return ""
    for prefix in _PREFIXES:
        if text.startswith(prefix):
            return text[len(prefix) :]
    return text


def _normalise(text: str) -> str:
    """Mirror the bootstrapper's substitutions prior to decoding."""

    if not text:
        return ""
    cleaned = _WHITESPACE_RE.sub("", text)
    # The bootstrap first expands ``z`` markers into explicit ``!`` sequences
    # before processing five-character groups.
    cleaned = cleaned.replace("z", "!!!!!")
    # The Lua decoder applies an additional gsub over literal ellipses before
    # chunking.  The substitution is effectively a no-op for the payloads seen
    # so far but we mirror it to keep behaviour aligned.
    cleaned = cleaned.replace("...", "...")
    return cleaned


def _iter_chunks(text: str) -> Iterable[str]:
    length = len(text)
    if length == 0:
        return
    groups = int(math.ceil(length / 5))
    padded = text.ljust(groups * 5, "!")
    for index in range(0, len(padded), 5):
        yield padded[index : index + 5]


def decode_lph85(text: str) -> bytes:
    """Decode an ``LPH`` payload (``LPH!``, ``LPH~`` or ``LPH@``) into raw bytes."""

    if text is None:
        raise TypeError("text must be a string")

    stripped = strip_lph_prefix(text)
    normalised = _normalise(stripped)
    out = bytearray()
    for chunk in _iter_chunks(normalised):
        acc = 0
        for char in chunk:
            value = ord(char) - 33
            if value < 0:
                raise ValueError(f"invalid LPH-85 character: {char!r}")
            acc = acc * 85 + value
        out.extend(struct.pack(">I", acc & 0xFFFFFFFF))
    return bytes(out)


__all__ = ["decode_lph85", "strip_lph_prefix"]
