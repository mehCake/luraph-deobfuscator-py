"""Helpers for mirroring the initv4 PRGA keystream tweaks."""

from __future__ import annotations

from typing import ByteString


def _ror8(value: int, rotation: int) -> int:
    """Rotate an eight-bit value right by ``rotation`` bits."""

    rotation &= 7
    value &= 0xFF
    if rotation == 0:
        return value
    return ((value >> rotation) | ((value << (8 - rotation)) & 0xFF)) & 0xFF


def apply_prga(decoded_lph: ByteString, key: ByteString) -> bytes:
    """Mirror the Lua PRGA helper using byte-wise XOR and rrotate."""

    if not key:
        raise ValueError("key must be non-empty")

    decoded_view = memoryview(decoded_lph)
    key_bytes = memoryview(key)

    key_len = len(key_bytes)
    output = bytearray(len(decoded_view))

    for index in range(len(decoded_view)):
        value = decoded_view[index]
        key_byte = key_bytes[index % key_len]
        value ^= key_byte
        value = _ror8(value, key_byte & 7)
        output[index] = value

    return bytes(output)


__all__ = ["apply_prga"]

