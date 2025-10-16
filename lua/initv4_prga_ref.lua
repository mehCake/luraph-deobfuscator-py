# Pseudo-Lua module compatible with the fallback lupa shim.
from __future__ import annotations

from typing import ByteString


def apply_prga_ref(decoded_lph: ByteString, key: ByteString) -> bytes:
    if not key:
        raise ValueError("key must be non-empty")

    decoded = memoryview(decoded_lph)
    key_bytes = memoryview(key)
    key_len = len(key_bytes)

    output = bytearray(len(decoded))
    for index, value in enumerate(decoded):
        key_byte = key_bytes[index % key_len]
        mixed = value ^ key_byte
        rotation = key_byte & 7
        if rotation:
            mixed &= 0xFF
            mixed = ((mixed >> rotation) | ((mixed << (8 - rotation)) & 0xFF)) & 0xFF
        output[index] = mixed
    return bytes(output)


initv4_prga_ref = {}
initv4_prga_ref["apply_prga_ref"] = apply_prga_ref
