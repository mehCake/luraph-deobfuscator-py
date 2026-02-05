"""Synthetic v14.3 serialized chunk fixture for regression tests."""

from __future__ import annotations

from pattern_analyzer import SerializedChunkDescriptor

_MAGIC = b"V143CHNK"


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint encoder only accepts non-negative integers")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _encode_zigzag(value: int) -> int:
    return (value << 1) ^ (value >> 63)


def _encode_string(value: str) -> bytes:
    payload = value.encode("utf-8")
    return _encode_varint(len(payload)) + payload


def _encode_bytes(data: bytes) -> bytes:
    return _encode_varint(len(data)) + data


def _encode_constant(entry) -> bytes:
    tag, value = entry
    if tag == "nil":
        return b"\x01"
    if tag == "boolean":
        return b"\x02" + (b"\x01" if value else b"\x00")
    if tag == "integer":
        encoded = _encode_varint(_encode_zigzag(value))
        return b"\x03" + encoded
    if tag == "number":
        import struct

        return b"\x04" + struct.pack(">d", float(value))
    if tag == "string":
        return b"\x05" + _encode_string(value)
    if tag == "bytes":
        return b"\x06" + _encode_bytes(value)
    raise ValueError(f"unknown constant tag {tag}")


def _encode_prototype(constants, instructions, children) -> bytes:
    payload = bytearray()
    payload.extend(_encode_varint(len(constants)))
    payload.extend(_encode_varint(len(instructions)))
    payload.extend(_encode_varint(len(children)))
    for constant in constants:
        payload.extend(_encode_constant(constant))
    for instr in instructions:
        payload.extend(_encode_varint(len(instr)))
        payload.extend(instr)
    for child in children:
        payload.extend(child)
    return bytes(payload)


_SAMPLE_CONSTANTS = [
    ("nil", None),
    ("boolean", True),
    ("boolean", False),
    ("integer", 123456),
    ("integer", -42),
    ("number", 3.14159),
    ("string", "hello world"),
    ("bytes", b"\x01\x02\x03"),
]

_CHILD_CONSTANTS = [("string", "child"), ("integer", 7)]

_CHILD_PROTO = _encode_prototype(_CHILD_CONSTANTS, [], [])

_TOP_LEVEL_PROTO = _encode_prototype(_SAMPLE_CONSTANTS, [], [_CHILD_PROTO])

SERIALIZED_CHUNK_BYTES = (
    _MAGIC + _encode_varint(1) + _TOP_LEVEL_PROTO
)

SERIALIZED_CHUNK_DESCRIPTOR = SerializedChunkDescriptor(
    buffer_name="chunk_literal",
    initial_offset=0,
    helper_functions={"decode": "a3"},
)

__all__ = [
    "SERIALIZED_CHUNK_DESCRIPTOR",
    "SERIALIZED_CHUNK_BYTES",
]
