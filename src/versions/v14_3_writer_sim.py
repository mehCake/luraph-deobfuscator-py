"""Instrumentation harness that mirrors the v14.3 loader helper network."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, MutableMapping, Optional, Sequence


class WriterLogEntry(dict):
    """Typed alias for log entries captured by :class:`V14_3Writer`."""


@dataclass
class V14_3Writer:
    """Instrumented writer that mirrors the Lua loader's bytecode writer.

    The original helpers (``o``, ``M``, ``r``, ``a3`` …) append data to a byte
    buffer one primitive at a time.  This Python port maintains the same write
    order but records rich metadata (operation type, offsets, semantic labels)
    so reverse-engineering sessions can replay or annotate each emission.
    """

    buf: bytearray = field(default_factory=bytearray)
    log: List[WriterLogEntry] = field(default_factory=list)

    def write_u8(self, value: int, *, label: Optional[str] = None) -> None:
        """Append a single byte and record the instrumentation entry."""

        if value < 0 or value > 0xFF:
            raise ValueError("write_u8 expects an unsigned byte")
        self._record_write(
            op="u8", label=label, payload=value, data=bytes([value & 0xFF])
        )

    def write_bytes(self, data: bytes, *, label: Optional[str] = None) -> None:
        """Append an arbitrary payload."""

        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must provide the buffer protocol")
        payload = bytes(data)
        self._record_write(op="bytes", label=label, payload=payload, data=payload)

    def write_varint(self, value: int, *, label: Optional[str] = None) -> None:
        """Encode ``value`` using the loader's little-endian base-128 format."""

        if value < 0:
            raise ValueError("varints must be non-negative")
        encoded = _encode_varint(value)
        self._record_write(op="varint", label=label, payload=value, data=encoded)

    def _record_write(
        self,
        *,
        op: str,
        payload: Any,
        data: bytes,
        label: Optional[str] = None,
    ) -> None:
        offset = len(self.buf)
        self.buf.extend(data)
        entry: WriterLogEntry = {
            "op": op,
            "offset": offset,
            "size": len(data),
            "label": label,
            "value": payload,
        }
        if op == "bytes":
            entry["bytes"] = data
        self.log.append(entry)

    def snapshot(self) -> Dict[str, Any]:
        """Return a copy of the current buffer/log for analysis."""

        return {"buf": bytes(self.buf), "log": list(self.log)}


@dataclass
class PrototypeSpec:
    """Lightweight model describing a simulated prototype."""

    constants: Sequence[MutableMapping[str, Any]]
    instructions: Sequence[bytes]
    children: Sequence["PrototypeSpec"] = field(default_factory=tuple)


def simulate_v14_3_writer(prototypes: Optional[Sequence[PrototypeSpec]] = None) -> Dict[str, Any]:
    """Execute the Python port of the loader helpers and return instrumentation.

    ``prototypes`` defaults to a minimal hierarchy that mirrors the structure the
    Lua loader emits: each prototype announces the size of its constant pool,
    instruction list, and nested prototypes before delegating to helper
    functions that encode individual constants or instructions.
    """

    writer = V14_3Writer()
    spec = list(prototypes) if prototypes is not None else list(_DEFAULT_PROTOTYPES)
    Y3(writer, spec)
    return writer.snapshot()


# ---------------------------------------------------------------------------
# Python translations of the loader helpers
# ---------------------------------------------------------------------------


def Y3(writer: V14_3Writer, prototypes: Sequence[PrototypeSpec]) -> None:
    """Entry point that mirrors the obfuscated ``Y3`` Lua closure.

    The loader begins by writing the number of prototypes, then iterates through
    each prototype by invoking the ``o`` helper.  This matches the control flow
    seen in the Lua source where the serialized chunk is populated before the
    VM consumes it.
    """

    a3(writer, len(prototypes), label="proto_count")
    for index, proto in enumerate(prototypes):
        o(writer, proto, index=index)


def o(writer: V14_3Writer, proto: PrototypeSpec, *, index: int) -> None:
    """Encode a single prototype header and delegate to helper routines."""

    a3(writer, len(proto.constants), label=f"proto[{index}].constant_count")
    a3(writer, len(proto.instructions), label=f"proto[{index}].instruction_count")
    a3(writer, len(proto.children), label=f"proto[{index}].child_count")

    for const_index, const in enumerate(proto.constants):
        M(writer, const, label=f"proto[{index}].const[{const_index}]")

    for inst_index, inst in enumerate(proto.instructions):
        r(writer, inst, label=f"proto[{index}].instr[{inst_index}]")

    for child_index, child in enumerate(proto.children):
        O3(writer, child, label=f"proto[{index}].child[{child_index}]")


def M(writer: V14_3Writer, constant: MutableMapping[str, Any], *, label: str) -> None:
    """Encode a single constant entry following the tag conventions."""

    kind = constant.get("kind")
    if kind == "nil":
        writer.write_u8(0x01, label=f"{label}.tag_nil")
    elif kind == "boolean":
        writer.write_u8(0x02, label=f"{label}.tag_boolean")
        writer.write_u8(0x01 if constant.get("value") else 0x00, label=f"{label}.bool")
    elif kind == "integer":
        writer.write_u8(0x03, label=f"{label}.tag_int")
        _write_zigzag(writer, int(constant.get("value", 0)), label=f"{label}.int")
    elif kind == "double":
        writer.write_u8(0x04, label=f"{label}.tag_double")
        payload = _encode_f64(float(constant.get("value", 0.0)))
        writer.write_bytes(payload, label=f"{label}.double")
    elif kind == "string":
        data = constant.get("value", "")
        encoded = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        writer.write_u8(0x05, label=f"{label}.tag_string")
        writer.write_varint(len(encoded), label=f"{label}.strlen")
        writer.write_bytes(encoded, label=f"{label}.strdata")
    elif kind == "bytes":
        data = bytes(constant.get("value", b""))
        writer.write_u8(0x06, label=f"{label}.tag_bytes")
        writer.write_varint(len(data), label=f"{label}.bytelen")
        writer.write_bytes(data, label=f"{label}.bytes")
    else:
        raise ValueError(f"unsupported constant kind: {kind}")


def r(writer: V14_3Writer, instruction: bytes, *, label: str) -> None:
    """Mirror the helper that packs instruction payloads."""

    payload = bytes(instruction)
    writer.write_varint(len(payload), label=f"{label}.len")
    writer.write_bytes(payload, label=f"{label}.data")


def O3(writer: V14_3Writer, proto: PrototypeSpec, *, label: str) -> None:
    """Delegate to :func:`o` for nested prototypes."""

    # Nested prototypes reuse the same ``o`` helper; record the label for clarity.
    o(writer, proto, index=int(label.split("[")[-1].split("]")[0]) if "[" in label else 0)


def a3(writer: V14_3Writer, value: int, *, label: Optional[str] = None) -> None:
    """Little-endian base-128 encoder used throughout the loader."""

    writer.write_varint(value, label=label)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varints must be non-negative")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            break
    return bytes(encoded)


def _write_zigzag(writer: V14_3Writer, value: int, *, label: str) -> None:
    # Mirror Lua's zig-zag encoding (signed to unsigned) while keeping the
    # result within 64 bits to match the loader's arithmetic.
    encoded = (value << 1) ^ (value >> 63)
    mask = (1 << 64) - 1
    writer.write_varint(encoded & mask, label=label)


def _encode_f64(value: float) -> bytes:
    import struct

    return struct.pack(">d", value)


_DEFAULT_PROTOTYPES: Sequence[PrototypeSpec] = (
    PrototypeSpec(
        constants=(
            {"kind": "nil"},
            {"kind": "boolean", "value": True},
            {"kind": "integer", "value": 42},
            {"kind": "double", "value": 3.14159},
            {"kind": "string", "value": "hello"},
            {"kind": "bytes", "value": b"\x01\x02\x03"},
        ),
        instructions=(b"\x10\x20", b"\x30"),
        children=(
            PrototypeSpec(
                constants=(
                    {"kind": "boolean", "value": False},
                    {"kind": "integer", "value": -7},
                ),
                instructions=(b"\x99",),
            ),
        ),
    ),
)


__all__ = [
    "V14_3Writer",
    "PrototypeSpec",
    "simulate_v14_3_writer",
    "Y3",
    "o",
    "M",
    "r",
    "O3",
    "a3",
]
