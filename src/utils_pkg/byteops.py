"""Helpers for interpreting packed VM bytecode fields."""

from __future__ import annotations

from typing import Iterable, Literal


Endian = Literal["little", "big"]


def read_uint(data: bytes, offset: int, size: int, *, endian: Endian = "little") -> int:
    """Return an unsigned integer read from ``data`` starting at ``offset``.

    Missing bytes are treated as zero so truncated payloads do not raise errors.
    """

    if size <= 0:
        return 0
    end = offset + size
    chunk = data[offset:end]
    if len(chunk) < size:
        chunk = chunk + b"\x00" * (size - len(chunk))
    return int.from_bytes(chunk, endian, signed=False)


def read_int(data: bytes, offset: int, size: int, *, endian: Endian = "little") -> int:
    """Return a signed integer from ``data`` respecting ``endian``."""

    if size <= 0:
        return 0
    end = offset + size
    chunk = data[offset:end]
    if len(chunk) < size:
        pad = b"\x00" * (size - len(chunk))
        if endian == "little":
            chunk = chunk + pad
        else:
            chunk = pad + chunk
    return int.from_bytes(chunk, endian, signed=True)


def sign_extend(value: int, bits: int) -> int:
    """Sign extend ``value`` with ``bits`` significant bits."""

    if bits <= 0:
        return value
    mask = 1 << (bits - 1)
    return (value ^ mask) - mask


def iter_words(data: bytes, size: int) -> Iterable[tuple[int, bytes]]:
    """Yield ``(offset, word_bytes)`` chunks of ``size`` bytes."""

    if size <= 0:
        return
    for offset in range(0, len(data), size):
        yield offset, data[offset : offset + size]


__all__ = ["read_uint", "read_int", "sign_extend", "iter_words"]
