"""Minimal Unicorn-based helpers to emulate simple decoder loops."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

try:  # pragma: no cover - optional dependency
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_ECX, UC_X86_REG_EDI, UC_X86_REG_ESI
except Exception:  # pragma: no cover - optional dependency path
    Uc = None  # type: ignore


def emulate_xor_decoder(code: bytes, key: int, data: bytearray) -> bytearray:
    """Run a trivial XOR decoder snippet under Unicorn."""

    if Uc is None:  # pragma: no cover - optional dependency path
        raise RuntimeError("unicorn engine not available")

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    base = 0x1000
    mu.mem_map(base, 0x1000)
    mu.mem_write(base, code)

    data_addr = 0x2000
    mu.mem_map(data_addr, 0x1000)
    mu.mem_write(data_addr, bytes(data))

    mu.reg_write(UC_X86_REG_ESI, data_addr)
    mu.reg_write(UC_X86_REG_EDI, data_addr)
    mu.reg_write(UC_X86_REG_ECX, len(data))

    mu.emu_start(base, base + len(code))
    result = mu.mem_read(data_addr, len(data))
    return bytearray(result)


__all__ = ["emulate_xor_decoder"]
