"""Unicorn-based emulator utilities for decoding native Luraph helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Mapping, Sequence

try:  # pragma: no cover - optional dependency import guard
    from unicorn import (
        Uc,
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_MEM_WRITE,
        UC_MEM_WRITE,
        UC_MODE_32,
        UC_MODE_64,
        UC_PROT_ALL,
    )
    from unicorn.x86_const import (
        UC_X86_REG_EAX,
        UC_X86_REG_ECX,
        UC_X86_REG_EDI,
        UC_X86_REG_EDX,
        UC_X86_REG_EIP,
        UC_X86_REG_ESI,
        UC_X86_REG_ESP,
        UC_X86_REG_RAX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDI,
        UC_X86_REG_RDX,
        UC_X86_REG_RIP,
        UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )
except Exception:  # pragma: no cover
    Uc = None  # type: ignore
    UC_ARCH_X86 = UC_HOOK_CODE = UC_HOOK_MEM_WRITE = UC_MEM_WRITE = 0  # type: ignore
    UC_MODE_32 = UC_MODE_64 = UC_PROT_ALL = 0  # type: ignore
    UC_X86_REG_EAX = UC_X86_REG_ECX = UC_X86_REG_EDI = UC_X86_REG_EDX = 0  # type: ignore
    UC_X86_REG_EIP = UC_X86_REG_ESI = UC_X86_REG_ESP = 0  # type: ignore
    UC_X86_REG_RAX = UC_X86_REG_RCX = UC_X86_REG_RDI = UC_X86_REG_RDX = 0  # type: ignore
    UC_X86_REG_RIP = UC_X86_REG_RSI = UC_X86_REG_RSP = 0  # type: ignore


_REGISTERS_32 = {
    "EAX": UC_X86_REG_EAX,
    "ECX": UC_X86_REG_ECX,
    "EDX": UC_X86_REG_EDX,
    "ESI": UC_X86_REG_ESI,
    "EDI": UC_X86_REG_EDI,
    "ESP": UC_X86_REG_ESP,
    "EIP": UC_X86_REG_EIP,
}

_REGISTERS_64 = {
    "RAX": UC_X86_REG_RAX,
    "RCX": UC_X86_REG_RCX,
    "RDX": UC_X86_REG_RDX,
    "RSI": UC_X86_REG_RSI,
    "RDI": UC_X86_REG_RDI,
    "RSP": UC_X86_REG_RSP,
    "RIP": UC_X86_REG_RIP,
    **_REGISTERS_32,
}


@dataclass(slots=True)
class EmulationRequest:
    """Configuration passed to :func:`emulate_decoder`."""

    code: bytes
    capture_address: int
    capture_size: int
    arch: str = "x86"
    mode: str = "64"
    base_address: int = 0x1000
    entry_address: int | None = None
    stack_address: int = 0x200000
    stack_size: int = 0x10000
    memory_map: Sequence[tuple[int, int]] = ((0x1000, 0x4000),)
    prefill: bytes | None = None
    initial_registers: Mapping[str, int] = field(default_factory=dict)
    stop_addresses: Iterable[int] = ()
    max_instructions: int = 200_000

    def __post_init__(self) -> None:
        if self.entry_address is None:
            self.entry_address = self.base_address
        if len(self.code) == 0:
            raise ValueError("code buffer cannot be empty")
        if self.capture_size <= 0:
            raise ValueError("capture_size must be positive")


@dataclass(slots=True)
class EmulationResult:
    """Outcome of a decoder emulation run."""

    buffer: bytes
    writes: int
    instructions_executed: int
    completed: bool

    def to_json(self) -> Dict[str, object]:  # pragma: no cover - trivial serialiser
        return {
            "writes": self.writes,
            "instructions": self.instructions_executed,
            "completed": self.completed,
        }


class _StopExecution(Exception):
    """Internal sentinel used to halt emulation."""


def _align(value: int, alignment: int = 0x1000) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _make_uc(request: EmulationRequest) -> "Uc":
    if Uc is None:  # pragma: no cover - optional dependency
        raise RuntimeError("unicorn is not installed; install `unicorn` to use the emulator")

    mode = request.mode
    if mode not in {"32", "64"}:
        raise ValueError("mode must be '32' or '64'")
    uc_mode = UC_MODE_64 if mode == "64" else UC_MODE_32
    uc = Uc(UC_ARCH_X86, uc_mode)

    for base, size in request.memory_map:
        uc.mem_map(base, _align(size), UC_PROT_ALL)

    code_base_aligned = request.base_address & ~0xFFF
    if all(base != code_base_aligned for base, _ in request.memory_map):
        uc.mem_map(code_base_aligned, _align(len(request.code)), UC_PROT_ALL)

    uc.mem_write(request.base_address, request.code)

    capture_base = request.capture_address & ~0xFFF
    capture_limit = request.capture_address + request.capture_size
    capture_span = _align(capture_limit - capture_base)
    mapped = False
    for base, size in request.memory_map:
        aligned_base = base & ~0xFFF
        aligned_size = _align(size)
        if capture_base >= aligned_base and capture_base < aligned_base + aligned_size:
            mapped = True
            break

    if not mapped:
        uc.mem_map(capture_base, capture_span, UC_PROT_ALL)

    if request.prefill:
        if len(request.prefill) != request.capture_size:
            raise ValueError("prefill length must match capture_size")
        uc.mem_write(request.capture_address, request.prefill)
    else:
        uc.mem_write(request.capture_address, b"\x00" * request.capture_size)

    stack_base = request.stack_address & ~0xFFF
    uc.mem_map(stack_base, _align(request.stack_size), UC_PROT_ALL)

    regs = _REGISTERS_64 if mode == "64" else _REGISTERS_32
    for name, value in request.initial_registers.items():
        reg_id = regs.get(name.upper())
        if reg_id is None:
            raise ValueError(f"unknown register name {name!r}")
        uc.reg_write(reg_id, value)

    stack_reg = regs["RSP" if mode == "64" else "ESP"]
    uc.reg_write(stack_reg, request.stack_address + request.stack_size // 2)
    ip_reg = regs["RIP" if mode == "64" else "EIP"]
    uc.reg_write(ip_reg, request.entry_address)

    return uc


def emulate_decoder(request: EmulationRequest) -> EmulationResult:
    """Execute a decoder snippet using Unicorn and capture the produced buffer."""

    uc = _make_uc(request)
    capture = bytearray(request.prefill or b"\x00" * request.capture_size)
    written: set[int] = set()
    stop_addresses = set(request.stop_addresses)
    instructions_executed = 0
    completed = False

    def _hook_mem_write(uc_inst, access, address, size, value, user_data):  # pragma: no cover - exercised in tests
        if access != UC_MEM_WRITE:
            return
        if request.capture_address <= address < request.capture_address + request.capture_size:
            data = uc_inst.mem_read(address, size)
            offset = address - request.capture_address
            for idx, byte in enumerate(data):
                pos = offset + idx
                if 0 <= pos < request.capture_size:
                    capture[pos] = byte
                    written.add(pos)
            if len(written) >= request.capture_size:
                raise _StopExecution()

    def _hook_code(uc_inst, address, size, user_data):  # pragma: no cover - exercised in tests
        nonlocal instructions_executed
        instructions_executed += 1
        if instructions_executed > request.max_instructions:
            raise _StopExecution()
        if stop_addresses and address in stop_addresses:
            raise _StopExecution()

    uc.hook_add(UC_HOOK_MEM_WRITE, _hook_mem_write)
    uc.hook_add(UC_HOOK_CODE, _hook_code)

    try:
        uc.emu_start(request.entry_address, 0)
        completed = True
    except _StopExecution:
        completed = True
    finally:
        buffer = bytes(capture)
    return EmulationResult(
        buffer=buffer,
        writes=len(written),
        instructions_executed=instructions_executed,
        completed=completed,
    )


__all__ = ["EmulationRequest", "EmulationResult", "emulate_decoder"]
