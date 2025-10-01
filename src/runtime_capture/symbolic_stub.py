"""Triton-based symbolic execution helpers (optional)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

try:  # pragma: no cover - optional dependency
    from triton import TritonContext, ARCH, Instruction  # type: ignore
except Exception:  # pragma: no cover
    TritonContext = None  # type: ignore


@dataclass
class SymbolicResult:
    expressions: list[str]
    solved: bool


def execute_stub(code: bytes, input_registers: dict[str, int] | None = None) -> SymbolicResult:
    """Run a handler under Triton and return symbolic expressions.

    This is intentionally conservative – it only executes if Triton is available
    and otherwise returns a placeholder result.
    """

    if TritonContext is None:  # pragma: no cover - optional path
        raise RuntimeError("Triton is not installed")

    ctx = TritonContext(ARCH.X86_64)
    base = 0x100000
    ctx.setConcreteMemoryAreaValue(base, code)
    ctx.setConcreteRegisterValue(ctx.registers.rip, base)

    if input_registers:
        for name, value in input_registers.items():
            reg = getattr(ctx.registers, name)
            ctx.setConcreteRegisterValue(reg, value)

    expressions: list[str] = []
    while True:
        rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
        if rip >= base + len(code):
            break
        inst = Instruction()
        inst.setAddress(rip)
        inst.setOpcode(ctx.getConcreteMemoryAreaValue(rip, 16))
        ctx.processing(inst)
        ctx.setConcreteRegisterValue(ctx.registers.rip, rip + inst.getSize())
        expressions.append(str(inst))

    return SymbolicResult(expressions, bool(expressions))


__all__ = ["SymbolicResult", "execute_stub"]
