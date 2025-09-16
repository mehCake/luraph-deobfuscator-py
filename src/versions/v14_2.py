from __future__ import annotations

from typing import Dict, Any

from ..vm.emulator import LuraphVM
from ..vm.opcodes import HandlerResult


def _handle_pcall(state, *args: Any) -> HandlerResult:
    # The pcall instruction is used for integrity checks in some payloads.  This
    # lightweight handler simply skips the call to keep execution moving.
    return 1, None


OPCODE_MAP: Dict[str, Any] = {"PCALL": _handle_pcall}


def process(vm: LuraphVM) -> None:
    """Apply version 14.2 specific patches to ``vm``.

    The handler neutralises anti-reverse-engineering tricks by rewriting any
    ``PCALL`` line number operand to ``1`` before execution.
    """

    for instr in vm.state.bytecode:
        if instr and instr[0] == "PCALL" and len(instr) > 1:
            instr[1] = 1
    vm.dispatch.update(OPCODE_MAP)
