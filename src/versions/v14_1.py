from __future__ import annotations

from typing import Dict, Any

from ..vm.emulator import LuraphVM

OPCODE_MAP: Dict[str, Any] = {}


def process(vm: LuraphVM) -> None:
    """Apply version 14.1 specific patches to ``vm``."""

    vm.dispatch.update(OPCODE_MAP)
