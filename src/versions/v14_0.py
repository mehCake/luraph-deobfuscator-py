from __future__ import annotations

from typing import Dict, Any

from ..vm.emulator import LuraphVM

# Placeholder for version specific opcode extensions.  The base VM already
# implements a large set of handlers so we only need to provide additions
# where versions diverge.
OPCODE_MAP: Dict[str, Any] = {}


def process(vm: LuraphVM) -> None:
    """Apply version 14.0 specific patches to ``vm``."""

    vm.dispatch.update(OPCODE_MAP)
