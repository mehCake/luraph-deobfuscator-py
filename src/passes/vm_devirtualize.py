"""
src/passes/vm_devirtualize.py

Takes IR (from vm_lift) and reconstructs higher-level Lua source.
"""

import logging
from typing import Dict, Any
from .vm_lift import VMFunction

logger = logging.getLogger("passes.vm_devirtualize")
logger.setLevel(logging.DEBUG)

class DevirtualizeError(Exception):
    pass

def ir_to_lua(ir: VMFunction, opcode_map: Dict[int, str], metadata: Dict[str, Any] = None) -> str:
    """
    Convert IR to Lua source.
    This is a placeholder; extend with control flow reconstruction, register renaming, etc.
    """
    lines = []
    lines.append("return function()")
    indent = "  "
    for instr in ir.instructions:
        args = ", ".join(str(x) for x in instr.operands)
        lines.append(f"{indent}-- PC {instr.pc:04X}")
        lines.append(f"{indent}{instr.mnemonic}({args})")
    lines.append("end")
    return "\n".join(lines)

def devirtualize_entry(ir: VMFunction, bootstrapper_metadata: Dict[str, Any]) -> str:
    opcode_map = bootstrapper_metadata.get("opcode_map") or bootstrapper_metadata.get("opcode_dispatch")
    if not opcode_map:
        raise DevirtualizeError("Missing opcode_map for devirtualization")

    try:
        return ir_to_lua(ir, opcode_map, bootstrapper_metadata)
    except Exception as e:
        logger.exception("Devirtualization failed: %s", e)
        raise DevirtualizeError(f"Devirtualization failed: {e}")
