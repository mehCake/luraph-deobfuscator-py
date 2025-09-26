"""
src/passes/vm_lift.py

Luraph VM lifter: convert decoded bytecode into an intermediate representation (IR).
This integrates with the pipeline in luraph_deobfuscator.py.

Responsibilities:
 - Parse raw decoded VM bytecode into instructions
 - Use opcode_map (from bootstrap_metadata) to label instructions
 - Build IR structures (VMFunction, VMInstruction)
 - Provide IR to downstream devirtualizer (vm_devirtualize)
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger("passes.vm_lift")
logger.setLevel(logging.DEBUG)

class VMInstruction:
    def __init__(self, opcode: int, operands: List[int], pc: int, mnemonic: str):
        self.opcode = opcode
        self.operands = operands
        self.pc = pc
        self.mnemonic = mnemonic

    def __repr__(self):
        return f"<IR pc={self.pc:04X} op={self.opcode:02X} {self.mnemonic} {self.operands}>"

class VMFunction:
    def __init__(self):
        self.instructions: List[VMInstruction] = []
        self.constants: List[Any] = []
        self.upvalues: List[Any] = []
        self.max_stack = 0

class LiftError(Exception):
    pass

def parse_bytecode_into_ir(bytecode: bytes, opcode_map: Dict[int, str], instr_size: int = 4) -> VMFunction:
    """
    Parse bytecode into IR. Assumes each instruction is `instr_size` bytes.
    Default = 4 (common for Lua-like VMs). Adapt this to Luraph’s actual format.
    """
    ir = VMFunction()

    if len(bytecode) % instr_size != 0:
        logger.warning("Bytecode len=%d not divisible by instr_size=%d", len(bytecode), instr_size)

    count = len(bytecode) // instr_size
    for i in range(count):
        pc = i * instr_size
        chunk = bytecode[pc:pc + instr_size]
        if len(chunk) < instr_size:
            break

        opcode = chunk[0]
        operands = list(chunk[1:])
        mnemonic = opcode_map.get(opcode, f"OP_{opcode:02X}")
        instr = VMInstruction(opcode, operands, pc, mnemonic)
        ir.instructions.append(instr)

        logger.debug("Lifted %s", instr)

    return ir

def lift_entry(decoded_bytes: bytes, bootstrapper_metadata: Dict[str, Any]) -> VMFunction:
    """
    Entrypoint: lift decoded VM bytecode into IR.
    """
    opcode_map = bootstrapper_metadata.get("opcode_map") or bootstrapper_metadata.get("opcode_dispatch")
    if not opcode_map:
        raise LiftError("Missing opcode_map in bootstrap metadata")

    try:
        ir = parse_bytecode_into_ir(decoded_bytes, opcode_map)
        return ir
    except Exception as e:
        logger.exception("VM lifting failed: %s", e)
        raise LiftError(f"VM lifting failed: {e}")
