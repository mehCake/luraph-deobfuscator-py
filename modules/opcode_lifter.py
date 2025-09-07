LURAPH_OPCODES = {
    1: 'OP_MOVE',
    2: 'OP_LOADK',
    3: 'OP_LOADBOOL',
    4: 'OP_LOADNIL',
    # Extend based on modern Luraph opcodes
}

def lift_opcodes(byte_data):
    lifted = []
    for instr in byte_data:
        opcode = instr if isinstance(instr, int) else instr[0]
        lifted.append(LURAPH_OPCODES.get(opcode, f"UNKNOWN_{opcode}"))
    return "\n".join(lifted)
