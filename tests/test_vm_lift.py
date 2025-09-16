from src.passes.vm_lift import VMLifter
from src.versions import OpSpec


def _op_table() -> dict[int, OpSpec]:
    return {
        0x01: OpSpec("LOADK", ("a", "b")),
        0x28: OpSpec("JMP", ("offset",)),
        0x15: OpSpec("RETURN", ("a", "b")),
    }


def test_vmlifter_basic_blocks():
    # LOADK R0, K0
    # JMP +1 (skip the second LOADK)
    # LOADK R1, K1 (unreachable but should live in its own block)
    # RETURN R0, 1
    bytecode = bytes(
        [
            0x01, 0x00, 0x00, 0x00,
            0x28, 0x01, 0x00, 0x00,
            0x01, 0x01, 0x01, 0x00,
            0x15, 0x00, 0x01, 0x00,
        ]
    )
    lifter = VMLifter()
    module = lifter.lift(bytecode, _op_table(), consts=["foo", "bar"])

    assert module.instruction_count == 4
    assert module.block_count >= 3
    entry = module.blocks[module.entry]
    assert entry.instructions[0].opcode == "LoadK"
    assert entry.instructions[0].args["const_value"] == "foo"
    assert module.register_types.get(0) == "string"
    # Ensure the jump created a successor pointing at the return block
    assert entry.successors
    last_block = module.blocks[module.order[-1]]
    assert last_block.instructions[-1].opcode == "Return"


def test_vmlifter_unknown_opcode():
    lifter = VMLifter()
    module = lifter.lift(bytes([0xFF, 0x00, 0x00, 0x00]), {}, consts=[])
    assert module.instructions[0].opcode == "Unknown"
    assert module.warnings
