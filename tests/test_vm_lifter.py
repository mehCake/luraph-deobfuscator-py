from __future__ import annotations

from src.vm.disassembler import Instruction
from src.vm.lifter import Lifter
from src.vm.opcode_map import OpcodeMap


SBX_BIAS = 131071


def _encode_abc(opcode: int, a: int, b: int, c: int) -> int:
    return (opcode & 0x3F) | ((a & 0xFF) << 6) | ((c & 0x1FF) << 14) | ((b & 0x1FF) << 23)


def _encode_asbx(opcode: int, a: int, sbx: int) -> int:
    bx = sbx + SBX_BIAS
    b = (bx >> 9) & 0x1FF
    c = bx & 0x1FF
    return _encode_abc(opcode, a, b, c)


def _instruction(index: int, raw: int, opcode: int, a: int, b: int, c: int) -> Instruction:
    return Instruction(index=index, raw=raw, opcode=opcode, a=a, b=b, c=c)


def test_lifter_constructs_cfg_and_resolves_operands():
    opcode_map = OpcodeMap()
    opcode_map.register(1, "LOADK")
    opcode_map.register(2, "JMP")
    opcode_map.register(3, "RETURN")

    instructions = [
        _instruction(0, _encode_abc(1, 0, 1, 0), 1, 0, 1, 0),
        _instruction(1, _encode_asbx(2, 0, 1), 2, 0, (1 + SBX_BIAS) >> 9, (1 + SBX_BIAS) & 0x1FF),
        _instruction(2, _encode_abc(3, 0, 1, 0), 3, 0, 1, 0),
        _instruction(3, _encode_abc(3, 0, 1, 0), 3, 0, 1, 0),
    ]

    lifter = Lifter(opcode_map=opcode_map)
    result = lifter.lift(instructions, constants=["", "hello"], verbose=True)

    program = result.program
    assert program.metadata["instruction_count"] == 4
    assert program.metadata["block_count"] == 3
    assert program.entry_block == "block_0"
    assert result.metadata["ir_format"] == "structured"
    assert result.ir_format == "structured"
    assert result.verbose_mapping  # verbose mapping generated even if caller prints later

    first_block = program.blocks[0]
    assert [op.mnemonic for op in first_block.ops] == ["LOADK", "JMP"]
    assert first_block.jump == program.blocks[2].block_id
    assert first_block.fallthrough is None

    load_operands = first_block.ops[0].operands
    assert load_operands[0].kind == "reg"
    assert load_operands[1].kind == "const"
    assert load_operands[1].resolved == "hello"

    second_block = program.blocks[1]
    assert second_block.predecessors == []
    assert second_block.ops[0].mnemonic == "RETURN"

    third_block = program.blocks[2]
    assert third_block.predecessors == [first_block.block_id]


def test_lifter_handles_empty_instruction_sequence():
    lifter = Lifter()
    result = lifter.lift([])

    assert result.program.blocks == []
    assert result.program.metadata["instruction_count"] == 0
    assert result.program.metadata["block_count"] == 0
    assert result.ir_format == "structured"
    assert result.metadata["ir_format"] == "structured"


def test_lifter_basic_ir_format_and_verbose_mapping():
    opcode_map = OpcodeMap()
    instructions = [
        _instruction(0, _encode_abc(1, 0, 1, 0), 1, 0, 1, 0),
        _instruction(1, _encode_abc(0x1D, 0, 1, 1), 0x1D, 0, 1, 1),
        _instruction(2, _encode_asbx(0x17, 0, -2), 0x17, 0, 0, 0),
    ]

    lifter = Lifter(opcode_map=opcode_map, version_hint="v14.4.2")
    result = lifter.lift(instructions, ir_format="basic", verbose=True)

    assert result.ir_format == "basic"
    assert result.metadata["ir_format"] == "basic"
    assert len(result.program.blocks) == 1
    block = result.program.blocks[0]
    assert [op.mnemonic for op in block.ops] == ["LOADK", "CALL", "JMP"]
    categories = [op.metadata.get("category") for op in block.ops]
    assert categories == ["load", "call", "jump"]
    assert result.ir_entries[0]["category"] == "load"
    assert result.raw_output is None
    assert result.verbose_mapping
    assert any("0000" in line for line in result.verbose_mapping)


def test_lifter_version_hint_registers_presets():
    instructions = [
        _instruction(0, _encode_abc(0x1D, 0, 1, 1), 0x1D, 0, 1, 1),
    ]

    lifter = Lifter(version_hint="v14.4.2")
    result = lifter.lift(instructions, ir_format="basic")

    block = result.program.blocks[0]
    assert block.ops[0].mnemonic == "CALL"
