from __future__ import annotations

from src.vm.ir_utils import collapse_trivial_blocks, compute_cfg, pretty_print_ir
from src.vm.lifter import BasicBlock, IROp, IROperand, IRProgram


def _make_op(mnemonic: str, index: int, value: int) -> IROp:
    operand = IROperand(field="a", value=value, kind="reg", resolved=f"r{value}")
    return IROp(mnemonic=mnemonic, operands=[operand], index=index, raw=None, metadata={})


def test_pretty_print_ir_includes_operands_and_metadata() -> None:
    block = BasicBlock(
        block_id="block_0",
        start_index=0,
        end_index=1,
        ops=[_make_op("LOADK", 0, 1)],
        fallthrough="block_1",
        successors=["block_1"],
        metadata={"hint": "entry"},
    )
    program = IRProgram(blocks=[block], metadata={"instruction_count": 1}, entry_block="block_0")

    rendered = pretty_print_ir(program, include_metadata=True)

    assert "block_0:" in rendered
    assert "; metadata: hint=entry" in rendered
    assert "LOADK" in rendered
    assert "reg:a=1 ('r1')" in rendered
    assert "; successors: block_1" in rendered


def test_compute_cfg_normalises_successors() -> None:
    block_a = BasicBlock(
        block_id="A",
        start_index=0,
        end_index=0,
        ops=[_make_op("MOVE", 0, 0)],
        fallthrough="B",
        successors=["B", "C"],
    )
    block_b = BasicBlock(
        block_id="B",
        start_index=1,
        end_index=1,
        ops=[_make_op("RETURN", 1, 0)],
        jump="C",
        successors=[],
    )
    block_c = BasicBlock(
        block_id="C",
        start_index=2,
        end_index=2,
        ops=[],
    )
    program = IRProgram(blocks=[block_a, block_b, block_c], metadata={}, entry_block="A")

    cfg = compute_cfg(program)

    assert cfg["successors"]["A"] == ["B", "C"]
    assert cfg["successors"]["B"] == ["C"]
    assert cfg["predecessors"]["C"] == ["A", "B"]


def test_collapse_trivial_blocks_merges_empty_bridge() -> None:
    block_a = BasicBlock(
        block_id="A",
        start_index=0,
        end_index=0,
        ops=[_make_op("MOVE", 0, 0)],
        fallthrough="B",
        successors=["B"],
    )
    block_b = BasicBlock(
        block_id="B",
        start_index=1,
        end_index=1,
        ops=[],
        fallthrough="C",
        successors=["C"],
    )
    block_c = BasicBlock(
        block_id="C",
        start_index=2,
        end_index=2,
        ops=[_make_op("RETURN", 2, 0)],
        predecessors=["B"],
    )
    program = IRProgram(blocks=[block_a, block_b, block_c], metadata={}, entry_block="A")

    collapsed = collapse_trivial_blocks(program)

    assert [block.block_id for block in collapsed.blocks] == ["A", "C"]
    assert collapsed.blocks[0].fallthrough == "C"
    assert collapsed.blocks[0].successors == ["C"]
    assert collapsed.blocks[1].predecessors == ["A"]

    # Original program is untouched
    assert [block.block_id for block in program.blocks] == ["A", "B", "C"]


def test_collapse_trivial_blocks_respects_metadata_guard() -> None:
    block_a = BasicBlock(
        block_id="A",
        start_index=0,
        end_index=0,
        ops=[_make_op("MOVE", 0, 0)],
        fallthrough="B",
        successors=["B"],
    )
    block_b = BasicBlock(
        block_id="B",
        start_index=1,
        end_index=1,
        ops=[],
        fallthrough="C",
        successors=["C"],
        metadata={"keep": True},
    )
    block_c = BasicBlock(
        block_id="C",
        start_index=2,
        end_index=2,
        ops=[_make_op("RETURN", 2, 0)],
        predecessors=["B"],
    )
    program = IRProgram(blocks=[block_a, block_b, block_c], metadata={}, entry_block="A")

    collapsed = collapse_trivial_blocks(program)

    assert [block.block_id for block in collapsed.blocks] == ["A", "B", "C"]

    collapsed_unprotected = collapse_trivial_blocks(program, preserve_metadata=False)
    assert [block.block_id for block in collapsed_unprotected.blocks] == ["A", "C"]
