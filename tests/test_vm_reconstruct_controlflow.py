from __future__ import annotations

from src.vm.lifter import BasicBlock, IRProgram, IROp, IROperand
from pathlib import Path

from src.vm.reconstruct_controlflow import (
    BlockNode,
    ControlFlowReconstructor,
    IfNode,
    SequenceNode,
    StructuredProgram,
    WhileNode,
    emit_structured_lua,
    write_structured_artifacts,
)


def _block(
    block_id: str,
    *,
    start: int = 0,
    end: int = 0,
    fallthrough: str | None = None,
    jump: str | None = None,
    successors: list[str] | None = None,
    metadata: dict | None = None,
) -> BasicBlock:
    block = BasicBlock(block_id=block_id, start_index=start, end_index=end)
    block.fallthrough = fallthrough
    block.jump = jump
    block.successors = successors or [succ for succ in (fallthrough, jump) if succ]
    if metadata:
        block.metadata.update(metadata)
    return block


def test_reconstructor_linear_sequence() -> None:
    block0 = _block("block_0", fallthrough="block_1")
    block1 = _block("block_1", fallthrough="block_2")
    block2 = _block("block_2")
    program = IRProgram(blocks=[block0, block1, block2], metadata={}, entry_block="block_0")

    reconstructor = ControlFlowReconstructor(program)
    structured = reconstructor.reconstruct()

    assert isinstance(structured, StructuredProgram)
    assert structured.entry == "block_0"
    assert isinstance(structured.body, SequenceNode)
    assert [node.block.block_id for node in structured.body.nodes if isinstance(node, BlockNode)] == [
        "block_0",
        "block_1",
        "block_2",
    ]


def test_reconstructor_if_else_structure() -> None:
    cond = _block(
        "block_0",
        fallthrough="block_1",
        jump="block_2",
        successors=["block_1", "block_2"],
        metadata={"control": {"type": "cond", "true_target": "block_1", "false_target": "block_2"}},
    )
    then_block = _block("block_1", fallthrough="block_3", successors=["block_3"])
    else_block = _block("block_2", fallthrough="block_3", successors=["block_3"])
    join = _block("block_3")
    program = IRProgram(blocks=[cond, then_block, else_block, join], metadata={}, entry_block="block_0")

    reconstructor = ControlFlowReconstructor(program)
    structured = reconstructor.reconstruct()

    assert len(structured.body.nodes) >= 1
    first = structured.body.nodes[0]
    assert isinstance(first, IfNode)
    assert first.join == "block_3"
    assert [node.block.block_id for node in first.then_branch.nodes if isinstance(node, BlockNode)] == ["block_1"]
    assert first.else_branch is not None
    assert [node.block.block_id for node in first.else_branch.nodes if isinstance(node, BlockNode)] == ["block_2"]


def test_reconstructor_loop_and_trap_detection() -> None:
    header = _block(
        "block_0",
        fallthrough="block_1",
        jump="block_3",
        successors=["block_1", "block_3"],
        metadata={"control": {"type": "cond", "true_target": "block_1", "false_target": "block_3"}},
    )
    body = _block("block_1", jump="block_0", successors=["block_0"])
    exit_block = _block("block_3")
    trap = _block("trap_block")
    trap.ops.append(
        IROp(
            mnemonic="CALL",
            operands=[IROperand(field="a", value=0, kind="reg", resolved="error")],
            index=5,
            raw=None,
            metadata={},
        )
    )
    program = IRProgram(blocks=[header, body, exit_block, trap], metadata={}, entry_block="block_0")

    reconstructor = ControlFlowReconstructor(program)
    structured = reconstructor.reconstruct()

    assert any(isinstance(node, WhileNode) for node in structured.body.nodes)
    loop = next(node for node in structured.body.nodes if isinstance(node, WhileNode))
    assert loop.exit == "block_3"
    assert len(loop.body.nodes) == 1
    assert structured.traps and structured.traps[0].block.block_id == "trap_block"
    # Ensure trap block is not included in the normal body nodes
    assert all(
        getattr(node, "block", None) != trap
        for node in structured.body.nodes
    )


def test_structured_ast_marks_uncertain_if_missing_join() -> None:
    cond_block = _block(
        "cond",
        metadata={"control": {"type": "cond"}},
    )
    then_block = _block("then")
    if_node = IfNode(
        condition=BlockNode(cond_block),
        then_branch=SequenceNode([BlockNode(then_block)]),
        else_branch=None,
        join=None,
        metadata={},
    )
    program = StructuredProgram(entry="cond", body=SequenceNode([if_node]), traps=tuple())

    ast = program.to_ast()
    body_nodes = ast["body"]["nodes"]
    metadata = body_nodes[0]["metadata"]
    assert "uncertain" in metadata
    assert "missing_join" in metadata["uncertain"]
    assert "missing_else" in metadata["uncertain"]


def test_emit_structured_lua_adds_todo_comments(tmp_path: Path) -> None:
    cond_block = _block(
        "cond",
        metadata={"control": {"type": "cond"}},
    )
    cond_block.ops.append(
        IROp(
            mnemonic="TEST",
            operands=[IROperand(field="a", value=1, kind="reg", resolved=None)],
            index=4,
            raw=0xDEADBEEF,
            metadata={},
        )
    )
    then_block = _block("then")
    if_node = IfNode(
        condition=BlockNode(cond_block),
        then_branch=SequenceNode([BlockNode(then_block)]),
        else_branch=None,
        join=None,
        metadata={},
    )
    program = StructuredProgram(entry="cond", body=SequenceNode([if_node]), traps=tuple())

    emitted = emit_structured_lua(program, candidate="demo")
    assert "-- TODO: missing join" in emitted
    assert "offset=0x" in emitted

    artefacts = write_structured_artifacts(program, candidate="demo", output_dir=tmp_path)
    lua_content = artefacts["lua"].read_text(encoding="utf-8")
    assert "-- Structured pseudo-Lua representation" in lua_content
    json_content = artefacts["json"].read_text(encoding="utf-8")
    assert "\"type\": \"program\"" in json_content
