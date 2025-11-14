from __future__ import annotations

from src.vm.inline_emitter import emit_inline
from src.vm.lifter import BasicBlock, IRProgram, IROp, IROperand


def _make_program() -> IRProgram:
    block = BasicBlock(block_id="block_0", start_index=0, end_index=2)
    block.raw_offsets = [0, 1, 2]
    block.ops.extend(
        [
            IROp(
                mnemonic="LOADK",
                operands=[
                    IROperand(field="a", value=0, kind="reg"),
                    IROperand(field="b", value=0, kind="const", resolved="hello"),
                    IROperand(field="c", value=None, kind="reg"),
                ],
                index=0,
                raw=0x1234,
            ),
            IROp(
                mnemonic="MOVE",
                operands=[
                    IROperand(field="a", value=1, kind="reg"),
                    IROperand(field="b", value=0, kind="reg"),
                    IROperand(field="c", value=None, kind="reg"),
                ],
                index=1,
                raw=0x5678,
            ),
            IROp(
                mnemonic="ADD",
                operands=[
                    IROperand(field="a", value=0, kind="reg"),
                    IROperand(field="b", value=0, kind="reg"),
                    IROperand(field="c", value=256, kind="const", resolved=5),
                ],
                index=2,
                raw=0x9ABC,
            ),
        ]
    )

    program = IRProgram(blocks=[block], metadata={"instruction_count": 3}, entry_block=block.block_id)
    return program


def test_emit_inline_renders_offsets_and_operations():
    program = _make_program()
    source = emit_inline(program)

    assert "-- block block_0 [0:2]" in source
    assert "regs[1] = \"hello\"" in source
    assert "regs[2] = regs[1]" in source
    assert "regs[1] = (regs[1]) + (5)" in source
    assert "offset=0x0000" in source
    assert "raw=0x00001234" in source


def test_emit_inline_wraps_when_requested():
    program = _make_program()
    wrapped = emit_inline(program, wrap=True)

    assert wrapped.startswith("return function(state)")
    assert "local regs = state.regs or {}" in wrapped
    assert wrapped.strip().endswith("end")
