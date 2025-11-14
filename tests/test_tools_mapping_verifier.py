from __future__ import annotations

import pytest

from src.tools.mapping_verifier import verify_inline_snippet
from src.vm.inline_emitter import emit_inline
from src.vm.lifter import BasicBlock, IRProgram, IROp, IROperand


def _program_for_verifier() -> IRProgram:
    block = BasicBlock(block_id="block_0", start_index=0, end_index=1)
    block.raw_offsets = [0, 1]
    block.ops.extend(
        [
            IROp(
                mnemonic="LOADK",
                operands=[
                    IROperand(field="a", value=0, kind="reg"),
                    IROperand(field="b", value=0, kind="const", resolved=10),
                    IROperand(field="c", value=None, kind="reg"),
                ],
                index=0,
                raw=0x1010,
            ),
            IROp(
                mnemonic="ADD",
                operands=[
                    IROperand(field="a", value=0, kind="reg"),
                    IROperand(field="b", value=0, kind="reg"),
                    IROperand(field="c", value=256, kind="const", resolved=5),
                ],
                index=1,
                raw=0x2020,
            ),
        ]
    )
    return IRProgram(blocks=[block], metadata={"instruction_count": 2}, entry_block=block.block_id)


def test_verify_inline_snippet_runs_with_lua_runtime():
    pytest.importorskip("lupa")
    program = _program_for_verifier()
    inline_source = emit_inline(program)

    vectors = [
        {
            "name": "simple_addition",
            "registers": [0, 0, 0],
            "constants": [],
            "expect": {"registers": [15]},
        }
    ]

    outcomes = verify_inline_snippet(inline_source, vectors)
    assert len(outcomes) == 1
    assert outcomes[0].passed
    assert outcomes[0].registers[0] == 15
