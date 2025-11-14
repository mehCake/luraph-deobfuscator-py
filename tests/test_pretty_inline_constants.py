from __future__ import annotations

import json
from pathlib import Path

from src.pretty.inline_constants import (
    DEFAULT_OUTPUT,
    InlineSummary,
    inline_constants,
    inline_constants_payload,
    main,
    write_inlined_lua,
)
from src.vm.lifter import BasicBlock, IRProgram, IROp, IROperand


def _sample_program() -> IRProgram:
    block = BasicBlock(block_id="entry", start_index=0, end_index=1)
    block.raw_offsets = [0, 1]
    block.ops = [
        IROp(
            mnemonic="LOADK",
            operands=(
                IROperand(field="A", value=0, kind="reg"),
                IROperand(field="Bx", value=0, kind="const", resolved=None),
            ),
            index=0,
            raw=None,
            metadata={},
        ),
        IROp(
            mnemonic="LOADK",
            operands=(
                IROperand(field="A", value=1, kind="reg"),
                IROperand(field="Bx", value=1, kind="const", resolved=None),
            ),
            index=1,
            raw=None,
            metadata={},
        ),
    ]
    return IRProgram(blocks=[block], metadata={}, entry_block="entry")


def test_inline_constants_respects_usage_threshold() -> None:
    program = _sample_program()
    constants = ["hello", 1234]

    updated, summary = inline_constants(program, constants, max_usage=1, max_numeric_abs=1000)

    # first constant is a short string used once – should be inlined
    first_operand = updated.blocks[0].ops[0].operands[1]
    assert first_operand.resolved == "hello"

    # second constant exceeds numeric threshold – stays unresolved
    second_operand = updated.blocks[0].ops[1].operands[1]
    assert second_operand.resolved is None

    assert isinstance(summary, InlineSummary)
    assert summary.inlined == 1
    assert summary.skipped_type == 1


def test_inline_constants_payload_handles_dict_input() -> None:
    payload = {
        "program": {
            "blocks": [
                {
                    "id": "entry",
                    "start_index": 0,
                    "end_index": 0,
                    "raw_offsets": [0],
                    "ops": [
                        {
                            "mnemonic": "LOADK",
                            "index": 0,
                            "operands": [
                                {"field": "A", "kind": "reg", "value": 0},
                                {"field": "Bx", "kind": "const", "value": 0},
                            ],
                        }
                    ],
                }
            ]
        }
    }

    program, summary = inline_constants_payload(payload, ["world"], max_usage=2)

    operand = program.blocks[0].ops[0].operands[1]
    assert operand.resolved == "world"
    assert summary.inlined == 1


def test_cli_main_emits_output(tmp_path: Path) -> None:
    ir_payload = {
        "program": {
            "blocks": [
                {
                    "id": "entry",
                    "start_index": 0,
                    "end_index": 1,
                    "raw_offsets": [0, 1],
                    "ops": [
                        {
                            "mnemonic": "LOADK",
                            "index": 0,
                            "operands": [
                                {"field": "A", "kind": "reg", "value": 0},
                                {"field": "Bx", "kind": "const", "value": 0},
                            ],
                        }
                    ],
                }
            ]
        }
    }

    ir_path = tmp_path / "ir.json"
    consts_path = tmp_path / "consts.json"
    output_path = tmp_path / "inlined.lua"

    ir_path.write_text(json.dumps(ir_payload), encoding="utf-8")
    consts_path.write_text(json.dumps(["hello"]), encoding="utf-8")

    # Ensure CLI writes to the requested location
    exit_code = main([
        str(ir_path),
        str(consts_path),
        "--output",
        str(output_path),
        "--max-usage",
        "2",
    ])

    assert exit_code == 0
    assert output_path.exists()
    contents = output_path.read_text(encoding="utf-8")
    assert '"hello"' in contents


def test_write_inlined_lua_uses_default_output(tmp_path: Path) -> None:
    program = _sample_program()
    inlined, _ = inline_constants(program, ["inline"], max_usage=1)

    destination = tmp_path / DEFAULT_OUTPUT.name
    path = write_inlined_lua(inlined, output_path=destination)
    assert path == destination
    assert destination.exists()
    assert "inline" in destination.read_text(encoding="utf-8")
