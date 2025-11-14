from __future__ import annotations

import json

from src.vm.disassembler import Instruction
from src.vm.opcode_proposer import (
    compute_opcode_usage,
    generate_map_candidates,
    group_proposals_by_opcode,
    load_disassembly_instructions,
    load_handler_suggestions,
    propose_opcode_mappings,
    render_ir_candidate,
    run_cli,
    synthesise_opcode_proposals,
)


def test_opcode_proposer_generates_candidates_and_ir():
    entries = [
        {"opcode": 1, "handler": "do_load", "mnemonics": ["LOADK", "CALL"]},
        {"opcode": 1, "handler": "call_handler", "mnemonics": ["CALL"]},
        {"opcode": 2, "handler": "return_handler", "mnemonics": ["RETURN"]},
    ]

    proposals = propose_opcode_mappings(entries)
    assert proposals, "expected proposals to be generated"

    grouped = group_proposals_by_opcode(proposals)
    assert set(grouped.keys()) == {1, 2}

    candidates = generate_map_candidates(grouped, top_n=2)
    assert candidates, "expected at least one candidate map"

    instructions = [
        Instruction(index=1, raw=0, opcode=1, a=0, b=1, c=2),
        Instruction(index=2, raw=0, opcode=2, a=0, b=0, c=0),
    ]

    rendered = render_ir_candidate(candidates[0], instructions)
    assert "CALL" in rendered  # opcode 1 should favour CALL due to multiple hints
    assert "RETURN" in rendered
    assert "IR Listing" in rendered


def _make_instruction(opcode: int, *, index: int = 0) -> Instruction:
    return Instruction(index=index, raw=0, opcode=opcode, a=1, b=2, c=3)


def test_compute_opcode_usage_counts_frequency() -> None:
    instructions = [_make_instruction(1, index=0), _make_instruction(1, index=1), _make_instruction(2, index=2)]
    usage = compute_opcode_usage(instructions)
    assert usage == {1: 2, 2: 1}


def test_synthesise_opcode_proposals_applies_overrides(tmp_path) -> None:
    handler_payload = {
        "handlers": [
            {
                "name": "handler_call",
                "opcode": 1,
                "resolvable": True,
                "candidates": [
                    {"mnemonic": "LOADK", "confidence": 0.6},
                    {"mnemonic": "CALL", "confidence": 0.9},
                ],
            },
            {
                "name": "handler_return",
                "opcode": 2,
                "resolvable": True,
                "candidates": [{"mnemonic": "RETURN", "confidence": 0.8}],
            },
        ]
    }
    handler_path = tmp_path / "handlers.json"
    handler_path.write_text(json.dumps(handler_payload), encoding="utf-8")

    disasm_path = tmp_path / "disasm.json"
    disasm_payload = {
        "instructions": [
            {"opcode": 1, "index": 0, "raw": 0, "a": 1, "b": 0, "c": 0},
            {"opcode": 1, "index": 1, "raw": 0, "a": 2, "b": 0, "c": 0},
            {"opcode": 2, "index": 2, "raw": 0, "a": 0, "b": 0, "c": 0},
        ]
    }
    disasm_path.write_text(json.dumps(disasm_payload), encoding="utf-8")

    handler_entries = load_handler_suggestions(handler_path)
    instructions = load_disassembly_instructions([disasm_path])
    overrides = {2: "RET"}

    candidates = synthesise_opcode_proposals(
        handler_entries,
        instructions,
        overrides=overrides,
        top_n=2,
    )

    assert candidates, "expected opcode map candidates"
    first = candidates[0]
    # Override should force opcode 2 mnemonic regardless of handler ranking
    assert first.mapping[2] == "RET"
    assert first.mapping[1] in {"CALL", "LOADK"}


def test_run_cli_appends_to_existing_output(tmp_path) -> None:
    handler_payload = {
        "handlers": [
            {
                "name": "handler_call",
                "opcode": 1,
                "resolvable": True,
                "candidates": [{"mnemonic": "CALL", "confidence": 0.9}],
            }
        ]
    }
    handler_path = tmp_path / "handlers.json"
    handler_path.write_text(json.dumps(handler_payload), encoding="utf-8")

    disasm_path = tmp_path / "disasm.json"
    disasm_payload = {
        "instructions": [
            {"opcode": 1, "index": 0, "raw": 0, "a": 0, "b": 0, "c": 0},
            {"opcode": 1, "index": 1, "raw": 0, "a": 0, "b": 0, "c": 0},
        ]
    }
    disasm_path.write_text(json.dumps(disasm_payload), encoding="utf-8")

    output_path = tmp_path / "out.json"
    existing = {
        "generated_at": "2023-01-01T00:00:00Z",
        "candidates": [
            {
                "confidence": 0.5,
                "mapping": {"9": "MOVE"},
                "selections": {},
            }
        ],
    }
    output_path.write_text(json.dumps(existing), encoding="utf-8")

    exit_code = run_cli(
        handler_path=handler_path,
        disasm_paths=[disasm_path],
        overrides={},
        output_path=output_path,
        top_n=1,
    )
    assert exit_code == 0

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert "candidates" in data and len(data["candidates"]) >= 2
    # Ensure existing mapping is preserved
    assert any(candidate.get("mapping", {}).get("9") == "MOVE" for candidate in data["candidates"])
