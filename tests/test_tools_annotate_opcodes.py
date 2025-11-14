from __future__ import annotations

import json

from pathlib import Path

from src.tools.annotate_opcodes import (
    generate_opcode_annotations,
    load_instruction_samples,
    write_opcode_annotations,
)


def _write_candidate(path: Path) -> None:
    payload = {
        "confidence": 0.9,
        "mapping": {"0": "LOADK", "1": "CALL"},
        "selections": {
            "0": {
                "mnemonic": "LOADK",
                "confidence": 0.95,
                "handlers": ["handler_load"],
                "reasons": ["rank-1"],
            },
            "1": {
                "mnemonic": "CALL",
                "confidence": 0.82,
                "handlers": ["handler_call"],
                "reasons": ["rank-1"],
            },
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_instructions(path: Path) -> None:
    instructions = [
        {"opcode": 0, "index": 0, "raw": 0x1234, "a": 1, "b": 0, "c": 0},
        {"opcode": 1, "index": 4, "raw": 0x5678, "a": 2, "b": 1, "c": 0},
    ]
    path.write_text(json.dumps(instructions), encoding="utf-8")


def test_generate_and_write_annotations(tmp_path: Path) -> None:
    opcode_dir = tmp_path / "opcode_maps"
    opcode_dir.mkdir()
    candidate_path = opcode_dir / "candidate_01.json"
    _write_candidate(candidate_path)

    lift_ir = tmp_path / "lift_ir.json"
    _write_instructions(lift_ir)

    instructions = load_instruction_samples([lift_ir])
    annotations = generate_opcode_annotations([candidate_path], instructions, max_examples=1)
    assert annotations and annotations[0].entries

    output = tmp_path / "opcode_annotations.md"
    write_opcode_annotations(output, annotations)

    text = output.read_text(encoding="utf-8")
    assert "<!-- OPCODE-ANNOTATIONS:BEGIN -->" in text
    assert "Candidate 1" in text
    assert "handler_load" in text
    assert "```" in text
    assert "0x00001234" in text.lower()


def test_write_preserves_manual_sections(tmp_path: Path) -> None:
    output = tmp_path / "opcode_annotations.md"
    output.write_text(
        "Manual notes\n\n"
        "<!-- OPCODE-ANNOTATIONS:BEGIN -->\nold block\n<!-- OPCODE-ANNOTATIONS:END -->\n\n"
        "Follow-up items\n",
        encoding="utf-8",
    )

    write_opcode_annotations(output, [])

    text = output.read_text(encoding="utf-8")
    assert "Manual notes" in text
    assert "Follow-up items" in text
    assert "old block" not in text
    assert "_No opcode map candidates were discovered._" in text
