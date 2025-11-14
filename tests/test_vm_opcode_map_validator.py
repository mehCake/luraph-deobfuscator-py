from __future__ import annotations

import json
from pathlib import Path

from src.vm.disassembler import Instruction
from src.vm.opcode_map_validator import validate_opcode_map, write_validation_report, run_cli


def _make_instruction(index: int, opcode: int, a: int, b: int, c: int) -> Instruction:
    return Instruction(index=index, raw=0, opcode=opcode, a=a, b=b, c=c)


def test_validate_flags_return_followups(tmp_path: Path) -> None:
    instructions = [
        _make_instruction(0, 1, 0, 0, 0),
        _make_instruction(1, 2, 1, 0, 0),
        _make_instruction(2, 3, 0, 0, 0),
    ]
    mapping = {1: "RETURN", 2: "MOVE", 3: "RETURN"}

    summary = validate_opcode_map(
        instructions,
        mapping,
        candidate="sample",
        strictness="balanced",
    )

    assert summary.total_instructions == 3
    assert any("terminal opcode" in issue.message for issue in summary.issues)
    report_path = write_validation_report(summary, output_dir=tmp_path, filename="report.md")
    text = report_path.read_text(encoding="utf-8")
    assert "Opcode Map Validation" in text
    assert "RETURN" in text


def test_cli_generates_report(tmp_path: Path) -> None:
    instructions = [
        {"index": 0, "raw": 0, "opcode": 1, "a": 0, "b": 0, "c": 0},
        {"index": 1, "raw": 0, "opcode": 2, "a": 0, "b": 1, "c": 0},
    ]
    disasm_path = tmp_path / "trace.json"
    disasm_path.write_text(json.dumps(instructions), encoding="utf-8")

    map_payload = {"mnemonics": {"1": "RETURN", "2": "MOVE"}}
    map_path = tmp_path / "map.json"
    map_path.write_text(json.dumps(map_payload), encoding="utf-8")

    output_dir = tmp_path / "reports"
    exit_code = run_cli(
        [
            "--map",
            str(map_path),
            "--disasm",
            str(disasm_path),
            "--candidate-name",
            "candidate_a",
            "--output-dir",
            str(output_dir),
            "--report-name",
            "candidate_a.md",
        ]
    )

    assert exit_code == 0
    report_path = output_dir / "candidate_a.md"
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "candidate_a" in content
    assert "RETURN" in content
