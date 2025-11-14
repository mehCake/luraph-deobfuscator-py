import json
from pathlib import Path

from src.tools.ambiguous_reporter import (
    build_ambiguous_report,
    write_json,
    write_markdown,
)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_ambiguous_report_detects_low_confidence_opcode(tmp_path: Path) -> None:
    pipeline_path = tmp_path / "pipeline_candidates.json"
    proposals_path = tmp_path / "opcode_proposals.json"
    structured_dir = tmp_path / "structured"

    _write_json(
        pipeline_path,
        {
            "opcode_handlers": {
                "10": ["handler_call"],
            }
        },
    )

    _write_json(
        proposals_path,
        {
            "candidates": [
                {
                    "confidence": 0.58,
                    "mapping": {"10": "CALL"},
                    "selections": {
                        "10": {
                            "mnemonic": "CALL",
                            "confidence": 0.6,
                            "handlers": ["handler_call"],
                            "reasons": ["rank-1"],
                        }
                    },
                },
                {
                    "confidence": 0.57,
                    "mapping": {"10": "RETURN"},
                    "selections": {
                        "10": {
                            "mnemonic": "RETURN",
                            "confidence": 0.55,
                            "handlers": ["handler_call"],
                            "reasons": ["rank-2"],
                        }
                    },
                },
            ]
        },
    )

    structured_dir.mkdir()
    _write_json(
        structured_dir / "candidate_01.json",
        {
            "body": {
                "type": "if",
                "metadata": {"uncertain": ["missing_else"]},
                "condition": {"type": "block", "id": "block_0"},
                "then": {"type": "sequence", "nodes": []},
            }
        },
    )

    report = build_ambiguous_report(
        pipeline_path=pipeline_path,
        proposals_path=proposals_path,
        structured_dir=structured_dir,
    )

    assert report.opcodes, "expected ambiguous opcode to be detected"
    assert any("missing_else" in node.issues for node in report.ir_nodes)

    md_path = tmp_path / "ambiguous.md"
    json_path = tmp_path / "ambiguous.json"
    write_markdown(report, md_path)
    write_json(report, json_path)

    md_text = md_path.read_text(encoding="utf-8")
    assert "0x0A" in md_text
    assert "missing_else" in md_text

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["opcodes"]
    assert payload["ir_nodes"]
    assert payload["summary"], "summary should not be empty"
