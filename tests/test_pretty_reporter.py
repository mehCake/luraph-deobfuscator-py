import json
from pathlib import Path

from src.pretty.reporter import build_final_report, write_final_report


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_build_final_report_includes_pipeline_and_opcode_details(tmp_path: Path) -> None:
    pipeline_payload = {
        "pipeline": ["string-escape", "prga", "permute"],
        "pipeline_confidence": 0.58,
        "pipeline_hints": ["xor-loop"],
        "version_hint": "v14.4.2",
        "pipelines": [
            {
                "sequence": ["string-escape", "prga", "permute", "vm_unpack"],
                "confidence": 0.74,
                "version_hint": "v14.4.2",
                "preferred_presets": ["v14.4.2-default", "v14.4.1-default"],
                "confidence_breakdown": {
                    "operation_score": 0.6,
                    "frequency_bonus": 0.1,
                },
            }
        ],
        "opcode_handlers": {
            "0": ["handler_move"],
            "1": ["handler_loadk"],
            "2": ["handler_call"],
        },
        "opcode_map_candidates": [
            {
                "confidence": 0.55,
                "mapping": {"0": "MOVE", "1": "LOADK"},
                "selections": {
                    "0": {"mnemonic": "MOVE", "confidence": 0.8, "handlers": ["handler_move"], "reasons": ["rank-1"]},
                    "1": {"mnemonic": "LOADK", "confidence": 0.7, "handlers": ["handler_loadk"], "reasons": ["rank-1"]},
                },
            }
        ],
    }
    pipeline_path = tmp_path / "pipeline_candidates.json"
    _write_json(pipeline_path, pipeline_payload)

    proposals_payload = {
        "candidates": [
            {
                "confidence": 0.6,
                "mapping": {"0": "MOVE", "1": "LOADK", "2": "CALL"},
                "selections": {},
            }
        ]
    }
    proposals_path = tmp_path / "opcode_proposals.json"
    _write_json(proposals_path, proposals_payload)

    report = build_final_report(
        pipeline_path,
        proposals_path=proposals_path,
        output_dir=tmp_path,
        target=tmp_path / "Obfuscated3.lua",
    )

    text = report.render_markdown()
    assert "string-escape → prga → permute → vm_unpack" in text
    assert "v14.4.2" in text
    assert "v14.4.2-default" in text
    assert "Unresolved opcodes" in text and "0x02" in text
    assert "PRGA" in text
    assert "Steps to Reproduce" in text
    assert "Ambiguous Analysis Items" in text
    assert "No ambiguous opcodes or IR regions detected." in text

    output_path = tmp_path / "final_report.md"
    write_final_report(report, output_path)
    saved = output_path.read_text(encoding="utf-8")
    assert saved == text


def test_final_report_includes_ambiguous_summary(tmp_path: Path) -> None:
    pipeline_payload = {
        "pipeline": ["string-escape", "xor"],
        "pipeline_confidence": 0.8,
    }
    _write_json(tmp_path / "pipeline_candidates.json", pipeline_payload)

    proposals_payload = {
        "candidates": [
            {
                "confidence": 0.9,
                "mapping": {"0": "MOVE"},
                "selections": {"0": {"mnemonic": "MOVE", "confidence": 0.9}},
            }
        ]
    }
    _write_json(tmp_path / "opcode_proposals.json", proposals_payload)

    ambiguous_payload = {
        "summary": ["Opcode 0x02 (CALL): alternate mnemonic RETURN scores 0.60"],
    }
    _write_json(tmp_path / "ambiguous.json", ambiguous_payload)

    report = build_final_report(
        tmp_path / "pipeline_candidates.json",
        proposals_path=tmp_path / "opcode_proposals.json",
        output_dir=tmp_path,
    )

    text = report.render_markdown()
    assert "Ambiguous Analysis Items" in text
    assert "Opcode 0x02" in text
