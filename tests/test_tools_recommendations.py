import json
from pathlib import Path

from src.tools.recommendations import (
    build_recommendation_checklist,
    main as recommendations_main,
    write_recommendation_markdown,
)


def _sample_pipeline() -> dict[str, object]:
    return {
        "pipelines": [
            {
                "sequence": ["string-escape", "prga", "vm_unpack"],
                "confidence": 0.78,
                "version_hint": "v14.4.2",
                "hypothesis_score": {"notes": ["Mapping coverage incomplete"]},
            }
        ],
        "chunks": [
            {
                "hints": ["dispatcher-cfg", "trap"],
                "handler_map": [
                    {
                        "opcode": 3,
                        "handler": "handler_trap",
                        "mnemonics": ["TRAP"],
                        "body": "-- trap guard",
                    }
                ],
            },
            {"hints": ["perm-array", "xor-loop", "string.char"]},
        ],
        "checksum_summary": {"total": 2, "invalid": 1, "valid": 1},
        "byte_candidates": [{"endianness_hint": "little"}],
        "opcode_handlers": {"1": ["handler_call"], "2": ["handler_return"]},
        "parity_summary": {"status": "mismatch", "recommendations": ["Try alternate rotate"]},
    }


def _sample_mapping() -> dict[str, object]:
    return {"mapping_files": ["/tmp/opcode_map.json"], "total_tables": 1}


def test_build_recommendation_checklist_captures_key_actions(tmp_path: Path) -> None:
    checklist = build_recommendation_checklist(
        target="Obfuscated3.lua",
        pipeline_report=_sample_pipeline(),
        mapping_report=_sample_mapping(),
        parity_summary={"status": "mismatch"},
    )

    items = checklist.items
    assert any("opcode" in item.lower() for item in items)
    assert any("strings" in item.lower() for item in items)
    assert any("trap" in item.lower() for item in items)
    assert "v14.4.2" in checklist.version_hint

    markdown = checklist.render_markdown()
    assert "Manual Review Checklist" in markdown
    assert "- [ ]" in markdown

    destination = tmp_path / "recommendations.md"
    write_recommendation_markdown(destination, checklist)
    assert destination.exists()


def test_write_and_cli(tmp_path: Path) -> None:
    pipeline_path = tmp_path / "pipeline.json"
    pipeline_path.write_text(json.dumps(_sample_pipeline()), encoding="utf-8")
    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(json.dumps(_sample_mapping()), encoding="utf-8")

    output_path = tmp_path / "recommendations.md"

    exit_code = recommendations_main(
        [
            "--pipeline",
            str(pipeline_path),
            "--mapping",
            str(mapping_path),
            "--output",
            str(output_path),
            "--target",
            "Obfuscated3.lua",
        ]
    )

    assert exit_code == 0
    content = output_path.read_text(encoding="utf-8")
    assert "Obfuscated3.lua" in content
    assert "Checklist" in content

