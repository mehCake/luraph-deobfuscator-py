import json
from pathlib import Path

from src.tools.report_to_user import build_user_summary, main as report_main


def test_build_user_summary_includes_next_steps(tmp_path: Path) -> None:
    pipeline_report = {
        "pipelines": [
            {
                "sequence": ["string-escape", "prga", "vm_unpack"],
                "confidence": 0.62,
                "version_hint": "v14.4.2",
                "hypothesis_score": {"notes": ["Parity coverage incomplete"]},
            }
        ],
        "vm_style": {"style": "register", "confidence": 0.8},
    }
    mapping_report = {"total_tables": 2}

    summary = build_user_summary(
        target="Obfuscated3.lua",
        pipeline_report=pipeline_report,
        mapping_report=mapping_report,
        parity_report_path=None,
        transform_profile_path=None,
        detection_report_path=tmp_path / "detection_report.md",
    )

    markdown = summary.render_markdown()
    assert "Next Steps" in markdown
    assert "Parity coverage incomplete" in markdown
    assert "v14.4.2" in markdown


def test_report_to_user_cli(tmp_path: Path) -> None:
    pipeline_path = tmp_path / "pipeline.json"
    pipeline_payload = {
        "pipelines": [
            {
                "sequence": ["string-escape", "prga"],
                "confidence": 0.85,
                "version_hint": "v14.4.2",
            }
        ]
    }
    pipeline_path.write_text(json.dumps(pipeline_payload), encoding="utf-8")

    output_path = tmp_path / "summary.md"

    exit_code = report_main(
        [
            "--pipeline",
            str(pipeline_path),
            "--output",
            str(output_path),
            "--target",
            "Obfuscated3.lua",
        ]
    )

    assert exit_code == 0
    content = output_path.read_text(encoding="utf-8")
    assert "Obfuscated3.lua" in content
    assert "Next Steps" in content
