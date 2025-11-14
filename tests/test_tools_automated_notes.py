import json
from pathlib import Path
from typing import Sequence

import pytest

from src.tools.automated_notes import (
    AutomatedNotes,
    build_automated_notes,
    main as automated_notes_main,
)


def _sample_pipeline() -> dict[str, object]:
    return {
        "pipelines": [
            {
                "sequence": ["string-escape", "prga", "vm_unpack"],
                "confidence": 0.82,
                "version_hint": "v14.4.2",
                "hypothesis_score": {"notes": ["Confirm opcode coverage", "Check parity mismatch"]},
            }
        ],
        "chunks": [{"id": 1}, {"id": 2}],
        "parity_summary": {"status": "mismatch", "recommendations": ["Try alternate rotate"]},
    }


def _sample_mapping() -> dict[str, object]:
    return {"mapping_files": ["/tmp/opmap.json"]}


def _sample_recommendations() -> Sequence[str]:
    return ["Inspect dispatcher CFG", "Review extracted strings"]


def test_build_automated_notes_collects_summary_and_actions() -> None:
    notes = build_automated_notes(
        target="Obfuscated3.lua",
        pipeline_report=_sample_pipeline(),
        mapping_report=_sample_mapping(),
        parity_summary={"status": "match"},
        recommendations=_sample_recommendations(),
        final_report_steps=("Verify checksum hints",),
    )

    assert isinstance(notes, AutomatedNotes)
    rendered = notes.render_text()
    assert "Obfuscated3.lua" in rendered
    assert "Pipeline confidence" in rendered
    assert rendered.count("•") >= 1
    # ensure we always surface exactly three action items
    assert rendered.strip().splitlines()[-3].startswith("1.")
    assert "Verify checksum hints" in rendered


def test_cli_generates_output_and_handles_copy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pipeline_path = tmp_path / "pipeline.json"
    pipeline_path.write_text(json.dumps(_sample_pipeline()), encoding="utf-8")

    recommendations_md = tmp_path / "recommendations.md"
    recommendations_md.write_text("## Next Steps\n- Inspect dispatcher CFG\n- Review extracted strings\n", encoding="utf-8")

    output_path = tmp_path / "notes.txt"

    copied: dict[str, bool] = {"called": False}

    def _fake_copy(_: str) -> bool:
        copied["called"] = True
        return True

    monkeypatch.setattr("src.tools.automated_notes._copy_to_clipboard", _fake_copy)

    exit_code = automated_notes_main(
        [
            "--pipeline",
            str(pipeline_path),
            "--target",
            "Obfuscated3.lua",
            "--recommendations",
            str(recommendations_md),
            "--output",
            str(output_path),
            "--copy",
        ]
    )

    assert exit_code == 0
    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "Top action items" in content
    assert copied["called"] is True
