import json
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path("src/tools/quick_status.sh")


@pytest.mark.skipif(not SCRIPT.exists(), reason="quick status script missing")
def test_quick_status_reports_top_candidate(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    pipeline_payload = {
        "pipelines": [
            {
                "sequence": ["string-escape", "prga", "permute"],
                "confidence": 0.9,
                "version_hint": "v14.4.2",
                "hypothesis_score": {
                    "overall": 0.9,
                    "components": {
                        "pipeline": 0.8,
                        "english": 0.7,
                        "lua": 0.6,
                        "parity": 0.5,
                        "mapping": 0.4,
                    },
                },
            }
        ],
        "pipeline_confidence": 0.82,
        "version_hint": "v14.4.2",
        "parity_summary": {"success": True, "matching_prefix": 32, "limit": 64},
    }
    (out_dir / "pipeline_candidates.json").write_text(
        json.dumps(pipeline_payload), encoding="utf-8"
    )
    report_text = """# Detection Report
## Summary
* Example summary line
"""
    (out_dir / "detection_report.md").write_text(report_text, encoding="utf-8")

    result = subprocess.run(
        ["bash", str(SCRIPT), "--output-dir", str(out_dir)],
        check=True,
        text=True,
        capture_output=True,
    )
    output = result.stdout
    assert "Top pipeline candidate" in output
    assert "string-escape -> prga -> permute" in output
    assert "Confidence: 0.900" in output
    assert "Version guess (heuristics): v14.4.2" in output
    assert "Status: success (matching prefix 32/64)" in output
    assert "• * Example summary line" in output


def test_quick_status_handles_missing_pipeline(tmp_path):
    out_dir = tmp_path / "outputs"
    out_dir.mkdir()
    result = subprocess.run(
        ["bash", str(SCRIPT), "--output-dir", str(out_dir)],
        check=True,
        text=True,
        capture_output=True,
    )
    assert "No pipeline candidates" in result.stdout
