"""Tests for the compare_outputs helper."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from src.tools.compare_outputs import compare_outputs


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_compare_outputs_detects_categories(tmp_path: Path) -> None:
    before = _write(
        tmp_path / "before.lua",
        """
local x = 1
if x > 0 then
    return x
end
""".strip()
        + "\n",
    )
    after = _write(
        tmp_path / "after.lua",
        """
local x = 2
while x > 0 do
    return x - 1
end
""".strip()
        + "\n",
    )

    out_dir = tmp_path / "diffs"
    result = compare_outputs(before, after, output_dir=out_dir, label_a="orig", label_b="patched")

    assert result.total_changes > 0
    # The loop transformation should be flagged as control-flow.
    assert result.control_flow_changes >= 1
    # Constants differ on the first line and inside the return expression.
    assert result.constant_changes >= 1
    assert result.html_report.exists()
    assert result.summary_report.exists()
    assert result.json_report.exists()

    summary = json.loads(result.json_report.read_text(encoding="utf-8"))
    assert summary["label_a"] == "orig"
    assert summary["label_b"] == "patched"
    # Sanity-check that the JSON serialisation includes our captured diff entries.
    assert any(diff["category"] == "control_flow" for diff in summary["differences"])


def test_compare_outputs_cli(tmp_path: Path) -> None:
    before = _write(tmp_path / "cli_before.lua", "return 1\n")
    after = _write(tmp_path / "cli_after.lua", "return 2\n")
    out_dir = tmp_path / "cli_out"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.tools.compare_outputs",
            str(before),
            str(after),
            "--out-dir",
            str(out_dir),
            "--label-a",
            "baseline",
            "--label-b",
            "candidate",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Total changes" in completed.stdout
    html_files = list(out_dir.glob("*.html"))
    assert html_files, "expected HTML diff artefact to be generated"
