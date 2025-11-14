from __future__ import annotations

import json
from pathlib import Path

from src.tools.generate_ci_smoke_test import SmokeScenario, run_smoke_tests


def test_smoke_test_runner_handles_empty_input(tmp_path: Path) -> None:
    scenario = SmokeScenario(name="empty", description="Empty file", payload="")
    output_dir = tmp_path / "smoke"

    report = run_smoke_tests(
        scenarios=[scenario],
        output_dir=output_dir,
        keep_samples=False,
    )

    assert report.success
    assert report.report_path.exists()

    data = json.loads(report.report_path.read_text(encoding="utf-8"))
    assert data["success"] is True
    assert data["scenarios"][0]["success"] is True

    sample_path = output_dir / "samples" / "empty.lua"
    assert not sample_path.exists()

    artefacts = report.results[0].artefacts
    assert artefacts is not None
    assert artefacts.report_md.exists()
