from __future__ import annotations

from pathlib import Path

import pytest

from src.tests import bootstrap_inspect


SAMPLES_DIR = Path("tests/samples")


def test_bootstrap_inspect_obfuscated3(tmp_path):
    sample = SAMPLES_DIR / "Obfuscated3.lua"
    report = bootstrap_inspect.inspect_payload(sample, output_dir=tmp_path)

    assert report["pipeline"], "pipeline should not be empty"
    assert "string.char" in report["summary"]
    assert "loadstring" in report["summary"]

    detection_report = Path(report["detection_report"])
    assert detection_report.exists()
    contents = detection_report.read_text(encoding="utf-8")
    assert "Pipeline operations" in contents
    assert "Suggested next steps" in contents


def test_bootstrap_inspect_rejects_unexpected_structure(tmp_path):
    sample = SAMPLES_DIR / "minimal_stub.lua"
    with pytest.raises(bootstrap_inspect.InspectionError):
        bootstrap_inspect.inspect_payload(sample, output_dir=tmp_path)
