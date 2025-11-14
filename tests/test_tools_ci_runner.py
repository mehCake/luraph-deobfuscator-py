from __future__ import annotations

import json
from pathlib import Path

from src.tools.ci_runner import run_ci_pipeline


def test_ci_runner_generates_expected_artefacts(monkeypatch, tmp_path):
    validation_calls: list[Path] = []

    def fake_validate_json_directory(path: Path, **_kwargs):
        validation_calls.append(path)
        return []

    monkeypatch.setattr(
        "src.tools.ci_runner.validate_json_directory",
        fake_validate_json_directory,
    )
    sample = Path("tests/samples/Obfuscated3.lua")
    parity_sample = Path("tests/parity/sample_lph.bin")

    result = run_ci_pipeline(
        [sample],
        parity_sample=parity_sample,
        output_dir=tmp_path,
        nightly=False,
    )

    assert result.samples, "at least one sample result should be recorded"
    sample_result = result.samples[0]

    assert sample_result.manifest_path.exists()
    assert sample_result.bootstrap_candidates.exists()
    assert sample_result.bytes_metadata.exists()
    assert sample_result.pipeline_report.exists()
    assert result.summary_path.exists()

    summary = json.loads(result.summary_path.read_text(encoding="utf-8"))
    assert summary["samples"], "summary should include sample entries"
    assert summary["samples"][0]["artefacts"]["manifest"].endswith("raw_manifest.json")

    assert result.parity_report is not None
    assert result.parity_report.exists()
    assert result.parity_success is True
    assert validation_calls


def test_ci_runner_supports_nightly_output(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.tools.ci_runner.validate_json_directory",
        lambda *_args, **_kwargs: [],
    )
    sample = Path("tests/samples/Obfuscated3.lua")

    result = run_ci_pipeline(
        [sample],
        output_dir=tmp_path,
        parity_sample=None,
        nightly=True,
    )

    # Timestamped nightly directory should be created beneath the output root.
    relative_parts = result.output_dir.relative_to(tmp_path).parts
    assert relative_parts[0] == "nightly"
    assert result.summary_path.exists()
