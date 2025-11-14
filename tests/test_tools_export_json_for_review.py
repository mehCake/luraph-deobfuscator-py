import json
from datetime import datetime
from pathlib import Path

import pytest

from src.tools.export_json_for_review import (
    ExportJsonForReviewError,
    export_json_for_review,
    main as run_export_json_for_review,
)


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_export_json_for_review_basic(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    write_json(
        out_dir / "pipeline_candidates.json",
        {
            "pipelines": [
                {"name": "candidate", "confidence": 0.9, "session_key": "TINY-123"},
            ],
            "session_key": "TINY-123",
        },
    )
    write_json(out_dir / "bootstrap_candidates.json", [{"kind": "chunk", "start": 1}])
    write_json(out_dir / "mapping_candidates.json", {"candidates": []})
    write_json(out_dir / "bytes" / "meta.json", {"entries": [1, 2, 3]})
    write_json(out_dir / "transform_profile.json", {"profile": {"version": "v14.4.2"}})

    metrics_dir = out_dir / "metrics"
    write_json(metrics_dir / "run-20240101.json", {"metrics": {"peak": 1}})
    write_json(metrics_dir / "run-20240102.json", {"metrics": {"peak": 2, "api_key": "hidden"}})

    runs_dir = out_dir / "runs"
    write_json(runs_dir / "run-20240102.manifest.json", {"id": "run-1", "secret_note": "drop"})

    summary = export_json_for_review(
        out_dir=out_dir,
        dest_dir=tmp_path / "exports",
        timestamp=datetime(2024, 1, 3, 4, 5, 6),
    )

    assert summary.package_path.name == "review-json-20240103-040506.json"
    assert "pipeline_report" in summary.included
    assert "metrics_report" in summary.included

    exported = json.loads(summary.package_path.read_text(encoding="utf-8"))
    pipeline = exported["artefacts"]["pipeline_report"]
    assert "session_key" not in pipeline
    assert "session_key" not in pipeline["pipelines"][0]

    metrics = exported["artefacts"]["metrics_report"]
    assert metrics == {"metrics": {"peak": 2}}

    manifest = exported["artefacts"]["run_manifest"]
    assert manifest == {"id": "run-1"}


def test_export_json_for_review_missing_required(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    with pytest.raises(ExportJsonForReviewError):
        export_json_for_review(out_dir=out_dir, dest_dir=tmp_path / "exports")


def test_cli_export_json_for_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    write_json(out_dir / "pipeline_candidates.json", {"pipelines": []})

    exports_dir = tmp_path / "exports"

    exit_code = run_export_json_for_review(
        ["--out-dir", str(out_dir), "--dest-dir", str(exports_dir), "--dry-run"]
    )
    assert exit_code == 0

    summary = export_json_for_review(
        out_dir=out_dir,
        dest_dir=exports_dir,
        timestamp=datetime(2024, 2, 1, 0, 0, 0),
    )
    assert summary.package_path.exists()
