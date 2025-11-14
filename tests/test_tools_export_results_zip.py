import json
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

from src.tools.export_results_zip import ExportResultsError, export_results_zip


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_export_results_excludes_key_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    write(out_dir / "good.txt", "hello")
    write(out_dir / "secret_key.bin", "should skip")
    write(out_dir / "nested" / "manifest.json", json.dumps({"value": 10}))
    write(out_dir / "nested" / "has_key.json", json.dumps({"key": "secret"}))

    summary = export_results_zip(
        source_dir=out_dir,
        runs_dir=tmp_path / "runs",
        timestamp=datetime(2024, 1, 2, 3, 4, 5),
    )

    assert summary.archive_path.name == "run-20240102-030405.zip"
    assert summary.included == [out_dir / "good.txt", out_dir / "nested" / "manifest.json"]
    skipped_paths = {path.name for path, _ in summary.skipped}
    assert skipped_paths == {"secret_key.bin", "has_key.json"}

    with zipfile.ZipFile(summary.archive_path) as zf:
        assert sorted(zf.namelist()) == ["good.txt", "nested/manifest.json"]


def test_export_results_dry_run(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    write(out_dir / "file.txt", "data")

    summary = export_results_zip(
        source_dir=out_dir,
        runs_dir=tmp_path / "runs",
        timestamp=datetime(2024, 6, 1, 0, 0, 0),
        dry_run=True,
    )

    assert summary.dry_run is True
    assert not summary.archive_path.exists()
    assert summary.included == [out_dir / "file.txt"]


def test_export_results_errors_when_no_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(ExportResultsError):
        export_results_zip(source_dir=out_dir, runs_dir=tmp_path / "runs")
