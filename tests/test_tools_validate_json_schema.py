from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.tools.validate_json_schema import (
    SchemaValidationError,
    validate_json_directory,
)


def _write_metrics_payload(base: Path, payload: dict[str, object]) -> Path:
    metrics_dir = base / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)
    path = metrics_dir / "sample.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _minimal_metrics_payload() -> dict[str, object]:
    return {
        "run_id": "test",
        "created_at": "2024-01-01T00:00:00",
        "runtime_seconds": 0.5,
        "max_rss_kib": None,
        "step_counts": {},
        "metrics": {},
        "extra": {},
    }


def test_validate_json_directory_success(tmp_path: Path) -> None:
    _write_metrics_payload(tmp_path, _minimal_metrics_payload())

    issues = validate_json_directory(tmp_path)

    assert issues == []


def test_validate_json_directory_failure(tmp_path: Path) -> None:
    payload = _minimal_metrics_payload()
    payload.pop("runtime_seconds")
    _write_metrics_payload(tmp_path, payload)

    with pytest.raises(SchemaValidationError) as excinfo:
        validate_json_directory(tmp_path)

    assert any(issue.path.endswith("runtime_seconds") for issue in excinfo.value.issues)


def test_validate_json_directory_strict_unknown(tmp_path: Path) -> None:
    unknown = tmp_path / "unexpected.json"
    unknown.write_text("{}", encoding="utf-8")

    issues = validate_json_directory(tmp_path, strict=True, raise_on_error=False)

    assert len(issues) == 1
    assert "no schema" in issues[0].message


def test_validate_json_schema_cli(tmp_path: Path) -> None:
    _write_metrics_payload(tmp_path, _minimal_metrics_payload())

    result = subprocess.run(
        [sys.executable, "-m", "src.tools.validate_json_schema", "--base-dir", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
