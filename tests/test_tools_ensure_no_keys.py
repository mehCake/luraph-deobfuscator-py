from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.tools.ensure_no_keys import KeyLeakError, ensure_no_keys, main as ensure_no_keys_main


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_no_violation_for_empty_values(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    _write_json(out_dir / "ok.json", {"key": "", "secret": None, "token": []})

    assert ensure_no_keys(out_dir) == []


def test_detects_nested_key_leaks(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    payload = {
        "pipelines": [
            {"metadata": {"KEY": "TINY-SECRET"}},
            {"nested": {"Token": {"value": "abc"}}},
        ]
    }
    _write_json(out_dir / "report.json", payload)

    with pytest.raises(KeyLeakError) as excinfo:
        ensure_no_keys(out_dir)

    violations = excinfo.value.violations
    assert len(violations) == 2
    paths = {violation.field_path for violation in violations}
    assert paths == {"/pipelines/0/metadata/KEY", "/pipelines/1/nested/Token"}


def test_cli_returns_error_code(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    out_dir = tmp_path / "out"
    _write_json(out_dir / "profile.json", {"secret": "hunter2"})

    caplog.set_level(logging.ERROR)
    exit_code = ensure_no_keys_main(["--base-dir", str(out_dir)])

    assert exit_code == 1
    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "profile.json" in messages
