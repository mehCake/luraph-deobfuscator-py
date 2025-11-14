from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.tools.cleanup_temp import CleanupPlan, cleanup_intermediate_artifacts, main


def _make_entry(base: Path, name: str, *, age_days: float) -> Path:
    path = base / name
    path.mkdir(parents=True, exist_ok=True)
    when = datetime.now() - timedelta(days=age_days)
    ts = when.timestamp()
    os.utime(path, (ts, ts))
    return path


def test_cleanup_removes_entries_outside_policy(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    intermediate = out_dir / "intermediate"
    intermediate.mkdir(parents=True)

    newest = _make_entry(intermediate, "run-newest", age_days=0.1)
    kept_old = _make_entry(intermediate, "run-older-but-kept", age_days=6.0)
    stale = _make_entry(intermediate, "run-stale", age_days=10.0)
    older = _make_entry(intermediate, "run-older", age_days=12.0)

    plan = CleanupPlan(out_dir=out_dir, retention_days=7, keep_latest=2, dry_run=False)
    removed = cleanup_intermediate_artifacts(plan)

    assert set(removed) == {stale, older}
    assert newest.exists()
    assert kept_old.exists()  # kept because it is within ``keep_latest``
    assert not stale.exists()
    assert not older.exists()


def test_cleanup_dry_run_preserves_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    intermediate = out_dir / "intermediate"
    intermediate.mkdir(parents=True)
    target = _make_entry(intermediate, "run-old", age_days=30)

    plan = CleanupPlan(out_dir=out_dir, retention_days=7, keep_latest=0, dry_run=True)
    removed = cleanup_intermediate_artifacts(plan)

    assert removed == [target]
    assert target.exists()


def test_cli_returns_success(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    intermediate = out_dir / "intermediate"
    intermediate.mkdir(parents=True)
    _make_entry(intermediate, "run-old", age_days=30)

    exit_code = main([
        "--out-dir",
        str(out_dir),
        "--retention-days",
        "0",
        "--keep-latest",
        "0",
        "--dry-run",
    ])

    assert exit_code == 0
