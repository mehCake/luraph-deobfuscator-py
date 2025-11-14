from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.tools.restore_backup import (
    RestoreBackupError,
    restore_backup,
)


def _write_backup(run_dir: Path, files: dict[str, str], contents: dict[str, str]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "backup_manifest.json").write_text(
        json.dumps({"files": files}, indent=2) + "\n", encoding="utf-8"
    )
    for filename, data in contents.items():
        (run_dir / filename).write_text(data, encoding="utf-8")


def test_restore_backup_success(tmp_path: Path) -> None:
    run_dir = tmp_path / "out" / "backups" / "run-test"
    files = {"original": "original.lua", "manifest": "manifest.json"}
    contents = {
        "original.lua": "print('ok')\n",
        "manifest.json": json.dumps({"value": 123}, indent=2),
    }
    _write_backup(run_dir, files, contents)

    result = restore_backup(run_dir, destination_root=tmp_path / "restored")

    assert result.restored_dir.exists()
    restored_original = result.restored_dir / "original.lua"
    assert restored_original.read_text(encoding="utf-8") == "print('ok')\n"
    assert all(item.destination.exists() for item in result.files)


def test_restore_backup_detects_key(tmp_path: Path) -> None:
    run_dir = tmp_path / "out" / "backups" / "run-key"
    files = {"manifest": "manifest.json"}
    contents = {"manifest.json": json.dumps({"key": "secret"})}
    _write_backup(run_dir, files, contents)

    with pytest.raises(RestoreBackupError):
        restore_backup(run_dir)


def test_restore_backup_cli(tmp_path: Path) -> None:
    run_dir = tmp_path / "out" / "backups" / "run-cli"
    files = {"original": "original.lua"}
    contents = {"original.lua": "print('cli')\n"}
    _write_backup(run_dir, files, contents)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.tools.restore_backup",
            str(run_dir),
            "--list",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "original.lua" in result.stdout
