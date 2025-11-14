from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.tools.transform_profile import load_profile
from src.tools.upgrade_profile import UpgradeResult, main as upgrade_profile_main, upgrade_profile


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_upgrade_profile_normalises_structure(tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.json"
    original_payload = {
        "version": "0.5",
        "permute": [2, 0, 1],
        "prga": {"rotate": 3},
        "opcode_map_id": "legacy",
        "note": "legacy entry",
        "key": "SHOULD-NOT-STAY",
    }
    _write_json(profile_path, original_payload)

    result = upgrade_profile(profile_path)

    assert isinstance(result, UpgradeResult)
    assert result.updated is True
    assert result.would_update is True
    assert result.removed_sensitive_fields == ["/key"]
    assert result.log_path.exists()
    log_lines = [line for line in result.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(log_lines) == 1

    upgraded = json.loads(profile_path.read_text(encoding="utf-8"))
    assert "key" not in upgraded
    assert "permute_table" in upgraded
    assert upgraded["version"] == load_profile(profile_path).version


def test_upgrade_profile_is_idempotent(tmp_path: Path) -> None:
    profile_path = tmp_path / "profile.json"
    _write_json(profile_path, {"version": "1.0", "permute_table": [0, 1, 2]})

    first = upgrade_profile(profile_path)
    assert first.updated is False
    assert first.would_update is False

    # Running again should not append to log
    second = upgrade_profile(profile_path)
    assert second.updated is False
    assert second.would_update is False
    assert not second.log_path.exists() or second.log_path.read_text(encoding="utf-8").strip() == ""


def test_upgrade_profile_dry_run(tmp_path: Path) -> None:
    profile_path = tmp_path / "legacy.json"
    _write_json(profile_path, {"version": "0.1", "secret": "keep", "permute": [1, 0]})

    result = upgrade_profile(profile_path, dry_run=True)

    assert result.updated is False
    assert result.would_update is True
    assert result.removed_sensitive_fields == ["/secret"]
    assert not result.log_path.exists()
    assert "secret" in profile_path.read_text(encoding="utf-8")


def test_upgrade_profile_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    profile_path = tmp_path / "cli_profile.json"
    _write_json(profile_path, {"permute": [0, 1], "token": "EXPOSED"})

    exit_code = upgrade_profile_main([str(profile_path)])
    assert exit_code == 0

    upgraded = json.loads(profile_path.read_text(encoding="utf-8"))
    assert "token" not in upgraded
    captured = capsys.readouterr().out
    assert "Profile upgraded" in captured
