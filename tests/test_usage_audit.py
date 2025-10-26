from __future__ import annotations

from pathlib import Path

import pytest

from src.usage_audit import (
    UsageConfirmationError,
    load_audit_entries,
    require_usage_confirmation,
)


def _make_input(tmp_path: Path) -> Path:
    target = tmp_path / "sample.lua"
    target.write_text("return 1", encoding="utf-8")
    return target


def test_usage_confirmation_requires_flags(tmp_path: Path) -> None:
    sample = _make_input(tmp_path)
    with pytest.raises(UsageConfirmationError):
        require_usage_confirmation(
            confirm_ownership=False,
            confirm_voluntary_key=True,
            inputs=[sample],
        )

    with pytest.raises(UsageConfirmationError):
        require_usage_confirmation(
            confirm_ownership=True,
            confirm_voluntary_key=False,
            inputs=[sample],
        )


def test_usage_confirmation_writes_encrypted_log(tmp_path: Path) -> None:
    sample = _make_input(tmp_path)
    log_path = tmp_path / "audit.log"
    result = require_usage_confirmation(
        confirm_ownership=True,
        confirm_voluntary_key=True,
        inputs=[sample],
        operator="analyst",
        script_key="sample-key",
        audit_log=log_path,
        audit_passphrase="secret",
    )

    assert result.log_path == log_path.resolve()
    entries = load_audit_entries(log_path, "secret")
    assert entries
    latest = entries[-1]
    assert latest["operator"] == "analyst"
    key_meta = latest.get("key", {})
    assert key_meta.get("present") is True
    assert "digest" in key_meta and "salt" in key_meta


def test_load_audit_entries_requires_passphrase_for_encrypted(tmp_path: Path) -> None:
    sample = _make_input(tmp_path)
    log_path = tmp_path / "audit.log"
    require_usage_confirmation(
        confirm_ownership=True,
        confirm_voluntary_key=True,
        inputs=[sample],
        audit_log=log_path,
        audit_passphrase="secret",
    )

    with pytest.raises(UsageConfirmationError):
        load_audit_entries(log_path)
