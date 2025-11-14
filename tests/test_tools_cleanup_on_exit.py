from __future__ import annotations

from pathlib import Path

import pytest

from src.tools.cleanup_on_exit import get_cleanup_manager


@pytest.fixture(autouse=True)
def _reset_cleanup_manager() -> None:
    manager = get_cleanup_manager()
    manager.reset_state_for_tests()
    yield
    manager.reset_state_for_tests()


def test_finalize_success_preserves_debug_paths(tmp_path: Path) -> None:
    manager = get_cleanup_manager()

    debug_dir = tmp_path / "debug"
    debug_dir.mkdir()

    key_buffer = bytearray(b"temporary-key")
    manager.register_temp_path(debug_dir)
    manager.register_key_buffer("session", key_buffer)

    manager.finalize(successful=True)

    assert debug_dir.exists(), "debug directory should be preserved on success"
    assert all(byte == 0 for byte in key_buffer), "key buffer must be wiped"


def test_forced_cleanup_removes_registered_paths(tmp_path: Path) -> None:
    manager = get_cleanup_manager()

    payload_file = tmp_path / "payload.bin"
    payload_file.write_bytes(b"secret payload bytes")

    manager.register_temp_path(payload_file, secure_wipe=True)
    manager.cleanup(reason="test", forced=True, successful=False)

    assert not payload_file.exists()


def test_register_after_finalize_allows_subsequent_cleanup(tmp_path: Path) -> None:
    manager = get_cleanup_manager()

    first_file = tmp_path / "first.bin"
    first_file.write_bytes(b"data")
    manager.register_temp_path(first_file)
    manager.finalize(successful=True)

    second_file = tmp_path / "second.bin"
    second_file.write_bytes(b"data")
    manager.register_temp_path(second_file)

    manager.cleanup(reason="forced", forced=True, successful=False)

    assert not second_file.exists()
