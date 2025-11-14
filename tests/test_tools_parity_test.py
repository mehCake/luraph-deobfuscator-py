"""Unit tests covering parity harness utilities."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.tools.parity_test import (
    DEFAULT_COMPARE_LIMIT,
    ParityMismatchError,
    _compare_prefix,
    _read_sample,
    run_prga_parity,
)


def test_compare_prefix_uses_wide_context() -> None:
    py_bytes = bytes(range(32))
    lua_bytes = bytearray(py_bytes)
    lua_bytes[10] ^= 0xFF

    with pytest.raises(ParityMismatchError) as excinfo:
        _compare_prefix(py_bytes, bytes(lua_bytes), limit=DEFAULT_COMPARE_LIMIT)

    mismatch = excinfo.value
    # 16 surrounding bytes -> 32 hex characters at most
    assert len(mismatch.context_py) <= 32
    assert len(mismatch.context_lua) <= 32
    assert mismatch.index == 10


def test_run_parity_zeroizes_key_override() -> None:
    sample_path = Path("tests/parity/sample_lph.bin")
    sample = _read_sample(sample_path)
    key_override = bytearray(sample.key)

    py_bytes, lua_bytes = run_prga_parity(
        sample_path,
        limit=DEFAULT_COMPARE_LIMIT,
        enable_bruteforce=False,
        report_path=None,
        intermediate_dir=None,
        key_override=key_override,
        scrub_override=True,
        raise_on_mismatch=True,
        redact_keys=True,
    )

    assert py_bytes == lua_bytes
    assert all(b == 0 for b in key_override), "CLI key buffers must be wiped"
