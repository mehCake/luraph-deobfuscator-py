"""Lua fallback integration tests for the bootstrap decoder."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_BOOTSTRAP_LUA_TESTS") != "1",
    reason="Set RUN_BOOTSTRAP_LUA_TESTS=1 to enable Lua fallback tests.",
)

if os.environ.get("RUN_BOOTSTRAP_LUA_TESTS") == "1":  # pragma: no cover - gated import
    pytest.importorskip("lupa", reason="lupa required for Lua fallback tests")

from src.bootstrap_decoder import BootstrapDecoder


def test_bootstrap_decoder_lua_fallback(tmp_path: Path) -> None:
    """Exercise the sandboxed Lua path against the reference bootstrapper."""

    project_root = Path(__file__).resolve().parents[1]
    bootstrap_path = project_root / "initv4.lua"
    if not bootstrap_path.exists():
        pytest.skip("initv4.lua not present in project root")

    target = tmp_path / "initv4.lua"
    target.write_text(bootstrap_path.read_text(encoding="utf-8"), encoding="utf-8")

    ctx = SimpleNamespace(
        debug_bootstrap=True,
        allow_lua_run=True,
        logs_dir=tmp_path / "logs",
    )
    decoder = BootstrapDecoder(ctx, str(target), "x0496iike33votwu83qtw")
    result = decoder.run_full_extraction()

    assert result.success, result.errors

    metadata = result.bootstrapper_metadata
    assert metadata.get("alphabet_len", 0) > 80
    assert metadata.get("opcode_map_count", 0) >= 16
    assert not metadata.get("needs_emulation"), metadata.get("extraction_notes")
    assert metadata.get("extraction_method") == "lua_fallback"
    assert metadata.get("extraction_log")

