from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("lupa", reason="lupa required for Lua fallback")

from src.bootstrap_decoder import BootstrapDecoder


def test_bootstrap_decoder_uses_lua_fallback(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/initv4_stub/initv4_fallback.lua")

    sandbox_dir = tmp_path / "lua"
    sandbox_dir.mkdir()
    target = sandbox_dir / "initv4.lua"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    ctx = SimpleNamespace(debug_bootstrap=True)
    decoder = BootstrapDecoder(ctx)
    result = decoder.run_extraction(str(target), b"x0496iike33votwu83qtw")

    assert result.success

    metadata = result.bootstrapper_metadata
    assert metadata.get("alphabet_len", 0) >= 80
    assert metadata.get("opcode_map_count", 0) >= 16
    assert "lua_fallback" in result.decoded_blobs

    notes = metadata.get("extraction_notes") or []
    assert any("lua-fallback" in note for note in notes)
    assert metadata.get("needs_emulation") is False
