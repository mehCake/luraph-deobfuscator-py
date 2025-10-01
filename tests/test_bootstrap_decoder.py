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

    ctx = SimpleNamespace(debug_bootstrap=True, allow_lua_run=True)
    decoder = BootstrapDecoder(ctx, str(target), "ug7bdorqbifndbz6yj0o4a")
    result = decoder.run_full_extraction()

    assert result.success

    metadata = result.bootstrapper_metadata
    assert metadata.get("alphabet_len", 0) >= 80
    assert metadata.get("opcode_map_count", 0) >= 16
    preview = metadata.get("alphabet_preview")
    assert isinstance(preview, str) and preview
    sample = metadata.get("opcode_map_sample")
    assert isinstance(sample, list) and sample
    confidence = metadata.get("extraction_confidence")
    assert confidence in {"high", "medium", "low"}
    assert metadata.get("function_name_source") in {"read", "mixed", "inferred"}
    assert "encoded" in result.decoded_blobs

    notes = metadata.get("extraction_notes") or []
    assert any("lua-fallback" in note for note in notes)
    assert metadata.get("needs_emulation") is False
    assert metadata.get("extraction_method") in {"lua_fallback", "lua_sandbox"}
    assert metadata.get("extraction_log")
