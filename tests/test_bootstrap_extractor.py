from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from src.bootstrap_extractor import BootstrapExtractor

STUB_PATH = Path("tests/fixtures/initv4_stub/initv4.lua")
STUB_TEXT = STUB_PATH.read_text(encoding="utf-8")


def _extract(debug: bool = False):
    ctx = SimpleNamespace(debug_bootstrap=debug)
    extractor = BootstrapExtractor(ctx)
    return extractor.extract(STUB_TEXT)


def test_bootstrap_extractor_alphabet() -> None:
    meta = _extract()
    alphabet = meta.get("alphabet")
    assert alphabet is not None
    assert len(alphabet) >= 85
    assert alphabet.startswith("0123456789")


def test_bootstrap_extractor_opcodes() -> None:
    meta = _extract()
    opcode_map = meta.get("opcode_map") or {}
    assert len(opcode_map) >= 16
    assert opcode_map.get(0x10) == "MOVE"
    assert opcode_map.get(0x2B) == "TFORLOOP"
    assert opcode_map.get(0x2C) == "SETLIST"


def test_bootstrap_extractor_constants() -> None:
    meta = _extract()
    constants = meta.get("constants") or {}
    assert constants.get("MAXSTACK") == 250
    assert constants.get("NUPVAL") == 12
    assert constants.get("NUM_REGS") == 255
    assert constants.get("DISPATCH_ENTRIES") == 46


def test_bootstrap_extractor_raw_matches_in_debug_mode() -> None:
    meta = _extract(debug=True)
    raw_matches = meta.get("raw_matches") or {}
    assert raw_matches.get("alphabets")
    assert raw_matches.get("opcodes")
    assert raw_matches.get("constants")
