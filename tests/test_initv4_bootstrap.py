from __future__ import annotations

from pathlib import Path

from src.versions.initv4 import InitV4Bootstrap
from src.versions.luraph_v14_2_json import LuraphV142JSON


def test_initv4_bootstrap_detects_alphabet_and_mapping(tmp_path: Path) -> None:
    fixture = Path("tests/fixtures/initv4_stub/initv4.lua")
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir()
    target = stub_dir / "initv4.lua"
    target.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")

    bootstrap = InitV4Bootstrap.load(stub_dir)
    assert bootstrap.path == target

    alphabet = bootstrap.alphabet()
    assert alphabet is not None
    assert len(alphabet) >= 85

    base_table = LuraphV142JSON().opcode_table()
    mapping = bootstrap.opcode_mapping(base_table)
    assert mapping.get("MOVE") == 0x10
    assert mapping.get("FORLOOP") == 0x2A

    table = bootstrap.build_opcode_table(base_table)
    assert table[0x10].mnemonic == "MOVE"
    assert table[0x2A].mnemonic == "FORLOOP"

    meta = dict(bootstrap.iter_metadata())
    assert meta.get("alphabet_length") == len(alphabet)
