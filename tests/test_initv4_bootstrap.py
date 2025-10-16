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

    extracted_alphabet, extracted_mapping, opcode_table, summary = bootstrap.extract_metadata(
        base_table,
        debug=False,
    )
    assert extracted_alphabet == alphabet
    assert extracted_mapping.get("MOVE") == 0x10
    assert opcode_table[0x2A].mnemonic == "FORLOOP"
    extraction_meta = summary.get("extraction") or {}
    assert extraction_meta.get("opcode_dispatch", {}).get("count", 0) >= len(opcode_table)


def test_metatable_handler_detection_in_summary() -> None:
    text = """
    local mt = {}
    mt.__index = function(tbl, key) return rawget(tbl, key) end
    mt["__newindex"] = function(tbl, key, value) rawset(tbl, key, value) end
    local t = {}
    setmetatable(t, mt)
    """

    bootstrap = InitV4Bootstrap(Path("dummy.lua"), text)
    base_table = LuraphV142JSON().opcode_table()

    _, _, _, summary = bootstrap.extract_metadata(base_table)

    assert summary.get("has_metatable_flow") is True
    handlers = summary.get("metatable_handlers")
    assert handlers and handlers.get("__index") == 1 and handlers.get("__newindex") == 1
    assert summary.get("setmetatable_calls") == 1

    meta = dict(bootstrap.iter_metadata())
    assert meta.get("has_metatable_flow") is True
    handler_meta = meta.get("metatable_handlers") or {}
    assert handler_meta.get("__index") == 1
    assert handler_meta.get("__newindex") == 1


def test_metatable_handlers_without_setmetatable_still_flagged() -> None:
    text = """
    local mt = {}
    mt.__index = function(tbl, key) return rawget(tbl, key) end
    return mt
    """

    bootstrap = InitV4Bootstrap(Path("dummy.lua"), text)
    base_table = LuraphV142JSON().opcode_table()

    _, _, _, summary = bootstrap.extract_metadata(base_table)

    assert summary.get("has_metatable_flow") is True
    handlers = summary.get("metatable_handlers") or {}
    assert handlers.get("__index") == 1
    assert summary.get("setmetatable_calls") is None

    meta = dict(bootstrap.iter_metadata())
    assert meta.get("has_metatable_flow") is True
    handler_meta = meta.get("metatable_handlers") or {}
    assert handler_meta.get("__index") == 1
