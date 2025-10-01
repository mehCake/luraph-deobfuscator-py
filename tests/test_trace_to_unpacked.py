from __future__ import annotations

import base64
from pathlib import Path

import pytest

from src.runtime_capture import trace_to_unpacked


def test_convert_json_buffer(tmp_path: Path) -> None:
    payload = {"4": [[None, None, 1]], "5": []}
    path = tmp_path / "dump.json"
    path.write_text('{"4": [[null, null, 1]], "5": []}', encoding="utf-8")
    result = trace_to_unpacked.convert_file(path)
    assert result["4"][0][2] == 1


def test_convert_lua_bytecode(tmp_path: Path) -> None:
    blob = b"\x1bLua" + b"\x00" * 8
    path = tmp_path / "bytecode.bin"
    path.write_bytes(blob)
    result = trace_to_unpacked.convert_file(path)
    assert result["format"] == "lua_bytecode"
    assert base64.b64decode(result["blob_b64"]) == blob


def test_convert_vm_words(tmp_path: Path) -> None:
    data = (0).to_bytes(2, "little") + (4).to_bytes(2, "little") + b"\x00\x00\x00\x00"
    path = tmp_path / "vm.bin"
    path.write_bytes(data * 2)
    result = trace_to_unpacked.convert_file(path)
    assert result["4"][0][2] == 4
    assert len(result["4"]) == 2


@pytest.mark.parametrize("bad", [b"abc", b"12345"])
def test_convert_invalid_vm(bad: bytes) -> None:
    with pytest.raises(ValueError):
        trace_to_unpacked.convert_bytes(bad)
