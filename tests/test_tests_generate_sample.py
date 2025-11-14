from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.tests.generate_sample import generate_sample_from_spec


def _expected_prga(data: bytes, key: bytes, rotate: int, xor_seed: int, bias: int) -> bytes:
    result = bytearray(len(data))
    for index, value in enumerate(data):
        mixed = value ^ key[index % len(key)]
        if rotate:
            rotate = rotate % 8
            mixed = ((mixed << rotate) | (mixed >> (8 - rotate))) & 0xFF
        if xor_seed:
            mixed ^= xor_seed & 0xFF
        if bias:
            mixed = (mixed + bias) & 0xFF
        result[index] = mixed
    return bytes(result)


def _expected_permutation(data: bytes, table: list[int]) -> bytes:
    block = len(table)
    padded = bytearray(data)
    remainder = len(padded) % block
    if remainder:
        padded.extend([0] * (block - remainder))
    output = bytearray(len(padded))
    for block_index in range(len(padded) // block):
        offset = block_index * block
        chunk = padded[offset : offset + block]
        for dest, src in enumerate(table):
            output[offset + dest] = chunk[src]
    return bytes(output)


def _write_spec(tmp_path: Path) -> Path:
    spec = {
        "name": "unit_pipeline",
        "base_payload": {"kind": "text", "value": "hi"},
        "operations": [
            {"type": "prga", "key": [1, 2, 3], "rotate": 1, "xor": 5},
            {"type": "permute", "table": [1, 0, 2], "block": 3},
            {"type": "pack", "style": "string_char", "chunk": 4},
        ],
    }
    spec_path = tmp_path / "sample.yaml"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    return spec_path


def test_generate_sample_outputs(tmp_path: Path) -> None:
    spec_path = _write_spec(tmp_path)
    result = generate_sample_from_spec(spec_path, tmp_path)

    assert result.binary_path.exists()
    assert result.lua_path.exists()
    metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
    first_operation = metadata["operations"][0]
    assert "key" in first_operation
    assert first_operation["key"]["redacted"] is True

    base = b"hi"
    expected = _expected_prga(base, bytes([1, 2, 3]), 1, 5, 0)
    expected = _expected_permutation(expected, [1, 0, 2])
    assert result.binary_path.read_bytes().startswith(expected[: len(base)])

    lua_text = result.lua_path.read_text(encoding="utf-8")
    assert "string.char" in lua_text
    assert "Synthetic sample" in lua_text


@pytest.mark.parametrize("flag", [["--list-only"], []])
def test_cli_execution(tmp_path: Path, flag: list[str]) -> None:
    spec_path = _write_spec(tmp_path)
    cmd = [sys.executable, "-m", "src.tests.generate_sample", str(spec_path), "--output-dir", str(tmp_path)] + flag
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    assert completed.returncode == 0
    if flag:
        assert "Sample:" in completed.stdout
    else:
        data = json.loads(completed.stdout)
        assert Path(data["binary"]).exists()
        assert Path(data["lua"]).exists()


def test_repo_spec_round_trip(tmp_path: Path) -> None:
    spec_path = Path("tests/samples/pipelines/v14_4_2_sample.yaml")
    result = generate_sample_from_spec(spec_path, tmp_path)
    assert result.binary_path.exists()
    metadata = json.loads(result.metadata_path.read_text(encoding="utf-8"))
    assert metadata["pack"]["style"] == "string_char"
