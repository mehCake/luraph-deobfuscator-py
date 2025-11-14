from __future__ import annotations

import base64
import json
from pathlib import Path

from src.decoders.constant_recover import decode_constants, write_constant_manifest


def test_base64_string_recovery(tmp_path: Path) -> None:
    payload = b"alpha\x00beta\x00gamma\x00"
    encoded = base64.b64encode(payload)
    result = decode_constants(encoded)
    assert result.data == payload
    assert result.stats["constant_count"] == 3
    values = [entry.value for entry in result.constants]
    assert values == ["alpha", "beta", "gamma"]


def test_prga_xor_stage(tmp_path: Path) -> None:
    plaintext = b"foo\x00bar\x00"
    masked = bytes(byte ^ 0x55 for byte in plaintext)
    profile = {"prga": {"mode": "xor", "value": 0x55}}
    result = decode_constants(masked, profile)
    assert result.data == plaintext
    assert any(stage.name.startswith("prga") for stage in result.stages)


def test_permutation_stage(tmp_path: Path) -> None:
    plaintext = b"ABCD"
    # permutation swaps pairs (1,0,3,2)
    permuted = bytes([plaintext[1], plaintext[0], plaintext[3], plaintext[2]])
    profile = {"permutation": {"table": [1, 0, 3, 2], "mode": "inverse"}}
    result = decode_constants(permuted, profile)
    assert result.data == plaintext
    assert result.stages[-1].name == "permute-table"


def test_manifest_writer(tmp_path: Path) -> None:
    payload = b"one\x00two\x00"
    result = decode_constants(payload)
    path = write_constant_manifest("sample", result, tmp_path)
    data = json.loads(path.read_text())
    assert data["candidate"] == "sample"
    assert data["constants"][0]["value"] == "one"
    assert Path(path).parent == tmp_path
