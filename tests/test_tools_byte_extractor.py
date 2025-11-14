"""Tests for byte extraction helpers used during bootstrap analysis."""

from __future__ import annotations

import json
from pathlib import Path

from src.tools.byte_extractor import (
    decode_candidate_snippet,
    generate_candidate_bytes,
    main,
)


def test_decode_candidate_snippet_handles_concat_and_unpack() -> None:
    snippet = "loadstring(string.char(table.unpack({0x40,0x41,0x42}, 2, 3)) .. \"\\x43\")"
    data = decode_candidate_snippet(snippet)
    assert data == b"ABC"


def test_generate_candidate_bytes_outputs_files(tmp_path: Path) -> None:
    candidates = [
        {
            "type": "loadstring",
            "snippet": "loadstring(\"\\x01\\x02\\x03\\x04\")",
            "start_offset": 10,
            "end_offset": 42,
            "confidence": 0.9,
        }
    ]
    manifest = tmp_path / "bootstrap_candidates.json"
    manifest.write_text(json.dumps(candidates, indent=2), encoding="utf-8")

    out_dir = tmp_path / "out"
    metadata = generate_candidate_bytes(manifest, out_dir)

    bytes_dir = out_dir / "bytes"
    payloads = list(bytes_dir.glob("*.bin"))
    assert len(payloads) == 1
    assert payloads[0].read_bytes() == b"\x01\x02\x03\x04"

    meta_path = bytes_dir / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta == metadata
    assert meta[0]["endianness_hint"] == "big"


def test_cli_invocation_creates_payloads(tmp_path: Path) -> None:
    candidates = [
        {
            "type": "numeric-array",
            "snippet": "{0x10,0x11,0x12,0x13}",
        }
    ]
    manifest = tmp_path / "bootstrap_candidates.json"
    manifest.write_text(json.dumps(candidates), encoding="utf-8")

    out_dir = tmp_path / "cli_out"
    exit_code = main([str(manifest), "--output-dir", str(out_dir)])
    assert exit_code == 0

    bytes_dir = out_dir / "bytes"
    files = list(bytes_dir.glob("*.bin"))
    assert files and files[0].read_bytes() == bytes([0x10, 0x11, 0x12, 0x13])
    meta = json.loads((bytes_dir / "meta.json").read_text(encoding="utf-8"))
    assert meta[0]["size"] == 4

