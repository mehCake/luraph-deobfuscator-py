"""Tests for the v14.3 blob analysis helpers."""

from __future__ import annotations

from pathlib import Path

from src.versions import v14_3_loader
from tests.fixtures.v14_3_serialized_chunk_fixture import (
    SERIALIZED_CHUNK_BYTES,
)


def _load_real_blob() -> bytes:
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    descriptor, data = v14_3_loader.extract_v14_3_serialized_chunk_bytes_from_source(source)
    assert descriptor.buffer_name  # basic sanity check
    return data


def test_dump_bytes_preview_emits_rows() -> None:
    data = b"Hello, world!" * 2
    preview = v14_3_loader.dump_bytes_preview(data, length=16, width=8)
    assert preview["preview_length"] == 16
    assert len(preview["rows"]) == 2
    assert preview["rows"][0]["ascii"].startswith("Hello")


def test_probe_fixture_blob_reports_varints() -> None:
    probe = v14_3_loader.probe_v14_3_blob(SERIALIZED_CHUNK_BYTES, bytes_preview=64, varint_count=6)
    assert probe["bytes_preview"]["rows"], "expected byte preview rows"
    assert probe["varints"], "expected some decoded varints"
    assert probe["varint_patterns"]["count"] >= len(probe["varints"]) - 1
    assert probe["section_guesses"], "heuristics should label entries"


def test_probe_real_blob_outputs_files(tmp_path) -> None:
    data = _load_real_blob()
    output_json = tmp_path / "probe.json"
    output_text = tmp_path / "probe.txt"
    probe = v14_3_loader.probe_v14_3_blob(
        data,
        bytes_preview=128,
        varint_count=10,
        output_json=output_json,
        output_text=output_text,
    )
    assert output_json.read_text(encoding="utf-8")
    assert output_text.read_text(encoding="utf-8")
    assert probe["bytes_preview"]["preview_length"] <= 128
    assert probe["varints"], "expected real blob varints"
    assert probe["ascii_sequences"] is not None
    assert probe["section_guesses"], "expected section guesses for real blob"
