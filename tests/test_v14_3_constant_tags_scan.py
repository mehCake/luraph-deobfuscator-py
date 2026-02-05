import json
from pathlib import Path

import pytest

from src.versions.v14_3_loader import (
    analyze_v14_3_constant_tags_for_real_payload,
    extract_v14_3_serialized_chunk_bytes_from_source,
    scan_v14_3_constant_tags,
)
from tests.fixtures.v14_3_serialized_chunk_fixture import (
    SERIALIZED_CHUNK_BYTES,
)


def test_scan_tags_fixture_reports_expected_set():
    summary = scan_v14_3_constant_tags(SERIALIZED_CHUNK_BYTES)
    assert summary["counts"][0x01] == 1
    assert summary["counts"][0x02] == 2
    assert summary["counts"][0x03] == 3
    assert summary["counts"][0x04] == 1
    assert summary["counts"][0x05] == 2
    assert summary["counts"][0x06] == 1
    assert summary["unique_tags"] == [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
    assert summary["errors"] == []
    assert summary["scanned_constants"] == 10


def test_scan_tags_real_payload_detects_unknown_tag():
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8")
    _, data = extract_v14_3_serialized_chunk_bytes_from_source(source)
    summary = scan_v14_3_constant_tags(data, max_constants=8)
    assert summary["counts"]
    assert any(tag >= 0x80 for tag in summary["unique_tags"])
    assert summary["scanned_constants"] <= 8


@pytest.mark.parametrize("output", ["analysis/tags.json"])
def test_analyze_helper_emits_file(tmp_path, output):
    output_path = tmp_path / Path(output)
    result = analyze_v14_3_constant_tags_for_real_payload(output_json=output_path)
    assert output_path.exists()
    written = json.loads(output_path.read_text(encoding="utf-8"))
    written_counts = {int(key): value for key, value in written["counts"].items()}
    assert written_counts == result["counts"]
