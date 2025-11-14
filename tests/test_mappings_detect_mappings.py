import json
from pathlib import Path

from src.mappings.detect_mappings import detect_mapping_candidates, main


def test_detect_mapping_candidates_table_and_bytes(tmp_path) -> None:
    chunks = [
        {
            "text": "local perm = {1, 0, 3, 2}",
        }
    ]

    byte_entry = {
        "name": "perm_table",
        "payload": bytes([2, 0, 1, 3]),
        "metadata": {"endianness_hint": "little"},
    }

    report = detect_mapping_candidates(
        chunks,
        byte_entries=[byte_entry],
        output_dir=tmp_path,
        version_hint="v14.4.2",
    )

    assert report["total_tables"] == 1
    assert report["byte_table_count"] == 1
    assert report["mapping_files"], "Expected mapping artefacts to be written"

    table_entry = report["tables"][0]
    assert any("permutation" in hint for hint in table_entry["hints"])
    assert table_entry["stats"]["length"] == 4

    byte_entry_report = report["byte_tables"][0]
    assert any("width=" in hint for hint in byte_entry_report["hints"])

    mapping_path = Path(report["mapping_files"][0])
    mapping_data = json.loads(mapping_path.read_text(encoding="utf-8"))
    assert mapping_data["mapping"] == [1, 0, 3, 2] or mapping_data["mapping"] == [2, 0, 1, 3]
    assert isinstance(mapping_data["inverse"], dict)


def test_cli_mapping_detection(tmp_path) -> None:
    chunk_path = tmp_path / "chunks.json"
    chunk_path.write_text(
        json.dumps(
            [
                {
                    "text": "local map = {0, 1, 2, 3}",
                }
            ]
        ),
        encoding="utf-8",
    )

    bytes_dir = tmp_path / "bytes"
    bytes_dir.mkdir()
    payload_path = bytes_dir / "perm.bin"
    payload_path.write_bytes(bytes([0, 1, 2, 3]))
    meta_path = bytes_dir / "meta.json"
    meta_path.write_text(
        json.dumps(
            [
                {
                    "name": "perm.bin",
                    "path": str(payload_path),
                    "endianness_hint": "little",
                }
            ]
        ),
        encoding="utf-8",
    )

    output_path = tmp_path / "report.json"
    mapping_dir = tmp_path / "maps"

    exit_code = main(
        [
            "--source",
            str(chunk_path),
            "--output",
            str(output_path),
            "--bytes-dir",
            str(bytes_dir),
            "--mapping-dir",
            str(mapping_dir),
            "--version-hint",
            "v14.4.2",
        ]
    )

    assert exit_code == 0
    assert output_path.exists()

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert report["mapping_files"]
    generated_files = list(mapping_dir.glob("*.json"))
    assert generated_files, "Expected mapping files in CLI output directory"
