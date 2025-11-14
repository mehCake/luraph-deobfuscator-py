import json
from pathlib import Path

import pytest

from src.io.loader import DEFAULT_EXTRACTION_THRESHOLD, load_lua_file, main


def test_load_lua_file_extracts_strings_and_manifest(tmp_path: Path) -> None:
    payload = "A" * (DEFAULT_EXTRACTION_THRESHOLD + 10)
    source = f"local payload = \"{payload}\"\r\nreturn payload"
    target = tmp_path / "sample.lua"
    target.write_text(source, encoding="utf-8")

    output_dir = tmp_path / "payloads"
    raw_text, extracted, manifest = load_lua_file(
        target,
        threshold=DEFAULT_EXTRACTION_THRESHOLD,
        output_dir=output_dir,
        include_manifest=True,
    )

    assert "\r" not in raw_text
    assert extracted, "Expected long string payload to be extracted"
    file_name, content = next(iter(extracted.items()))
    assert len(content) == len(payload)
    payload_path = output_dir / file_name
    assert payload_path.is_file()

    string_entries = [entry for entry in manifest if entry["type"] == "escaped-string"]
    assert string_entries, "Manifest should record escaped string entries"
    assert string_entries[0]["payload_length"] >= len(payload)


def test_load_lua_file_collects_numeric_arrays_and_string_char(tmp_path: Path) -> None:
    array_values = ",".join(str(i) for i in range(8))
    source = (
        f"local arr = {{{array_values}}}\n"
        "local s = string.char(65,66,67,68,69,70)\n"
    )
    target = tmp_path / "mix.lua"
    target.write_text(source, encoding="utf-8")

    output_dir = tmp_path / "payloads"
    _, _, manifest = load_lua_file(
        target,
        threshold=4,
        output_dir=output_dir,
        include_manifest=True,
    )

    numeric_entries = [entry for entry in manifest if entry["type"] == "numeric-array"]
    assert numeric_entries, "Numeric array should appear in manifest"
    numeric_file = Path(numeric_entries[0]["payload_file"])
    assert numeric_file.exists()

    stringchar_entries = [
        entry
        for entry in manifest
        if entry["type"] == "escaped-string" and "string.char" in (entry.get("note") or "")
    ]
    assert stringchar_entries, "string.char sequences should be recorded"
    stringchar_file = Path(stringchar_entries[0]["payload_file"])
    assert stringchar_file.exists()


def test_cli_writes_manifest_and_outputs_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = (
        "local payload = string.char(70,71,72,73,74,75)\n"
        "local arr = {1,2,3,4,5,6,7,8}\n"
    )
    target = tmp_path / "source.lua"
    target.write_text(source, encoding="utf-8")

    out_dir = tmp_path / "out"
    exit_code = main(
        [
            str(target),
            "--output-dir",
            str(out_dir),
            "--threshold",
            "4",
        ]
    )

    assert exit_code == 0
    manifest_path = out_dir / "raw_manifest.json"
    assert manifest_path.is_file()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert any(entry["type"] == "numeric-array" for entry in data)

    captured = capsys.readouterr()
    assert "Manifest written to" in captured.out
