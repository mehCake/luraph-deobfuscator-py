"""Tests for bootstrap manifest analysis helpers."""

from __future__ import annotations

import json
from pathlib import Path

from src.bootstrap.extract_bootstrap import identify_bootstrap_candidates, main


def _write_manifest(path: Path, manifest: list[dict]) -> None:
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def test_identify_candidates_flags_loadstring(tmp_path: Path) -> None:
    raw_text = (
        "local payload = string.char(65,66,67,68)\n"
        "local bootstrap = loadstring(payload)\n"
        "return bootstrap()\n"
    )
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    string_payload = payload_dir / "payload_stringchar_001.txt"
    string_payload.write_text("65,66,67,68", encoding="utf-8")

    string_start = raw_text.index("string.char")
    string_end = string_start + len("string.char(65,66,67,68)")
    load_start = raw_text.index("loadstring")
    load_end = load_start + len("loadstring(payload)")

    manifest = [
        {
            "type": "escaped-string",
            "start_offset": string_start,
            "end_offset": string_end,
            "payload_length": len("65,66,67,68"),
            "source_length": string_end - string_start,
            "payload_file": str(string_payload),
            "note": "string.char sequence",
        },
        {
            "type": "loadstring",
            "start_offset": load_start,
            "end_offset": load_end,
            "payload_length": len("payload"),
            "source_length": load_end - load_start,
        },
    ]

    candidates = identify_bootstrap_candidates(manifest, raw_text, tmp_path)

    assert candidates, "Expected at least one bootstrap candidate"
    load_candidates = [cand for cand in candidates if cand.kind == "loadstring"]
    assert load_candidates, "Expected loadstring candidate to be present"
    primary = load_candidates[0]
    assert primary.confidence >= 0.6
    assert "loadstring" in primary.references
    assert any("load/loadstring" in reason for reason in primary.reasons)


def test_identify_candidates_uses_autocorrelation(tmp_path: Path) -> None:
    raw_text = "local arr = {1,2,1,2,1,2,1,2}\n"
    array_start = raw_text.index("{")
    array_end = raw_text.index("}") + 1
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    array_payload = payload_dir / "payload_numeric-array_001.bin"
    array_payload.write_bytes(bytes([1, 2] * 4))

    manifest = [
        {
            "type": "numeric-array",
            "start_offset": array_start,
            "end_offset": array_end,
            "payload_length": 8,
            "source_length": array_end - array_start,
            "payload_file": str(array_payload),
        }
    ]

    candidates = identify_bootstrap_candidates(manifest, raw_text, tmp_path)

    assert candidates, "Expected numeric array to be considered"
    numeric = candidates[0]
    assert numeric.kind == "numeric-array"
    assert any("autocorrelation" in reason for reason in numeric.reasons)
    assert numeric.autocorrelation["score"] >= 0.9


def test_cli_emits_candidates(tmp_path: Path) -> None:
    raw_text = "local bootstrap = loadstring(\"print('hi')\")()\n"
    raw_path = tmp_path / "raw_payload.txt"
    raw_path.write_text(raw_text, encoding="utf-8")

    load_start = raw_text.index("loadstring")
    load_end = load_start + len("loadstring(\"print('hi')\")")
    manifest = [
        {
            "type": "loadstring",
            "start_offset": load_start,
            "end_offset": load_end,
            "payload_length": len("\"print('hi')\""),
            "source_length": load_end - load_start,
        }
    ]
    manifest_path = tmp_path / "raw_manifest.json"
    _write_manifest(manifest_path, manifest)

    output_path = tmp_path / "bootstrap_candidates.json"
    exit_code = main(
        [
            str(manifest_path),
            "--raw-text",
            str(raw_path),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data and data[0]["type"] == "loadstring"
