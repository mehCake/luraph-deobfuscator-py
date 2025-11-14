from __future__ import annotations

import base64
import json
from pathlib import Path

from src.pretty.string_deobf import decode_string_table, main


def _encode_with_alphabet(text: str, alphabet: str) -> str:
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    translation = str.maketrans(standard, alphabet[:64])
    return encoded.translate(translation)


def test_decode_string_table_detects_base64() -> None:
    payload = decode_string_table("sample", ["SGVsbG8h"])
    entry = payload["entries"][0]
    previews = [cand["preview"] for cand in entry["candidates"]]
    assert any("Hello" in preview for preview in previews)


def test_decode_string_table_handles_custom_alphabet() -> None:
    custom_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    encoded = _encode_with_alphabet("flag", custom_alphabet)
    payload = decode_string_table("tbl", [encoded], custom_alphabets=(custom_alphabet,))
    entry = payload["entries"][0]
    methods = [cand["method"] for cand in entry["candidates"]]
    assert any(method.startswith("base64(") for method in methods)
    assert any("custom alphabet" in cand["notes"] for cand in entry["candidates"])
    decoded_candidates = [base64.b64decode(cand["base64"]).decode("latin-1") for cand in entry["candidates"]]
    assert any("flag" in decoded for decoded in decoded_candidates)


def test_decode_string_table_rle_expansion() -> None:
    # Simple RLE payload: 3 x 'A', 2 x 'B'
    rle_bytes = bytes([3, ord("A"), 2, ord("B")]).decode("latin-1")
    payload = decode_string_table("rle", [rle_bytes])
    entry = payload["entries"][0]
    methods = [cand["method"] for cand in entry["candidates"]]
    assert any(method.endswith("+rle") for method in methods)
    decoded = [base64.b64decode(cand["base64"]).decode("latin-1") for cand in entry["candidates"]]
    assert any(candidate.startswith("AAABB") for candidate in decoded)


def test_cli_main_writes_output(tmp_path: Path) -> None:
    table_path = tmp_path / "table.json"
    table_path.write_text(json.dumps({"name": "demo", "strings": ["SGVsbG8="]}), encoding="utf-8")

    out_dir = tmp_path / "strings"
    exit_code = main([str(table_path), "--out-dir", str(out_dir)])

    assert exit_code == 0
    output_file = out_dir / "demo.json"
    assert output_file.exists()
    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert data["summary"]["table"] == "demo"
