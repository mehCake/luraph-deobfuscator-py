"""Smoke integration covering the initv4 bootstrap decoding path."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INITV4 = PROJECT_ROOT / "initv4.lua"
SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


@pytest.mark.skipif(
    not INITV4.exists(),
    reason="initv4 fixture missing",
)
def test_cli_runs_with_initv4_payload(tmp_path: Path) -> None:
    target = tmp_path / "sample.json"
    target.write_text('{"foo": "bar"}', encoding="utf-8")

    out_dir = PROJECT_ROOT / "out"
    if out_dir.exists():
        shutil.rmtree(out_dir)

    cmd = [
        sys.executable,
        "-m",
        "src.main",
        str(target),
        "--script-key",
        SCRIPT_KEY,
        "--bootstrapper",
        str(INITV4),
        "--yes",
        "--all",
        "--output-prefix",
        "integration",
        "--chunk-lines",
        "200",
        "--max-iterations",
        "1",
        "--artifact-only",
        "--confirm-ownership",
        "--confirm-voluntary-key",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
    assert proc.returncode == 0, proc.stderr

    lua_out = target.with_name(f"{target.stem}_deob.lua")
    json_out = target.with_name(f"{target.stem}_deob.json")

    assert lua_out.exists()
    assert lua_out.stat().st_size > 0
    assert json_out.exists()
    assert json_out.stat().st_size > 0

    b64_path = out_dir / "bootstrap_blob.b64.txt"
    assert b64_path.exists()
    assert b64_path.read_text().strip(), "expected bootstrap blob base64 output"

    alphabet_path = out_dir / "alphabet.txt"
    opcode_map_path = out_dir / "opcode_map.txt"
    unpacked_path = out_dir / "unpacked.json"

    assert alphabet_path.exists()
    assert opcode_map_path.exists()
    assert unpacked_path.exists()

    lua_chunk = out_dir / "integration.lua"
    if not lua_chunk.exists():
        lua_chunk = out_dir / "integration.part01.lua"
    assert lua_chunk.exists()
    assert lua_chunk.read_text().strip() != ""

    data = json.loads(unpacked_path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
