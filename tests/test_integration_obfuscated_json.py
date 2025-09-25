"""End-to-end bootstrapper extraction and payload decoding tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("RUN_INTEGRATION_TESTS"),
    reason="Set RUN_INTEGRATION_TESTS=1 to enable integration tests.",
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INITV4_PATH = PROJECT_ROOT / "initv4.lua"
SAMPLE_JSON = PROJECT_ROOT / "examples" / "complex_obfuscated.json"
SCRIPT_KEY = "x5elqj5j4ibv9z3329g7b"


def test_integration_obfuscated_json(tmp_path: Path) -> None:
    """Running the CLI should produce both decoded Lua and JSON reports."""

    if not INITV4_PATH.exists():
        pytest.skip("bootstrapper script missing")
    if not SAMPLE_JSON.exists():
        pytest.skip("obfuscated JSON sample missing")

    target = tmp_path / SAMPLE_JSON.name
    target.write_bytes(SAMPLE_JSON.read_bytes())

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        str(target),
        "--script-key",
        SCRIPT_KEY,
        "--bootstrapper",
        str(INITV4_PATH),
        "--yes",
        "--debug-bootstrap",
        "--allow-lua-run",
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr

    output_lua = target.with_name(f"{target.stem}_deob.lua")
    output_json = target.with_name(f"{target.stem}_deob.json")

    assert output_lua.exists()
    assert output_json.exists()

    lua_text = output_lua.read_text(encoding="utf-8")
    assert "function" in lua_text

    payload = json.loads(output_json.read_text(encoding="utf-8"))
    bootstrap_meta = payload.get("bootstrapper_metadata") or {}
    assert bootstrap_meta.get("alphabet_len", 0) > 0
    assert bootstrap_meta.get("opcode_map_count", 0) >= 16
    assert bootstrap_meta.get("artifact_paths")

