from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from src.versions.luraph_v14_4_1 import InitV4_2Handler

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


def test_initv4_cli_round_trip(tmp_path):
    source_json = PROJECT_ROOT / "Obfuscated.json"
    bootstrapper = PROJECT_ROOT / "initv4.lua"

    local_json = tmp_path / source_json.name
    local_bootstrap = tmp_path / bootstrapper.name
    local_json.write_bytes(source_json.read_bytes())
    local_bootstrap.write_bytes(bootstrapper.read_bytes())

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        str(local_json),
        "--bootstrapper",
        str(local_bootstrap),
        "--script-key",
        SCRIPT_KEY,
        "--allow-lua-run",
        "--yes",
    ]

    subprocess.run(cmd, cwd=tmp_path, check=True, capture_output=True)

    report_path = local_json.with_name(f"{local_json.stem}_deob.json")
    lua_path = local_json.with_name(f"{local_json.stem}_deob.lua")

    assert report_path.exists()
    assert lua_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    metadata = report.get("bootstrapper_metadata") or {}

    handler = InitV4_2Handler()
    handler.update_bootstrap_metadata(metadata)
    opcode_table = handler.build_opcode_table(handler.bootstrap_metadata)

    assert len(opcode_table) >= 30
    assert "function" in lua_path.read_text(encoding="utf-8").lower()

