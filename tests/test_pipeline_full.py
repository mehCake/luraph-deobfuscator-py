from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_PATH = REPO_ROOT / "initv4.lua"
JSON_PATH = REPO_ROOT / "Obfuscated.json"
SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


def _has_lupa() -> bool:
    try:
        import importlib.util

        return importlib.util.find_spec("lupa") is not None
    except Exception:  # pragma: no cover - defensive
        return False


def _has_luajit() -> bool:
    bundled = REPO_ROOT / "bin" / "luajit.exe"
    if bundled.exists() and os.access(bundled, os.X_OK):
        return True
    found = shutil.which("luajit")
    return found is not None


@pytest.mark.skipif(not (_has_lupa() or _has_luajit()), reason="lupa/luajit unavailable for full pipeline test")
def test_pipeline_full(tmp_path):
    out_dir = tmp_path / "out"
    cmd = [
        sys.executable,
        str(REPO_ROOT / "src" / "sandbox_runner.py"),
        "--init",
        str(INIT_PATH),
        "--json",
        str(JSON_PATH),
        "--key",
        SCRIPT_KEY,
        "--out",
        str(out_dir),
        "--run-lifter",
    ]

    completed = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT)
    if completed.returncode != 0:
        failure_path = out_dir / "failure_report.txt"
        failure_text = failure_path.read_text(encoding="utf-8") if failure_path.exists() else "<missing failure report>"
        pytest.fail(
            "pipeline command failed\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}\n"
            f"failure_report:\n{failure_text}"
        )

    unpacked = out_dir / "unpacked_dump.json"
    lift_ir = out_dir / "lift_ir.json"
    opcode_map = out_dir / "opcode_map.v14_4_1.verified.json"
    scaffold = list(out_dir.glob("deobfuscated.part*.lua")) or [out_dir / "deobfuscated.full.lua"]

    assert unpacked.exists() and unpacked.stat().st_size > 0
    assert lift_ir.exists() and lift_ir.stat().st_size > 0
    assert opcode_map.exists() and opcode_map.stat().st_size > 0
    assert any(path.exists() and path.stat().st_size > 0 for path in scaffold)

    summary_path = out_dir / "summary.json"
    assert summary_path.exists()
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary.get("status") == "ok"

