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
        "-m",
        "src.sandbox_runner",
        "--init",
        str(INIT_PATH),
        "--json",
        str(JSON_PATH),
        "--key",
        SCRIPT_KEY,
        "--out",
        str(out_dir),
        "--run-lifter",
        "--use-fixtures",
        "--lifter-mode",
        "fast",
    ]

    env = os.environ.copy()
    env.setdefault("SCRIPT_KEY", SCRIPT_KEY)
    env.setdefault("LURAPH_SCRIPT_KEY", SCRIPT_KEY)

    completed = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO_ROOT, env=env)
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
    assert summary.get("script_key_provider") == "override"
    assert summary.get("bootstrap_source") == "embedded"
    assert summary.get("lifter_mode") == "fast"

    metadata_path = out_dir / "lift_metadata.json"
    assert metadata_path.exists()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata.get("function_count", 0) >= 1
    coverage = metadata.get("opcode_coverage", {})
    assert isinstance(coverage, dict)
    seen = coverage.get("seen", [])
    assert metadata.get("distinct_opcodes", 0) == len(seen)
    if "missing" in coverage:
        assert not coverage["missing"]

    bootstrap_meta_path = out_dir / "bootstrap_blob.meta.json"
    assert bootstrap_meta_path.exists()
    bootstrap_meta = json.loads(bootstrap_meta_path.read_text(encoding="utf-8"))
    assert bootstrap_meta.get("script_key_provider") == "override"
    assert bootstrap_meta.get("bootstrap_source") == "embedded"
    assert isinstance(bootstrap_meta.get("timestamp"), str)

