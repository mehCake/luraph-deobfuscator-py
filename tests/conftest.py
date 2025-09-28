"""Test configuration ensuring the project source tree is importable."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any
import importlib

import pytest

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)
else:
    idx = sys.path.index(root_str)
    if idx != 0:
        sys.path.insert(0, sys.path.pop(idx))

if str(TESTS) in sys.path:
    sys.path.pop(sys.path.index(str(TESTS)))
sys.path.insert(1, str(TESTS))

# Import the project package eagerly so subsequent imports reuse it
importlib.import_module("src")


SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


def _copy_fixture_dir(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            target.mkdir(exist_ok=True)
            _copy_fixture_dir(item, target)
        else:
            target.write_bytes(item.read_bytes())


@pytest.fixture(scope="session")
def v1441_capture(tmp_path_factory) -> Dict[str, Any]:
    """Run the Lua devirtualizer against the v14.4.1 fixture and capture artefacts."""

    luajit = shutil.which("luajit")
    if not luajit:
        pytest.skip("luajit not installed; skipping v14.4.1 capture tests")

    workdir = tmp_path_factory.mktemp("v1441")
    fixture_dir = TESTS / "fixtures" / "v14_4_1"
    _copy_fixture_dir(fixture_dir, workdir)

    script = ROOT / "tools" / "devirtualize_v2.lua"
    proc = subprocess.run(
        [luajit, str(script), SCRIPT_KEY],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"devirtualize_v2.lua failed: {proc.stderr}")

    unpacked_path = workdir / "unpacked_dump.json"
    opcode_path = workdir / "lift_opcodes.json"
    with open(unpacked_path, "r", encoding="utf-8") as handle:
        unpacked = json.load(handle)
    opcode_map = {}
    if opcode_path.exists():
        with open(opcode_path, "r", encoding="utf-8") as handle:
            opcode_map = json.load(handle)

    return {
        "workdir": workdir,
        "unpacked": unpacked,
        "opcode_map": opcode_map,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
