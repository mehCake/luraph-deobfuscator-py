from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.mark.skipif(shutil.which("luajit") is None, reason="luajit executable not available")
def test_devirtualize_fixture_roundtrip(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    fixture = repo / "examples" / "mini_vm"

    for name in ("init.lua", "Obfuscated.json", "expected.lua"):
        shutil.copy(fixture / name, tmp_path / name)

    shutil.copy(tmp_path / "init.lua", tmp_path / "initv4.lua")

    for tool in ("devirtualize_v2.lua", "lifter.lua", "reformat_v2.lua"):
        shutil.copy(repo / "tools" / tool, tmp_path / tool)

    result = subprocess.run(
        ["luajit", "devirtualize_v2.lua", "ug7bdorqbifndbz6yj0o4a"],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert "wrote unpacked_dump.lua" in result.stdout

    decoded_path = tmp_path / "decoded_output.lua"
    assert decoded_path.exists()

    expected = (fixture / "expected.lua").read_text(encoding="utf-8").strip()
    decoded = decoded_path.read_text(encoding="utf-8").strip()
    assert decoded == expected

    pretty = subprocess.run(
        ["luajit", "reformat_v2.lua", "decoded_output.lua"],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )
    assert pretty.stdout.startswith("-- Reformatted")
