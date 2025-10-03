import json
from pathlib import Path

import pytest


def test_initv4_shim_captures_unpacked(tmp_path: Path) -> None:
    lupa = pytest.importorskip("lupa")
    LuaRuntime = lupa.LuaRuntime

    tools_dir = Path("tools")
    shim_path = tools_dir / "shims" / "initv4_shim.lua"
    toy_vm = Path("tests/fixtures/toy_vm.lua")

    out_dir = tmp_path / "capture"
    out_dir.mkdir()

    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.execute(
        "package.path = package.path .. ';./tools/?.lua;./tools/?/init.lua;./tools/shims/?.lua'"
    )
    lua.execute(
        f"local shim = dofile('{shim_path.as_posix()}'); shim.install(_G, {{ out_dir = '{out_dir.as_posix()}' }})"
    )
    lua.execute(f"dofile('{toy_vm.as_posix()}')")

    capture_path = out_dir / "unpacked_dump.json"
    assert capture_path.exists()
    payload = json.loads(capture_path.read_text(encoding="utf-8"))
    assert payload["4"][0][2] == 32
    assert payload["5"][0] == "ABC"

    log_path = out_dir / "shim_usage.txt"
    assert log_path.exists()
    log_contents = log_path.read_text(encoding="utf-8")
    assert "[shim] L1(" in log_contents
