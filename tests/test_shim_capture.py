from pathlib import Path

import pytest


def test_initv4_shim_captures_unpacked(tmp_path: Path) -> None:
    lupa = pytest.importorskip("lupa")
    LuaRuntime = lupa.LuaRuntime

    tools_dir = Path("tools")
    shim_path = tools_dir / "shims" / "initv4_shim.lua"
    toy_vm = Path("tests/fixtures/toy_vm.lua")

    lua = LuaRuntime(unpack_returned_tuples=True)
    lua.execute(
        "package.path = package.path .. ';./tools/?.lua;./tools/?/init.lua;./tools/shims/?.lua'"
    )
    lua.execute(
        f"local shim = dofile('{shim_path.as_posix()}'); shim.install(_G, {{ out_dir = '{tmp_path.as_posix()}' }})"
    )
    lua.execute(f"dofile('{toy_vm.as_posix()}')")

    capture_path = tmp_path / "unpacked_dump.lua.json"
    assert capture_path.exists()
    data = capture_path.read_text(encoding="utf-8")
    assert "shim_capture" not in data  # real JSON encoder should have been used
    log_path = tmp_path / "shim_usage.txt"
    assert log_path.exists()
    log_contents = log_path.read_text(encoding="utf-8")
    assert "[shim]" in log_contents
