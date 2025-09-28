from __future__ import annotations

from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_devirtualize_v2_contains_hook() -> None:
    script = (_project_root() / "tools" / "user_env" / "devirtualize_v2.lua").read_text(encoding="utf-8")
    assert "debug.sethook" in script
    assert "LuraphInterpreter" in script


def test_lifter_default_opcodes_present() -> None:
    lifter = (_project_root() / "tools" / "user_env" / "lifter.lua").read_text(encoding="utf-8")
    for mnemonic in ("MOVE", "LOADK", "RETURN", "CLOSURE"):
        assert mnemonic in lifter


def test_root_tools_scripts_exist() -> None:
    base = _project_root() / "tools"
    for name in ("devirtualize_v2.lua", "lifter.lua", "reformat_v2.lua"):
        assert (base / name).exists(), name


def test_examples_mini_vm_expected_matches() -> None:
    fixture_dir = _project_root() / "examples" / "mini_vm"
    expected = (fixture_dir / "expected.lua").read_text(encoding="utf-8")
    assert "sum_three" in expected
    assert "return" in expected

    obf_json = (fixture_dir / "Obfuscated.json").read_text(encoding="utf-8")
    assert "LPH!" in obf_json
