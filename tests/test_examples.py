from pathlib import Path

from src.deobfuscator import LuaDeobfuscator


def deobfuscate(path: str) -> str:
    return LuaDeobfuscator().deobfuscate_file(path)


def golden(path: str) -> str:
    name = Path(path).name
    return Path("tests/golden") / f"{name}.out"


def test_example_obfuscated_matches_golden(tmp_path):
    out = deobfuscate("example_obfuscated.lua")
    expected = golden("example_obfuscated.lua").read_text()
    assert out == expected


def test_json_wrapped_matches_golden(tmp_path):
    out = deobfuscate("examples/json_wrapped.lua")
    expected = golden("json_wrapped.lua").read_text()
    assert out == expected


def test_complex_example_contains_script_key(tmp_path):
    out = deobfuscate("examples/complex_obfuscated")
    assert "script_key" in out
