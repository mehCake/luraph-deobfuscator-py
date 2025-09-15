from pathlib import Path

from luraph_for_lua import deobfuscate


def _golden(name: str) -> str:
    return Path("tests/golden") / f"{name}.out"


def test_example_obfuscated_matches_golden():
    out = deobfuscate("example_obfuscated.lua")
    expected = _golden("example_obfuscated.lua").read_text()
    assert out == expected


def test_json_wrapped_matches_golden():
    out = deobfuscate("examples/json_wrapped.lua")
    expected = _golden("json_wrapped.lua").read_text()
    assert out == expected

