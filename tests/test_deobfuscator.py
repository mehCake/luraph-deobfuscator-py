import json
from src.deobfuscator import LuaDeobfuscator


def test_simple_devirtualization():
    payload = json.dumps(
        {
            "constants": ["print", "hello"],
            "bytecode": [
                ["GETGLOBAL", 0],
                ["LOADK", 1],
                ["CALL", 1],
                ["RETURN"],
            ],
        }
    )
    deob = LuaDeobfuscator()
    result = deob.deobfuscate_content(payload)
    assert "print(a)" in result
    assert "'hello'" in result or '"hello"' in result


def test_constant_folding():
    payload = json.dumps(
        {
            "constants": ["print"],
            "bytecode": [
                ["GETGLOBAL", 0],
                ["LOADN", 5],
                ["LOADN", 3],
                ["ADD"],
                ["CALL", 1],
                ["RETURN"],
            ],
        }
    )
    deob = LuaDeobfuscator()
    result = deob.deobfuscate_content(payload)
    assert "local c = 8" in result
    assert "print(c)" in result
