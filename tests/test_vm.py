import json
from src.deobfuscator import LuaDeobfuscator


def test_vm_constant_return(tmp_path):
    program = {
        "constants": ["script_key"],
        "bytecode": [["LOADK", 0], ["RETURN"]],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "script_key"


def test_vm_branch_and_arithmetic(tmp_path):
    program = {
        "constants": [2, 3, 6, "success", "fail"],
        "bytecode": [
            ["LOADK", 0],
            ["LOADK", 1],
            ["MUL"],
            ["LOADK", 2],
            ["EQ"],
            ["JMPIF", 3],
            ["LOADK", 4],
            ["JMP", 2],
            ["LOADK", 3],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "success"


def test_vm_table_ops(tmp_path):
    program = {
        "constants": ["answer", 42],
        "bytecode": [
            ["NEWTABLE"],
            ["LOADK", 0],
            ["LOADK", 1],
            ["SETTABLE"],
            ["LOADK", 0],
            ["GETTABLE"],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "42"


def test_vm_comparisons_and_jmpifnot(tmp_path):
    program = {
        "constants": [2, 3, "lt", "ge"],
        "bytecode": [
            ["LOADK", 0],
            ["LOADK", 1],
            ["LT"],
            ["JMPIFNOT", 3],
            ["LOADK", 2],
            ["JMP", 2],
            ["LOADK", 3],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "lt"


def test_vm_pow_and_mod(tmp_path):
    program = {
        "constants": [2, 5],
        "bytecode": [
            ["LOADK", 0],
            ["LOADK", 1],
            ["POW"],
            ["LOADK", 1],
            ["MOD"],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "2"


def test_vm_bitwise_and_loop(tmp_path):
    program = {
        "constants": [1, 2, 3],
        "bytecode": [
            ["LOADK", 0],
            ["LOADK", 1],
            ["SHL"],
            ["LOADK", 2],
            ["BXOR"],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "7"


def test_vm_for_loop(tmp_path):
    program = {
        "constants": [1, 3, 1, "done"],
        "bytecode": [
            ["LOADK", 0],
            ["LOADK", 1],
            ["LOADK", 2],
            ["FORPREP", 2],
            ["LOADNIL"],
            ["JMP", 1],
            ["FORLOOP", -1],
            ["LOADK", 3],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "done"


def test_vm_loadn_and_move():
    program = {
        "constants": [],
        "bytecode": [
            ["LOADN", 5],
            ["MOVE", 0],
            ["ADD"],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "10"


def test_vm_loadb_branch():
    program = {
        "constants": ["yes", "no"],
        "bytecode": [
            ["LOADB", 1],
            ["JMPIFNOT", 3],
            ["LOADK", 0],
            ["JMP", 2],
            ["LOADK", 1],
            ["RETURN"],
        ],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "yes"
