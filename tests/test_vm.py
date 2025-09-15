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


def test_vm_closure_with_upvalue():
    inner = {"constants": [], "bytecode": [["GETUPVAL", 0], ["RETURN"]]}
    program = {
        "constants": [42, inner],
        "bytecode": [["LOADK", 0], ["CLOSURE", 1, 1], ["CALL", 0], ["RETURN"]],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "42"


def test_vm_vararg_addition():
    inner = {"constants": [], "bytecode": [["VARARG", 2], ["ADD"], ["RETURN"]]}
    program = {
        "constants": [inner],
        "bytecode": [["CLOSURE", 0, 0], ["LOADN", 3], ["LOADN", 4], ["CALL", 2], ["RETURN"]],
    }
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == "7"


def test_vm_metamethod_add():
    program = {
        "constants": [{"value": 5, "__add": "addmm"}, 3],
        "bytecode": [["LOADK", 0], ["LOADK", 1], ["ADD"], ["RETURN"]],
    }
    from src.vm import LuraphVM

    vm = LuraphVM(program["constants"], program["bytecode"], env={"addmm": lambda a, b: a["value"] + b})
    assert vm.run() == 8


def test_vm_self_method_call():
    table = {"value": 1, "adder": "add_func"}
    program = {
        "constants": [table, "adder", 5],
        "bytecode": [["LOADK", 0], ["SELF", 1], ["LOADK", 2], ["CALL", 2], ["RETURN"]],
    }
    from src.vm import LuraphVM

    vm = LuraphVM(program["constants"], program["bytecode"], env={"add_func": lambda self, x: self["value"] + x})
    assert vm.run() == 6


def test_vm_setlist():
    program = {
        "constants": [],
        "bytecode": [
            ["NEWTABLE"],
            ["LOADN", 1],
            ["LOADN", 2],
            ["LOADN", 3],
            ["SETLIST", 3],
            ["RETURN"],
        ],
    }
    from src.vm import LuraphVM

    vm = LuraphVM(program["constants"], program["bytecode"])
    assert vm.run() == {1: 1, 2: 2, 3: 3}


def test_vm_test_and_testset():
    program = {
        "constants": [1, 2],
        "bytecode": [
            ["LOADB", 1],
            ["TEST", 0],
            ["LOADK", 0],
            ["LOADK", 1],
            ["RETURN"],
        ],
    }
    from src.vm import LuraphVM

    vm = LuraphVM(program["constants"], program["bytecode"])
    assert vm.run() == 2

    program2 = {
        "constants": [],
        "bytecode": [["LOADB", 1], ["TESTSET", 1], ["RETURN"]],
    }
    vm2 = LuraphVM(program2["constants"], program2["bytecode"])
    assert vm2.run() is True


def test_vm_lph_constant_decryption():
    key = "hxsk0st7cyvjkicxnibhbm"
    plain = "secret"
    enc = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(plain))
    program = {"constants": [enc], "bytecode": [["LOADK", 0], ["RETURN"]]}
    data = json.dumps(program)
    out = LuaDeobfuscator().deobfuscate_content(data)
    assert out == plain
