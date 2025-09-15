from opcode_lifter import OpcodeLifter
from lua_vm_simulator import LuaVMSimulator


def test_simulator_executes_numeric_for_loop():
    payload = {
        "constants": [0, 3, 1],
        "bytecode": [
            {"op": "LOADK", "a": 0, "const": 0},
            {"op": "LOADK", "a": 1, "const": 1},
            {"op": "LOADK", "a": 2, "const": 2},
            {"op": "LOADN", "a": 4, "value": 0},
            {"op": "FORPREP", "a": 0, "offset": 1},
            {"op": "ADD", "a": 4, "b": 4, "c": 3},
            {"op": "FORLOOP", "a": 0, "offset": -2},
            {"op": "RETURN", "a": 4, "b": 1},
        ],
    }

    program = OpcodeLifter().lift_program(payload, version="v14.0.2")
    result = LuaVMSimulator().run(program)
    assert result == 6
