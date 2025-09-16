from opcode_lifter import OpcodeLifter
from src.passes.devirtualizer import Devirtualizer


def test_devirtualizer_structures_conditionals():
    payload = {
        "constants": [True, "result"],
        "bytecode": [
            {"op": "LOADK", "a": 0, "const": 0},
            {"op": "LOADK", "a": 1, "const": 1},
            {"op": "JMPIFNOT", "a": 0, "offset": 3},
            {"op": "MOVE", "a": 2, "b": 1},
            {"op": "RETURN", "a": 2, "b": 1},
            {"op": "RETURN", "a": 1, "b": 1},
        ],
    }

    function = OpcodeLifter().lift_program(payload, version="v14.0.2")
    rendered = Devirtualizer(function).render()

    assert "if" in rendered
    assert "return" in rendered
    assert "local" in rendered
