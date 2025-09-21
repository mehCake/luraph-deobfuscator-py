from opcode_lifter import OpcodeLifter
from lua_vm_simulator import LuaVMSimulator
from src.ir import VMFunction, VMInstruction


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


def test_simulator_handles_generic_for_loop():
    def iterator(limit: int, last: int) -> tuple[int | None, ...]:
        next_val = last + 1
        if next_val > limit:
            return (None,)
        return (next_val,)

    payload = {
        "constants": [iterator, 3, 0, 0],
        "bytecode": [
            {"op": "LOADK", "a": 0, "const": 0},
            {"op": "LOADK", "a": 1, "const": 1},
            {"op": "LOADK", "a": 2, "const": 2},
            {"op": "LOADK", "a": 4, "const": 3},
            {"op": "TFORLOOP", "a": 0, "offset": 0, "c": 1, "target": 7},
            {"op": "ADD", "a": 4, "b": 4, "c": 3},
            {"op": "JMP", "offset": -3},
            {"op": "RETURN", "a": 4, "b": 1},
        ],
    }

    program = OpcodeLifter().lift_program(payload, version="v14.0.2")
    simulator = LuaVMSimulator()
    result = simulator.run(program)
    assert result == 6


def test_simulator_detects_self_loop_dummy():
    program = VMFunction(
        constants=[],
        instructions=[VMInstruction("JMP", aux={"offset": -1})],
    )

    simulator = LuaVMSimulator(loop_threshold=3)
    result = simulator.run(program)

    assert result is None
    assert simulator.analysis["dummy_loops"]
    assert simulator.analysis["dummy_loops"][0]["reason"] == "self_loop"
    assert simulator.analysis.get("halt_reason") == "dummy_loop"


def test_simulator_marks_anti_debug_checks():
    def payload_function() -> int:
        return 123

    program = VMFunction(
        constants=[],
        instructions=[
            VMInstruction("GETGLOBAL", a=0, aux={"b_mode": "const", "const_b": "pcall"}),
            VMInstruction("LOADK", a=1, aux={"b_mode": "const", "const_b": payload_function}),
            VMInstruction(
                "CALL",
                a=0,
                b=2,
                c=2,
                aux={
                    "b_mode": "immediate",
                    "immediate_b": 2,
                    "c_mode": "immediate",
                    "immediate_c": 2,
                },
            ),
            VMInstruction(
                "RETURN",
                a=0,
                b=1,
                aux={"b_mode": "immediate", "immediate_b": 1},
            ),
        ],
        register_count=2,
    )

    simulator = LuaVMSimulator()
    result = simulator.run(program)

    assert result is True
    assert "pcall" in simulator.analysis["anti_debug_checks"]
    assert not simulator.analysis["dummy_loops"]
