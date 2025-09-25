from opcode_lifter import OpcodeLifter


def test_numeric_opcode_mapping_produces_canonical_instructions():
    payload = {
        "constants": ["print", "hello"],
        "bytecode": [
            {"op": "0x01", "a": 0, "const": 1},
            {"op": "MOVE", "a": 1, "b": 0},
            {"op": "0x24", "a": 0, "b": 2, "c": 1},
            {"op": "0x27", "a": 1, "b": 1},
        ],
    }

    lifter = OpcodeLifter()
    program = lifter.lift_program(payload, version="v14.0.2")

    assert len(program.instructions) == 4
    loadk = program.instructions[0]
    assert loadk.opcode == "LOADK"
    assert loadk.aux["const_b"] == "hello"
    assert loadk.pc == 0

    call = program.instructions[2]
    assert call.opcode == "CALL"
    assert call.aux["immediate_b"] == 2
    assert call.aux["immediate_c"] == 1

    ret = program.instructions[3]
    assert ret.opcode == "RETURN"
    assert ret.aux["immediate_b"] == 1

    metadata = program.metadata
    assert metadata["opcode_table"]["trusted"] is False
    trace = metadata.get("ir_trace")
    assert isinstance(trace, list) and trace[0]["pc"] == 0
    assert trace[2]["op"] == "CALL"
