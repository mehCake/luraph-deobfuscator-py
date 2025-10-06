import json
from pathlib import Path

from src.lifter.lifter import lift_program
from src.utils.luraph_vm import rebuild_vm_bytecode
from src.utils.opcode_inference import infer_opcode_map


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "simple_vm.json"


def _load_fixture(name: str) -> dict:
    with open(FIXTURES, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data[name]


def _instruction_names(result, opcode_map):
    names = []
    for row in result.instructions:
        if hasattr(row, "mnemonic"):
            names.append(getattr(row, "mnemonic"))
            continue
        if isinstance(row, dict):
            mnemonic = row.get("op") or row.get("mnemonic")
            if mnemonic:
                names.append(str(mnemonic))
                continue
            opcode = row.get("opcode")
            if opcode is not None and opcode_map:
                mapped = opcode_map.get(opcode)
                if mapped:
                    names.append(str(mapped))
                    continue
        names.append("UNKNOWN")
    return names


def test_bytecode_reconstruction_matches_expected():
    unpacked = _load_fixture("print_hi")
    opcode_map = infer_opcode_map(unpacked)
    result = rebuild_vm_bytecode(unpacked, opcode_map)

    assert result.bytecode
    names = _instruction_names(result, opcode_map)
    assert names == ["LOADK", "MOVE", "CALL", "RETURN"]

    constants = {str(item) for item in result.constants}
    for token in ("hi", "print"):
        assert any(token in value for value in constants)
    for keyword in ("LOADK", "MOVE", "CALL", "RETURN"):
        assert keyword in " ".join(names)


def test_lifter_exec_simulation():
    unpacked = _load_fixture("return_42")
    opcode_map = infer_opcode_map(unpacked)
    result = rebuild_vm_bytecode(unpacked, opcode_map)

    lift_result = lift_program(result.instructions, result.constants, opcode_map)
    assert lift_result.stack_trace, "expected emulator to record stack trace"
    final_snapshot = lift_result.stack_trace[-1]
    assert final_snapshot["opcode"] == "RETURN"
    registers = final_snapshot.get("registers", {})
    assert registers.get("local_0") == "42"
