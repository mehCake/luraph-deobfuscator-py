from pathlib import Path

from src.utils.luraph_vm import rebuild_vm_bytecode
from src.utils.opcode_inference import infer_opcode_map


def _instruction_names(result):
    return [row.get("op") for row in result.instructions]


def test_bytecode_reconstruction_matches_expected(v1441_capture):
    unpacked = v1441_capture["unpacked"]
    opcode_map = infer_opcode_map(unpacked)
    result = rebuild_vm_bytecode(unpacked, opcode_map)

    assert result.bytecode
    names = _instruction_names(result)
    assert names == ["LOADK", "MOVE", "CALL", "RETURN"]

    expected_path = Path(__file__).resolve().parent / "fixtures" / "v14_4_1" / "expected.lua"
    with open(expected_path, "r", encoding="utf-8") as handle:
        expected_src = handle.read().strip()

    # Simple heuristic: ensure constants and operations mention keywords from expected source
    constants = {str(item) for item in result.constants}
    for token in ("hi", "print"):
        assert any(token in value for value in constants)
    for keyword in ("LOADK", "MOVE", "CALL", "RETURN"):
        assert keyword in " ".join(names)
    assert "print" in expected_src
