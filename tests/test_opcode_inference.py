import json
from pathlib import Path

from src.utils.opcode_inference import infer_opcode_map


def test_opcode_inference_matches_fixture(v1441_capture):
    unpacked = v1441_capture["unpacked"]
    inferred = infer_opcode_map(unpacked)
    assert inferred

    fixture_path = Path(__file__).resolve().parent / "fixtures" / "v14_4_1" / "expected_opcodes.json"
    with open(fixture_path, "r", encoding="utf-8") as handle:
        expected = json.load(handle)

    for key, value in expected.items():
        opnum = int(key)
        assert inferred.get(opnum) == value
