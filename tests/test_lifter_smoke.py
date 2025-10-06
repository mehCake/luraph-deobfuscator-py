import json
from pathlib import Path

from src.lifter_core import run_lifter


def _fixture_unpacked() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "v14_4_1" / "expected_unpacked.json"


def test_lifter_generates_ir(tmp_path):
    out_dir = tmp_path / "out"
    result = run_lifter(_fixture_unpacked(), out_dir)

    assert result["status"] == "ok"
    assert (out_dir / "lift_ir.lua").exists()
    assert (out_dir / "lift_ir.json").exists()
    assert (out_dir / "lift_stack.json").exists()
    assert (out_dir / "opcode_candidates.json").exists()


def test_lifter_reports_opcode_and_function_counts(tmp_path):
    out_dir = tmp_path / "out"
    result = run_lifter(_fixture_unpacked(), out_dir)

    assert result["status"] == "ok"
    assert isinstance(result.get("function_count"), int)
    assert result["function_count"] >= 1
    assert result.get("missing_opcodes") == []

    metadata = json.loads((out_dir / "lift_metadata.json").read_text())
    assert metadata.get("function_count", 0) >= 1
    seen_opcodes = metadata.get("opcode_coverage", {}).get("seen", [])
    assert metadata.get("distinct_opcodes", 0) == len(seen_opcodes)
    assert len(seen_opcodes) >= 1
    coverage = metadata.get("opcode_coverage", {})
    assert isinstance(coverage, dict)
    if "missing" in coverage:
        assert isinstance(coverage["missing"], list)


def test_lifter_counts_many_distinct_opcodes(tmp_path):
    unpacked_path = tmp_path / "synthetic_unpacked.json"
    instructions = []
    for opcode in range(10):
        instructions.append({"3": opcode, "6": 0, "7": 0, "8": 0})
    payload = {"4": instructions, "5": []}
    unpacked_path.write_text(json.dumps(payload), encoding="utf-8")

    out_dir = tmp_path / "out_many"
    result = run_lifter(unpacked_path, out_dir)

    assert result["status"] == "ok"
    metadata = json.loads((out_dir / "lift_metadata.json").read_text())
    seen = metadata.get("opcode_coverage", {}).get("seen", [])
    assert metadata.get("distinct_opcodes", 0) >= 10
    assert len(seen) >= 10
