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
    assert (out_dir / "opcode_candidates.json").exists()
