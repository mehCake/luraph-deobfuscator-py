from pathlib import Path

from src.lifter_core import run_lifter
from src.opcode_verifier import run_verification


def _fixture_unpacked() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "v14_4_1" / "expected_unpacked.json"


def test_opcode_verifier_produces_map(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    run_lifter(_fixture_unpacked(), out_dir)
    result = run_verification(_fixture_unpacked(), out_dir)

    assert result["status"] == "ok"
    opmap_path = out_dir / "opcode_map.v14_4_1.verified.json"
    assert opmap_path.exists()
    assert opmap_path.stat().st_size > 0
