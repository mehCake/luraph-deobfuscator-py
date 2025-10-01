from pathlib import Path

from src.deob_reconstruct import reconstruct
from src.lifter_core import run_lifter
from src.opcode_verifier import run_verification


def _fixture_unpacked() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "v14_4_1" / "expected_unpacked.json"


def test_reconstruct_emits_chunks(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    run_lifter(_fixture_unpacked(), out_dir)
    run_verification(_fixture_unpacked(), out_dir)
    result = reconstruct(
        _fixture_unpacked(), out_dir / "opcode_map.v14_4_1.verified.json", out_dir, 200
    )

    assert result["status"] == "ok"
    chunk = out_dir / "deobfuscated.part01.lua"
    assert chunk.exists()
    assert chunk.read_text(encoding="utf-8").startswith("-- deobfuscated")
