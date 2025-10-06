import json
from pathlib import Path

from src.lifter_core import run_lifter
from src.utils.luraph_vm import rebuild_vm_bytecode

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "v14_4_1"


def test_vm_lift_end_to_end(tmp_path):
    unpacked_path = FIXTURES / "expected_unpacked.json"
    opcode_map_path = FIXTURES / "expected_opcodes.json"

    unpacked = json.loads(unpacked_path.read_text(encoding="utf-8"))
    opcode_map = json.loads(opcode_map_path.read_text(encoding="utf-8"))

    rebuild = rebuild_vm_bytecode(unpacked, opcode_map)
    mnemonics = {row.get("mnemonic") for row in rebuild.instructions}
    assert {"CALL", "RETURN", "LOADK"}.issubset(mnemonics)

    out_dir = tmp_path / "lift_out"
    out_dir.mkdir()
    (out_dir / "opcode_map.v14_4_1.verified.json").write_text(
        opcode_map_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = run_lifter(unpacked_path, out_dir)
    assert result["status"] == "ok"

    lua_text = (out_dir / "lift_ir.lua").read_text(encoding="utf-8")
    assert "return" in lua_text.lower()
    assert "call" in lua_text.lower()

    metadata = json.loads((out_dir / "lift_metadata.json").read_text(encoding="utf-8"))
    coverage = metadata.get("opcode_coverage", {})
    seen = set(coverage.get("seen", []))
    expected_codes = {int(key) for key, value in opcode_map.items() if value in {"CALL", "RETURN", "LOADK"}}
    assert expected_codes <= seen
