import json
import shutil
from pathlib import Path

import pytest

from src import sandbox


@pytest.mark.skipif(shutil.which("luajit") is None, reason="luajit not available")
def test_run_sandbox_with_fixture(tmp_path):
    """Ensure ``run_sandbox`` captures unpackedData using the Lua fallback."""

    fixture_root = Path(__file__).resolve().parent / "fixtures" / "v14_4_1"
    out_dir = tmp_path / "out"

    result = sandbox.run_sandbox(
        str(fixture_root / "initv4.lua"),
        str(fixture_root / "Obfuscated.json"),
        "zkzhqwk4b58pjnudvikpf",
        str(out_dir),
        timeout_seconds=15,
    )

    assert result["status"] == "ok"

    unpacked_path = out_dir / "unpacked_dump.json"
    assert unpacked_path.exists()

    with unpacked_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    # devirtualize_v2.lua serialises the Lua table using ``array`` containers
    assert "array" in data
    # slot 4 contains the VM instruction table
    instruction_table = data["array"][3]
    assert "array" in instruction_table
    assert len(instruction_table["array"]) > 0
