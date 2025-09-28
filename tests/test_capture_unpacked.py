import json
from pathlib import Path


def test_unpacked_dump_written(v1441_capture):
    workdir = Path(v1441_capture["workdir"])
    unpacked_json = workdir / "unpacked_dump.json"
    unpacked_lua = workdir / "unpacked_dump.lua"
    assert unpacked_json.exists()
    assert unpacked_lua.exists()

    with open(unpacked_json, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    assert isinstance(data, dict)
    assert "array" in data
    # vm instructions live at array[4]
    vm_instr = data["array"][3]
    assert "array" in vm_instr
    assert len(vm_instr["array"]) == 4
