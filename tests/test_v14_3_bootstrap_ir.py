from pathlib import Path

from opcode_lifter import build_bootstrap_ir_v14_3
from src.utils_pkg import ast as lua_ast


def test_bootstrap_ir_v14_3_annotations_expose_loader_details() -> None:
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    chunk = lua_ast.Chunk(body=[], metadata={"source": source})

    bootstrap = build_bootstrap_ir_v14_3(chunk)
    assert bootstrap is not None
    assert bootstrap.serialized_chunk is not None
    assert bootstrap.string_decoder is not None
    assert bootstrap.string_decoder.primitive_table_info is bootstrap.primitive_table_info

    annotations = bootstrap.annotations
    assert isinstance(annotations, dict)

    loader_info = annotations.get("loader")
    assert isinstance(loader_info, dict)
    assert loader_info.get("prototype_count", 0) >= 1
    assert loader_info.get("has_constant_reader") is True
    assert loader_info.get("has_instruction_reader") is True
    steps = loader_info.get("steps", [])
    assert "read_constant_array" in steps
    assert "read_opcode_array" in steps

    vm_entry = annotations.get("vm_entry")
    assert isinstance(vm_entry, dict)
    assert vm_entry.get("control_variable") == "x"
    assert vm_entry.get("state_count", 0) >= 2
