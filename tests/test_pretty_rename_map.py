from __future__ import annotations

from pathlib import Path

import pytest

from src.pretty.rename_map import apply_rename_map, propose_rename_map, save_rename_map
from src.vm.lifter import BasicBlock, IRProgram, IROp, IROperand


@pytest.fixture()
def sample_program() -> IRProgram:
    load_str = IROp(
        mnemonic="LOADK",
        operands=[
            IROperand(field="A", value=0, kind="reg"),
            IROperand(field="Bx", value=1, kind="const", resolved="hello"),
        ],
        index=0,
        raw=0,
    )

    new_table = IROp(
        mnemonic="NEWTABLE",
        operands=[
            IROperand(field="A", value=1, kind="reg"),
            IROperand(field="B", value=0, kind="count"),
            IROperand(field="C", value=0, kind="count"),
        ],
        index=1,
        raw=1,
    )

    call_fn = IROp(
        mnemonic="CALL",
        operands=[
            IROperand(field="A", value=2, kind="reg"),
            IROperand(field="B", value=2, kind="count"),
            IROperand(field="C", value=1, kind="count"),
        ],
        index=2,
        raw=2,
        metadata={"category": "call"},
    )

    block = BasicBlock(
        block_id="block_0",
        start_index=0,
        end_index=3,
        ops=[load_str, new_table, call_fn],
        successors=[],
        predecessors=[],
    )

    return IRProgram(blocks=[block], metadata={}, entry_block="block_0")


def test_propose_rename_map_assigns_category_names(sample_program: IRProgram) -> None:
    rename_map = propose_rename_map(sample_program, version_hint="v14.4.2")

    assert rename_map["R0"].startswith("str_")
    assert rename_map["R1"].startswith("arr_")
    assert rename_map["R2"].startswith("fn_")


def test_apply_rename_map_to_program_enriches_metadata(sample_program: IRProgram) -> None:
    rename_map = {"R0": "str_1", "R1": "arr_1", "R2": "fn_1"}
    transformed = apply_rename_map(sample_program, rename_map)
    assert transformed is not sample_program

    block = transformed.blocks[0]
    op_aliases = block.ops[0].metadata.get("rename_aliases")
    assert op_aliases == {"A": "str_1"}
    assert transformed.metadata["rename_map"]["R2"] == "fn_1"


def test_apply_rename_map_to_mapping_clones_structure(sample_program: IRProgram) -> None:
    rename_map = {"R0": "str_1"}
    program_dict = sample_program.as_dict()
    updated = apply_rename_map(program_dict, rename_map)

    assert updated is not program_dict
    assert updated["metadata"]["rename_map"]["R0"] == "str_1"
    operand = updated["blocks"][0]["ops"][0]["operands"][0]
    assert operand["alias"] == "str_1"


def test_save_rename_map_requires_explicit_call(tmp_path: Path) -> None:
    rename_map = {"R0": "str_1"}
    path = save_rename_map(rename_map, out_dir=tmp_path / "rename_maps", name="demo")
    assert path.exists()
    payload = path.read_text(encoding="utf-8")
    assert "str_1" in payload

    with pytest.raises(FileExistsError):
        save_rename_map(rename_map, out_dir=tmp_path / "rename_maps", name="demo")
