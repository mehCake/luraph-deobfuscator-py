from __future__ import annotations

import pytest

from src.utils.luraph_vm import VMRebuildResult, looks_like_vm_bytecode, rebuild_vm_bytecode


def _decode_words(blob: bytes) -> list[int]:
    return [int.from_bytes(blob[index : index + 4], "little") for index in range(0, len(blob), 4)]


def test_rebuild_vm_bytecode_basic() -> None:
    instr1 = {"array": [None, None, 0, None, None, 1, 2, 3]}
    instr2 = {"array": [None, None, 4, None, None, 2], "map": {"Bx": 512}}
    instr3 = {"array": [None, None, 0x16, None, None, 0, 0, 0], "map": {"sBx": -1}}

    unpacked = {
        "array": [
            None,
            None,
            None,
            {"array": [instr1, instr2, instr3]},
            {"array": ["const0", "const1"]},
        ]
    }

    opcode_map = {0x00: "MOVE", 0x04: "LOADK", 0x16: "JMP"}

    result: VMRebuildResult = rebuild_vm_bytecode(unpacked, opcode_map)
    assert isinstance(result.bytecode, bytes)
    assert len(result.instructions) == 3
    assert result.constants == ["const0", "const1"]

    words = _decode_words(result.bytecode)
    assert len(words) == 3

    move = words[0]
    assert move & 0x3F == 0x00
    assert (move >> 6) & 0xFF == 1
    assert (move >> 23) & 0x1FF == 2
    assert (move >> 14) & 0x1FF == 3

    loadk = words[1]
    assert loadk & 0x3F == 0x04
    # Bx = 512 -> high bits encode 1 while C=0
    assert (loadk >> 23) & 0x1FF == 1
    assert (loadk >> 14) & 0x1FF == 0

    jmp = words[2]
    assert jmp & 0x3F == 0x16
    # ensure signed offset propagated
    assert ((jmp >> 23) & 0x1FF) != 0 or ((jmp >> 14) & 0x1FF) != 0


@pytest.mark.parametrize(
    "blob, expected",
    [
        (bytes.fromhex("01000000 02000000 03000000"), False),
        (bytes.fromhex("00000040 01008000 02000001 03000002"), True),
    ],
)
def test_bytecode_heuristic(blob: bytes, expected: bool) -> None:
    assert looks_like_vm_bytecode(blob) is expected
