"""Tests for :mod:`src.lifter.debug_dump`."""

from __future__ import annotations

import json
from dataclasses import dataclass

from src.lifter.debug_dump import LifterDebugDump


@dataclass
class DataclassInstruction:
    """Instruction-like object exposing a ``raw`` payload."""

    op: str
    raw: dict[str, object]


@dataclass
class PlainInstruction:
    """Instruction-like object without an explicit ``raw`` field."""

    op: str
    a: int


def test_dump_raw_instructions_handles_varied_entry_shapes(tmp_path) -> None:
    dump = LifterDebugDump(tmp_path)
    instructions = [
        {"raw": {"op": "MOVE", "a": 1, "b": 0}},
        DataclassInstruction(op="LOADK", raw={"op": "LOADK", "bx": 3}),
        PlainInstruction(op="RETURN", a=0),
        ("tuple", "ignored"),
    ]

    dump.dump_raw_instructions(instructions)

    payload = json.loads((tmp_path / "raw_instructions.json").read_text())

    assert payload[0]["op"] == "MOVE"
    assert payload[0]["a"] == 1
    assert payload[1]["op"] == "LOADK"
    assert payload[1]["bx"] == 3
    assert payload[2]["op"] == "RETURN"
    assert payload[2]["a"] == 0
    # Ensure fallback serialisation still produces a JSON-serialisable representation.
    assert isinstance(payload[3], (str, list))
