"""Tests covering lifter safety limits."""

from src.lifter.runner import run_lifter_safe


def _make_instruction(index: int) -> dict:
    return {
        "pc": index + 1,
        "index": index,
        "opcode": 0,
        "opnum": 0,
        "mnemonic": "MOVE",
        "A": 0,
        "B": 0,
        "C": 0,
    }


def test_instruction_budget_triggers_partial_output() -> None:
    instructions = [_make_instruction(i) for i in range(200)]
    result = run_lifter_safe(
        instructions,
        [],
        {0: "MOVE"},
        instruction_budget=50,
        time_limit=None,
    )

    assert result.metadata.get("partial") is True
    assert result.metadata.get("partial_kind") == "instruction_budget"
    assert result.metadata.get("instructions_processed") == 50
    assert len(result.ir_entries) == 50
    assert "lifter aborted" in result.lua_source
