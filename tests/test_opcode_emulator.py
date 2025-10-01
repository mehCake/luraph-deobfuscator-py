"""Unit tests for the opcode emulator.

The tests use deliberately small contexts so failures are easy to diagnose.  A
few opcodes (e.g. CALL, FORLOOP) exercise multiple paths to ensure the
implementation mirrors Lua 5.1 semantics closely enough for validation
purposes.
"""

from __future__ import annotations

import pytest

from src.opcode_emulator import (
    ExecutionContext,
    Instruction,
    OpcodeEmulator,
    build_default_testcases,
    run_testcase,
)


@pytest.fixture
def emulator() -> OpcodeEmulator:
    return OpcodeEmulator()


def test_move(emulator: OpcodeEmulator) -> None:
    instr = Instruction("MOVE", a=0, b=1)
    ctx = ExecutionContext(registers=[None, 42], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.registers[0] == 42


def test_loadk(emulator: OpcodeEmulator) -> None:
    instr = Instruction("LOADK", a=1, bx=0)
    ctx = ExecutionContext(registers=[0, None], constants=[99])
    emulator.execute(instr, ctx)
    assert ctx.registers[1] == 99


def test_call_with_arguments(emulator: OpcodeEmulator) -> None:
    instr = Instruction("CALL", a=0, b=3, c=2)
    ctx = ExecutionContext(registers=[lambda x, y: x + y, 3, 4], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.registers[0] == 7


def test_return_collects_values(emulator: OpcodeEmulator) -> None:
    instr = Instruction("RETURN", a=0, b=3)
    ctx = ExecutionContext(registers=["a", "b", "c"], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.return_values == ["a", "b"]


def test_eq_branches_on_mismatch(emulator: OpcodeEmulator) -> None:
    instr = Instruction("EQ", a=0, b=0, c=1)
    ctx = ExecutionContext(registers=[5, 5], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.branch_taken is True
    assert ctx.pc == 2


def test_lt_branch_not_taken_when_a_true(emulator: OpcodeEmulator) -> None:
    instr = Instruction("LT", a=1, b=0, c=1)
    ctx = ExecutionContext(registers=[1, 2], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.branch_taken is False
    assert ctx.pc == 1


def test_le_branch_taken_when_condition_matches(emulator: OpcodeEmulator) -> None:
    instr = Instruction("LE", a=0, b=0, c=1)
    ctx = ExecutionContext(registers=[2, 2], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.branch_taken is True
    assert ctx.pc == 2


def test_getglobal_reads_environment(emulator: OpcodeEmulator) -> None:
    instr = Instruction("GETGLOBAL", a=0, bx=0)
    ctx = ExecutionContext(registers=[None], constants=["foo"], env={"foo": "bar"})
    emulator.execute(instr, ctx)
    assert ctx.registers[0] == "bar"


def test_setglobal_writes_environment(emulator: OpcodeEmulator) -> None:
    instr = Instruction("SETGLOBAL", a=0, bx=0)
    ctx = ExecutionContext(registers=[123], constants=["baz"], env={})
    emulator.execute(instr, ctx)
    assert ctx.env["baz"] == 123


def test_gettable_fetches_value(emulator: OpcodeEmulator) -> None:
    instr = Instruction("GETTABLE", a=0, b=1, c=0, c_is_k=True)
    ctx = ExecutionContext(registers=[None, {"key": "value"}], constants=["key"])
    emulator.execute(instr, ctx)
    assert ctx.registers[0] == "value"


def test_settable_assigns_value(emulator: OpcodeEmulator) -> None:
    instr = Instruction("SETTABLE", a=0, b=0, c=1, b_is_k=True, c_is_k=True)
    ctx = ExecutionContext(registers=[{}], constants=["answer", 42])
    emulator.execute(instr, ctx)
    assert ctx.registers[0]["answer"] == 42


def test_forprep_initialises_counter(emulator: OpcodeEmulator) -> None:
    instr = Instruction("FORPREP", a=0, sbx=1)
    ctx = ExecutionContext(registers=[5, 10, 1, None], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.registers[0] == 4
    assert ctx.pc == 2


def test_forloop_continues_until_limit(emulator: OpcodeEmulator) -> None:
    instr = Instruction("FORLOOP", a=0, sbx=-1)
    ctx = ExecutionContext(registers=[4, 6, 2, None], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.registers[0] == 6
    assert ctx.branch_taken is True
    assert ctx.pc == 0


def test_tforloop_iterates_when_iterator_returns_value(emulator: OpcodeEmulator) -> None:
    def iterator(state, control):
        if control is None:
            return (state + 1,)
        return (None,)

    instr = Instruction("TFORLOOP", a=0, c=1)
    ctx = ExecutionContext(registers=[iterator, 10, None, None], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.registers[2] == 11
    assert ctx.branch_taken is True
    assert ctx.pc == 2


def test_closure_stores_prototype(emulator: OpcodeEmulator) -> None:
    proto = lambda: "closure"
    instr = Instruction("CLOSURE", a=1, bx=3)
    ctx = ExecutionContext(registers=[None, None], constants=[], prototypes={3: proto})
    emulator.execute(instr, ctx)
    assert ctx.registers[1] is proto


def test_vararg_copies_requested_values(emulator: OpcodeEmulator) -> None:
    instr = Instruction("VARARG", a=0, b=3)
    ctx = ExecutionContext(registers=[None, None, None], constants=[], varargs=[1, 2, 3, 4])
    emulator.execute(instr, ctx)
    assert ctx.registers[:3] == [1, 2, 3]


def test_jmp_moves_program_counter(emulator: OpcodeEmulator) -> None:
    instr = Instruction("JMP", sbx=5)
    ctx = ExecutionContext(registers=[], constants=[])
    emulator.execute(instr, ctx)
    assert ctx.pc == 6


@pytest.mark.parametrize("mnemonic", [
    "MOVE",
    "LOADK",
    "CALL",
    "RETURN",
    "EQ",
    "LT",
    "LE",
    "GETGLOBAL",
    "SETGLOBAL",
    "GETTABLE",
    "SETTABLE",
    "FORPREP",
    "FORLOOP",
    "TFORLOOP",
    "CLOSURE",
    "VARARG",
    "JMP",
])
def test_default_testcases_cover_all_handlers(mnemonic: str) -> None:
    # Ensure the canned test cases execute without raising and satisfy their
    # assertions.  This doubles as a regression test for ``build_default_testcases``
    # which feeds the automatic validation stage.
    cases = list(build_default_testcases(mnemonic))
    assert cases, f"No testcases generated for {mnemonic}"
    for case in cases:
        run_testcase(case)

