"""Opcode emulator used to validate inferred Luraph opcode semantics.

This module provides a very small, deterministic execution environment that
implements a subset of the Lua 5.1 virtual machine semantics.  It is **not** a
full interpreter; instead it focuses on the handful of opcodes that appear in
the validation harness (MOVE, LOADK, CALL, RETURN, EQ, LT, LE, GETGLOBAL,
SETGLOBAL, GETTABLE, SETTABLE, FORLOOP, FORPREP, TFORLOOP, CLOSURE, VARARG and
JMP).  The goal is to execute single instructions in isolation so that the
pipeline can compare the observed side effects with the expected behaviour of a
candidate mnemonic.

The design favours clarity over raw speed: every opcode is implemented as a
dedicated handler function that receives an :class:`Instruction` instance and an
:class:`ExecutionContext`.  Handlers mutate the context in-place (updating
registers, globals, return values, etc.) and advance the program counter.

Even though the real Luraph interpreter packs operands inside bit-fields, the
validation pipeline deals with already-decoded instruction dictionaries.  The
``Instruction`` dataclass therefore accepts human readable fields such as
``mnemonic``, ``a``, ``b``, ``c`` and constant flags.  ``OpcodeEmulator`` exposes
``normalise`` helpers so callers can feed raw dictionaries produced by other
tools without having to instantiate :class:`Instruction` manually.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Dataclasses describing the instruction under test and the execution context
# ---------------------------------------------------------------------------


@dataclass
class Instruction:
    """Decoded instruction representation used by the emulator.

    Attributes mirror Lua 5.1 operands (``A``, ``B``, ``C``, ``Bx`` and
    ``sBx``).  ``b_is_k``/``c_is_k`` indicate whether ``B``/``C`` reference a
    constant instead of a register.  The original opcode number is kept for
    reporting purposes so that validation can group samples per opcode.
    """

    mnemonic: str
    a: Optional[int] = None
    b: Optional[int] = None
    c: Optional[int] = None
    bx: Optional[int] = None
    sbx: Optional[int] = None
    b_is_k: bool = False
    c_is_k: bool = False
    opnum: Optional[int] = None
    line: Optional[int] = None


@dataclass
class ExecutionContext:
    """State mutated by the instruction handlers."""

    registers: List[object]
    constants: List[object]
    env: Dict[str, object] = field(default_factory=dict)
    upvalues: List[object] = field(default_factory=list)
    prototypes: Dict[int, Callable[..., object]] = field(default_factory=dict)
    varargs: List[object] = field(default_factory=list)
    pc: int = 0
    branch_taken: bool = False
    return_values: List[object] = field(default_factory=list)

    def ensure_register(self, index: int) -> None:
        if index >= len(self.registers):
            self.registers.extend([None] * (index + 1 - len(self.registers)))

    def ensure_constant(self, index: int) -> None:
        if index >= len(self.constants):
            self.constants.extend([None] * (index + 1 - len(self.constants)))


# ---------------------------------------------------------------------------
# Opcode emulator
# ---------------------------------------------------------------------------


class OpcodeEmulator:
    """Collection of opcode handler implementations."""

    def __init__(self) -> None:
        self._handlers: Dict[str, Callable[[Instruction, ExecutionContext], None]] = {
            "MOVE": self._op_move,
            "LOADK": self._op_loadk,
            "CALL": self._op_call,
            "RETURN": self._op_return,
            "EQ": self._op_eq,
            "LT": self._op_lt,
            "LE": self._op_le,
            "GETGLOBAL": self._op_getglobal,
            "SETGLOBAL": self._op_setglobal,
            "GETTABLE": self._op_gettable,
            "SETTABLE": self._op_settable,
            "FORPREP": self._op_forprep,
            "FORLOOP": self._op_forloop,
            "TFORLOOP": self._op_tforloop,
            "CLOSURE": self._op_closure,
            "VARARG": self._op_vararg,
            "JMP": self._op_jmp,
        }

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def supported_mnemonics(self) -> Sequence[str]:
        return tuple(self._handlers.keys())

    def execute(self, instruction: Instruction, ctx: ExecutionContext) -> None:
        mnemonic = instruction.mnemonic.upper()
        handler = self._handlers.get(mnemonic)
        if handler is None:
            raise NotImplementedError(f"Opcode {mnemonic!r} has no emulator handler")
        ctx.branch_taken = False
        handler(instruction, ctx)

    # Normalisation utilities -------------------------------------------------

    def normalise(self, raw: object) -> Instruction:
        """Convert dictionaries or ``Instruction`` instances into ``Instruction``."""

        if isinstance(raw, Instruction):
            return raw
        if not isinstance(raw, dict):
            raise TypeError(f"Unsupported instruction representation: {type(raw)!r}")

        mnemonic = (
            raw.get("mnemonic")
            or raw.get("opname")
            or raw.get("name")
            or raw.get("opcode")
            or raw.get("op")
        )
        if not mnemonic:
            raise ValueError("Instruction lacks mnemonic/opcode name")

        def _pick(*names: str) -> Optional[int]:
            for name in names:
                if name in raw and raw[name] is not None:
                    return int(raw[name])
            return None

        a = _pick("A", "a")
        b = _pick("B", "b")
        c = _pick("C", "c")
        bx = _pick("Bx", "bx", "k", "const", "const_index")
        sbx = _pick("sBx", "sbx")
        opnum = _pick("opnum", "opcode_index", "op_index")
        line = _pick("line")

        b_is_k = bool(raw.get("B_is_k") or raw.get("b_is_k") or raw.get("kb"))
        c_is_k = bool(raw.get("C_is_k") or raw.get("c_is_k") or raw.get("kc"))

        return Instruction(
            mnemonic=str(mnemonic).upper(),
            a=a,
            b=b,
            c=c,
            bx=bx,
            sbx=sbx,
            b_is_k=b_is_k,
            c_is_k=c_is_k,
            opnum=opnum,
            line=line,
        )

    # ------------------------------------------------------------------
    # Operand helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rk(ctx: ExecutionContext, value: Optional[int], is_const: bool) -> object:
        if value is None:
            return None
        if is_const:
            ctx.ensure_constant(value)
            return ctx.constants[value]
        ctx.ensure_register(value)
        return ctx.registers[value]

    # ------------------------------------------------------------------
    # Opcode implementations
    # ------------------------------------------------------------------

    def _advance_pc(self, ctx: ExecutionContext, offset: int = 1) -> None:
        ctx.pc += offset

    def _op_move(self, instr: Instruction, ctx: ExecutionContext) -> None:
        ctx.ensure_register(instr.a or 0)
        ctx.ensure_register(instr.b or 0)
        ctx.registers[instr.a] = ctx.registers[instr.b]
        self._advance_pc(ctx)

    def _op_loadk(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.bx is None:
            raise ValueError("LOADK expects bx/constant index")
        ctx.ensure_register(instr.a or 0)
        ctx.ensure_constant(instr.bx)
        ctx.registers[instr.a] = ctx.constants[instr.bx]
        self._advance_pc(ctx)

    def _op_call(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.a is None:
            raise ValueError("CALL requires register A")
        ctx.ensure_register(instr.a)
        b = instr.b or 0
        c = instr.c or 0

        func = ctx.registers[instr.a]
        if not callable(func):
            raise TypeError("CALL expects register A to contain a callable")

        # Number of arguments is B-1 (B == 0 uses vararg tail).
        if b == 0:
            args = ctx.registers[instr.a + 1 :] + list(ctx.varargs)
        else:
            end = instr.a + b - 1
            ctx.ensure_register(end)
            args = list(ctx.registers[instr.a + 1 : end + 1])

        result = func(*args)
        if result is None:
            results: List[object] = []
        elif isinstance(result, tuple):
            results = list(result)
        elif isinstance(result, list):
            results = list(result)
        else:
            results = [result]

        if c == 0:
            # Multi-result: fill registers starting at A with all results.
            for index, value in enumerate(results):
                ctx.ensure_register(instr.a + index)
                ctx.registers[instr.a + index] = value
        elif c == 1:
            # No results requested.
            pass
        else:
            wanted = c - 1
            for i in range(wanted):
                value = results[i] if i < len(results) else None
                ctx.ensure_register(instr.a + i)
                ctx.registers[instr.a + i] = value
        self._advance_pc(ctx)

    def _op_return(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.a is None:
            raise ValueError("RETURN requires register A")
        b = instr.b or 0
        if b == 0:
            ctx.return_values = list(ctx.registers[instr.a :])
        else:
            end = instr.a + b - 1
            ctx.ensure_register(end - 1)
            ctx.return_values = list(ctx.registers[instr.a : end])
        self._advance_pc(ctx)

    def _compare(self, instr: Instruction, ctx: ExecutionContext, op: Callable[[object, object], bool]) -> None:
        lhs = self._rk(ctx, instr.b, instr.b_is_k)
        rhs = self._rk(ctx, instr.c, instr.c_is_k)
        outcome = op(lhs, rhs)
        expected = bool(instr.a)
        if outcome != expected:
            ctx.branch_taken = True
            self._advance_pc(ctx, 2)
        else:
            ctx.branch_taken = False
            self._advance_pc(ctx)

    def _op_eq(self, instr: Instruction, ctx: ExecutionContext) -> None:
        self._compare(instr, ctx, lambda lhs, rhs: lhs == rhs)

    def _op_lt(self, instr: Instruction, ctx: ExecutionContext) -> None:
        self._compare(instr, ctx, lambda lhs, rhs: lhs < rhs)

    def _op_le(self, instr: Instruction, ctx: ExecutionContext) -> None:
        self._compare(instr, ctx, lambda lhs, rhs: lhs <= rhs)

    def _op_getglobal(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.bx is None:
            raise ValueError("GETGLOBAL expects a constant index")
        ctx.ensure_constant(instr.bx)
        name = ctx.constants[instr.bx]
        if not isinstance(name, str):
            raise TypeError("GETGLOBAL expects constant to be a string name")
        ctx.ensure_register(instr.a or 0)
        ctx.registers[instr.a] = ctx.env.get(name)
        self._advance_pc(ctx)

    def _op_setglobal(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.bx is None:
            raise ValueError("SETGLOBAL expects constant index")
        ctx.ensure_constant(instr.bx)
        name = ctx.constants[instr.bx]
        ctx.ensure_register(instr.a or 0)
        ctx.env[name] = ctx.registers[instr.a]
        self._advance_pc(ctx)

    def _op_gettable(self, instr: Instruction, ctx: ExecutionContext) -> None:
        table = self._rk(ctx, instr.b, False)
        if not isinstance(table, dict):
            raise TypeError("GETTABLE expects register B to contain a table/dict")
        key = self._rk(ctx, instr.c, instr.c_is_k)
        ctx.ensure_register(instr.a or 0)
        ctx.registers[instr.a] = table.get(key)
        self._advance_pc(ctx)

    def _op_settable(self, instr: Instruction, ctx: ExecutionContext) -> None:
        ctx.ensure_register(instr.a or 0)
        table = ctx.registers[instr.a]
        if not isinstance(table, dict):
            raise TypeError("SETTABLE expects register A to contain a table/dict")
        key = self._rk(ctx, instr.b, instr.b_is_k)
        value = self._rk(ctx, instr.c, instr.c_is_k)
        table[key] = value
        self._advance_pc(ctx)

    def _op_forprep(self, instr: Instruction, ctx: ExecutionContext) -> None:
        base = instr.a or 0
        ctx.ensure_register(base + 2)
        initial = ctx.registers[base]
        step = ctx.registers[base + 2]
        ctx.registers[base] = (initial - step)
        self._advance_pc(ctx, (instr.sbx or 0) + 1)

    def _op_forloop(self, instr: Instruction, ctx: ExecutionContext) -> None:
        base = instr.a or 0
        ctx.ensure_register(base + 2)
        ctx.ensure_register(base + 3)
        ctx.registers[base] = ctx.registers[base] + ctx.registers[base + 2]
        step = ctx.registers[base + 2]
        limit = ctx.registers[base + 1]
        value = ctx.registers[base]
        continue_loop = (step >= 0 and value <= limit) or (step < 0 and value >= limit)
        if continue_loop:
            ctx.registers[base + 3] = value
            self._advance_pc(ctx, (instr.sbx or 0) + 1)
            ctx.branch_taken = True
        else:
            self._advance_pc(ctx)
            ctx.branch_taken = False

    def _op_tforloop(self, instr: Instruction, ctx: ExecutionContext) -> None:
        base = instr.a or 0
        ctx.ensure_register(base + 2)
        iterator = ctx.registers[base]
        state = ctx.registers[base + 1]
        control = ctx.registers[base + 2]
        if not callable(iterator):
            raise TypeError("TFORLOOP expects iterator function in R[A]")
        results = iterator(state, control)
        if results is None:
            results = ()
        elif not isinstance(results, tuple):
            results = (results,)
        if results and results[0] is not None:
            ctx.ensure_register(base + 2)
            ctx.registers[base + 2] = results[0]
            for offset in range(1, instr.c or 1):
                value = results[offset] if offset < len(results) else None
                ctx.ensure_register(base + 2 + offset)
                ctx.registers[base + 2 + offset] = value
            self._advance_pc(ctx, 2)
            ctx.branch_taken = True
        else:
            self._advance_pc(ctx)
            ctx.branch_taken = False

    def _op_closure(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.bx is None:
            raise ValueError("CLOSURE expects a prototype index")
        prototype = ctx.prototypes.get(instr.bx)
        if prototype is None:
            raise KeyError(f"Prototype {instr.bx} missing for CLOSURE")
        ctx.ensure_register(instr.a or 0)
        ctx.registers[instr.a] = prototype
        self._advance_pc(ctx)

    def _op_vararg(self, instr: Instruction, ctx: ExecutionContext) -> None:
        if instr.a is None:
            raise ValueError("VARARG requires register A")
        count = instr.b or 0
        values = list(ctx.varargs)
        if count == 0:
            for offset, value in enumerate(values):
                ctx.ensure_register(instr.a + offset)
                ctx.registers[instr.a + offset] = value
        else:
            for offset in range(count):
                value = values[offset] if offset < len(values) else None
                ctx.ensure_register(instr.a + offset)
                ctx.registers[instr.a + offset] = value
        self._advance_pc(ctx)

    def _op_jmp(self, instr: Instruction, ctx: ExecutionContext) -> None:
        self._advance_pc(ctx, (instr.sbx or 0) + 1)
        ctx.branch_taken = True


# ---------------------------------------------------------------------------
# Lightweight validation harness
# ---------------------------------------------------------------------------


@dataclass
class TestCase:
    instruction: Instruction
    context: ExecutionContext
    assertion: Callable[[ExecutionContext], None]


def build_default_testcases(mnemonic: str) -> Iterable[TestCase]:
    """Return generic test cases for the provided mnemonic.

    These test cases are used by higher level validation code when the unpacked
    bootstrap does not supply richer metadata.  They ensure the opcode handlers
    behave like their Lua 5.1 counterparts.
    """

    emu = OpcodeEmulator()

    if mnemonic == "MOVE":
        instr = Instruction("MOVE", a=0, b=1)
        ctx = ExecutionContext(registers=[None, "sentinel"], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == "sentinel"

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "LOADK":
        instr = Instruction("LOADK", a=0, bx=1)
        ctx = ExecutionContext(registers=[None], constants=["ignored", 123])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == 123

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "CALL":
        instr = Instruction("CALL", a=0, b=2, c=2)
        ctx = ExecutionContext(registers=[lambda x: x + 5, 7], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == 12

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "RETURN":
        instr = Instruction("RETURN", a=1, b=3)
        ctx = ExecutionContext(registers=[0, "v1", "v2", "ignored"], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.return_values == ["v1", "v2"]

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "EQ":
        instr = Instruction("EQ", a=0, b=0, c=1)
        ctx = ExecutionContext(registers=[5, 5], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.branch_taken is True

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "LT":
        instr = Instruction("LT", a=1, b=0, c=1)
        ctx = ExecutionContext(registers=[3, 10], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.branch_taken is False

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "LE":
        instr = Instruction("LE", a=0, b=0, c=1)
        ctx = ExecutionContext(registers=[4, 4], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.branch_taken is True

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "GETGLOBAL":
        instr = Instruction("GETGLOBAL", a=0, bx=0)
        ctx = ExecutionContext(registers=[None], constants=["foo"], env={"foo": 99})

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == 99

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "SETGLOBAL":
        instr = Instruction("SETGLOBAL", a=0, bx=0)
        ctx = ExecutionContext(registers=[321], constants=["bar"], env={})

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.env["bar"] == 321

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "GETTABLE":
        instr = Instruction("GETTABLE", a=0, b=1, c=2, c_is_k=True)
        ctx = ExecutionContext(registers=[None, {"key": "value"}], constants=[None, None, "key"])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == "value"

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "SETTABLE":
        instr = Instruction("SETTABLE", a=0, b=0, c=2, b_is_k=True, c_is_k=True)
        ctx = ExecutionContext(registers=[{}], constants=["field", "ignored", "payload"])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0]["field"] == "payload"

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "FORPREP":
        instr = Instruction("FORPREP", a=0, sbx=2)
        ctx = ExecutionContext(registers=[5, 10, 1, None], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == 4
            assert result_ctx.pc == 3

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "FORLOOP":
        instr = Instruction("FORLOOP", a=0, sbx=-1)
        ctx = ExecutionContext(registers=[4, 6, 2, None], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == 6
            assert result_ctx.branch_taken is True

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "TFORLOOP":
        def iterator(state, control):
            if control is None:
                return ("item", state)
            return (None,)

        instr = Instruction("TFORLOOP", a=0, c=1)
        ctx = ExecutionContext(registers=[iterator, "state", None, None], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[2] == "item"
            assert result_ctx.branch_taken is True

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "CLOSURE":
        instr = Instruction("CLOSURE", a=0, bx=1)
        prototype = lambda *args: ("closure", args)
        ctx = ExecutionContext(registers=[None], constants=[], prototypes={1: prototype})

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] is prototype

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "VARARG":
        instr = Instruction("VARARG", a=0, b=2)
        ctx = ExecutionContext(registers=[None, None], constants=[], varargs=["alpha", "beta", "gamma"])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.registers[0] == "alpha"
            assert result_ctx.registers[1] == "beta"

        yield TestCase(instr, ctx, _assert)

    elif mnemonic == "JMP":
        instr = Instruction("JMP", sbx=2)
        ctx = ExecutionContext(registers=[], constants=[])

        def _assert(result_ctx: ExecutionContext) -> None:
            assert result_ctx.pc == 3

        yield TestCase(instr, ctx, _assert)

    else:
        raise ValueError(f"No default testcase for mnemonic {mnemonic!r}")


def run_testcase(testcase: TestCase, emulator: Optional[OpcodeEmulator] = None) -> None:
    """Execute ``testcase`` and run its assertion."""

    emu = emulator or OpcodeEmulator()
    emu.execute(testcase.instruction, testcase.context)
    testcase.assertion(testcase.context)

