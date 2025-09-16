from __future__ import annotations

from typing import Any, Callable, Dict, Optional, Tuple, List

from src.vm.state import VMState
from src.exceptions import VMEmulationError

# Type alias for opcode handlers.  Handlers return a tuple of
# (advance, result). ``result`` is used for opcodes like RETURN that need to
# return a value to the caller.
HandlerResult = Tuple[int, Optional[Any]]
# ``OpcodeHandler`` deliberately uses ``Callable[..., HandlerResult]`` because
# individual opcodes take a varying number of integer arguments.  Each handler
# explicitly annotates its own parameters for clarity.
OpcodeHandler = Callable[..., HandlerResult]


class VMClosure:
    """Callable representing a VM function with captured upvalues."""

    def __init__(self, proto: Dict[str, Any], upvalues: List[Any], env: Dict[str, Any]):
        self.proto = proto
        self.upvalues = upvalues
        self.env = env

    def __call__(self, *args: Any) -> Any:  # pragma: no cover - thin wrapper
        from src.vm.emulator import LuraphVM  # local import to avoid cycle

        vm = LuraphVM(self.proto.get("constants", []), self.proto.get("bytecode", []), env=self.env.copy())
        vm.state.upvalues = {i: v for i, v in enumerate(self.upvalues)}
        vm.state.varargs = list(args)
        return vm.run()
# Stack manipulation and loads

def handle_loadk(state: VMState, idx: int) -> HandlerResult:
    state.stack.append(state.constants[idx])
    return 1, None


def handle_loadn(state: VMState, value: Any) -> HandlerResult:
    state.stack.append(value)
    return 1, None


def handle_loadb(state: VMState, value: int) -> HandlerResult:
    state.stack.append(bool(value))
    return 1, None


def handle_loadnil(state: VMState) -> HandlerResult:
    state.stack.append(None)
    return 1, None


def handle_move(state: VMState, idx: int) -> HandlerResult:
    state.stack.append(state.stack[idx])
    return 1, None


def handle_getglobal(state: VMState, idx: int) -> HandlerResult:
    name = state.constants[idx]
    state.stack.append(state.env.get(name))
    return 1, None


def handle_setglobal(state: VMState, idx: int) -> HandlerResult:
    value = state.stack.pop()
    name = state.constants[idx]
    state.env[name] = value
    return 1, None


def handle_getupval(state: VMState, idx: int) -> HandlerResult:
    state.stack.append(state.upvalues.get(idx))
    return 1, None


def handle_setupval(state: VMState, idx: int) -> HandlerResult:
    state.upvalues[idx] = state.stack.pop()
    return 1, None
# Arithmetic and bitwise operations

def _invoke_metamethod(state: VMState, a: Any, b: Any, name: str) -> Any:
    for obj in (a, b):
        if isinstance(obj, dict) and name in obj:
            mm = obj[name]
            if isinstance(mm, str):
                mm = state.env.get(mm)
            if callable(mm):
                return mm(a, b)
    raise VMEmulationError(f"metamethod {name} not found")


def _binary_op(state: VMState, op: Callable[[Any, Any], Any], metamethod: str) -> None:
    b = state.stack.pop()
    a = state.stack.pop()
    try:
        state.stack.append(op(a, b))
    except Exception:
        state.stack.append(_invoke_metamethod(state, a, b, metamethod))


def _unary_op(state: VMState, op: Callable[[Any], Any], metamethod: str) -> None:
    a = state.stack.pop()
    try:
        state.stack.append(op(a))
    except Exception:
        state.stack.append(_invoke_metamethod(state, a, None, metamethod))


def handle_add(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a + b, "__add")
    return 1, None


def handle_sub(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a - b, "__sub")
    return 1, None


def handle_mul(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a * b, "__mul")
    return 1, None


def handle_div(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a / b, "__div")
    return 1, None


def handle_mod(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a % b, "__mod")
    return 1, None


def handle_pow(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a ** b, "__pow")
    return 1, None


def handle_unm(state: VMState) -> HandlerResult:
    _unary_op(state, lambda a: -a, "__unm")
    return 1, None


def handle_bnot(state: VMState) -> HandlerResult:
    _unary_op(state, lambda a: ~int(a), "__bnot")
    return 1, None


def handle_band(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: int(a) & int(b), "__band")
    return 1, None


def handle_bor(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: int(a) | int(b), "__bor")
    return 1, None


def handle_bxor(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: int(a) ^ int(b), "__bxor")
    return 1, None


def handle_shl(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: int(a) << int(b), "__shl")
    return 1, None


def handle_shr(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: int(a) >> int(b), "__shr")
    return 1, None


def handle_concat(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: str(a) + str(b), "__concat")
    return 1, None


def handle_test(state: VMState, expect: int) -> HandlerResult:
    """Conditional test; skip next instruction when the truthiness does not match."""
    val = state.stack.pop()
    return (2 if bool(val) != bool(expect) else 1), None


def handle_testset(state: VMState, expect: int) -> HandlerResult:
    """Conditional test that preserves the value when the expectation matches."""
    val = state.stack.pop()
    if bool(val) == bool(expect):
        state.stack.append(val)
        return 1, None
    return 2, None
# Comparisons and logic

def handle_eq(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a == b, "__eq")
    return 1, None


def handle_ne(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a != b, "__ne")
    return 1, None


def handle_lt(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a < b, "__lt")
    return 1, None


def handle_le(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a <= b, "__le")
    return 1, None


def handle_gt(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a > b, "__gt")
    return 1, None


def handle_ge(state: VMState) -> HandlerResult:
    _binary_op(state, lambda a, b: a >= b, "__ge")
    return 1, None


def handle_not(state: VMState) -> HandlerResult:
    _unary_op(state, lambda a: not a, "__not")
    return 1, None
# Table operations

def handle_newtable(state: VMState) -> HandlerResult:
    state.stack.append({})
    return 1, None


def handle_settable(state: VMState) -> HandlerResult:
    value = state.stack.pop()
    key = state.stack.pop()
    table = state.stack.pop()
    if key in table or "__newindex" not in table:
        table[key] = value
    else:
        mm = table["__newindex"]
        if isinstance(mm, str):
            mm = state.env.get(mm)
        if callable(mm):
            mm(table, key, value)
        else:
            raise VMEmulationError("__newindex metamethod missing")
    state.stack.append(table)
    return 1, None


def handle_gettable(state: VMState) -> HandlerResult:
    key = state.stack.pop()
    table = state.stack.pop()
    try:
        state.stack.append(table[key])
    except Exception:
        mm = table.get("__index") if isinstance(table, dict) else None
        if isinstance(mm, str):
            mm = state.env.get(mm)
        if callable(mm):
            state.stack.append(mm(table, key))
        else:
            raise
    return 1, None


def handle_len(state: VMState) -> HandlerResult:
    _unary_op(state, lambda a: len(a), "__len")
    return 1, None


def handle_vararg(state: VMState, count: int) -> HandlerResult:
    values = state.varargs if count == 0 else state.varargs[:count]
    state.stack.extend(values)
    return 1, None


def handle_self(state: VMState, method_idx: int) -> HandlerResult:
    table = state.stack.pop()
    name = state.constants[method_idx]
    method = None
    if isinstance(table, dict):
        method = table.get(name)
        if isinstance(method, str):
            method = state.env.get(method)
    if not callable(method):
        raise VMEmulationError("self method not found")
    state.stack.append(method)
    state.stack.append(table)
    return 1, None


def handle_setlist(state: VMState, count: int) -> HandlerResult:
    values = [state.stack.pop() for _ in range(count)][::-1]
    table = state.stack.pop()
    start = len(table) + 1
    for i, v in enumerate(values, start):
        table[i] = v
    state.stack.append(table)
    return 1, None


def handle_closure(state: VMState, idx: int, n_upvals: int) -> HandlerResult:
    proto = state.constants[idx]
    upvals = [state.stack.pop() for _ in range(n_upvals)][::-1]
    state.stack.append(VMClosure(proto, upvals, state.env))
    return 1, None
# Control flow

def handle_jmp(state: VMState, offset: int) -> HandlerResult:
    return offset, None


def handle_jmpif(state: VMState, offset: int) -> HandlerResult:
    cond = state.stack.pop()
    return (offset if cond else 1), None


def handle_jmpifnot(state: VMState, offset: int) -> HandlerResult:
    cond = state.stack.pop()
    return (offset if not cond else 1), None


def handle_forprep(state: VMState, offset: int) -> HandlerResult:
    step = state.stack.pop()
    limit = state.stack.pop()
    start = state.stack.pop()
    state.stack.extend([start - step, limit, step])
    return offset, None


def handle_forloop(state: VMState, offset: int) -> HandlerResult:
    step = state.stack[-1]
    limit = state.stack[-2]
    state.stack[-3] += step
    idx = state.stack[-3]
    if (step > 0 and idx <= limit) or (step <= 0 and idx >= limit):
        return offset, None
    state.stack.pop()
    state.stack.pop()
    state.stack.pop()
    return 1, None
# Calls and returns

def handle_call(state: VMState, argc: int) -> HandlerResult:
    call_args = [state.stack.pop() for _ in range(argc)][::-1]
    func = state.stack.pop()
    ret = func(*call_args)
    if ret is not None:
        if isinstance(ret, (list, tuple)):
            state.stack.extend(ret)
        else:
            state.stack.append(ret)
    return 1, None


def handle_return(state: VMState) -> HandlerResult:
    value = state.stack.pop() if state.stack else None
    state.pc = len(state.bytecode)
    return 0, value


def handle_close(state: VMState) -> HandlerResult:
    """Close open upvalues.  No-op for this simple emulator."""
    return 1, None


def handle_unimplemented(state: VMState, *args: Any) -> HandlerResult:
    raise VMEmulationError("opcode not implemented")


# Map opcodes to handlers.  Multiple aliases map to the same handler where
# Luraph uses alternative mnemonic names.
OPCODE_HANDLERS: Dict[str, OpcodeHandler] = {
    "LOADK": handle_loadk,
    "LOADN": handle_loadn,
    "LOADBOOL": handle_loadb,
    "LOADB": handle_loadb,
    "LOADNIL": handle_loadnil,
    "MOVE": handle_move,
    "GETGLOBAL": handle_getglobal,
    "SETGLOBAL": handle_setglobal,
    "GETUPVAL": handle_getupval,
    "SETUPVAL": handle_setupval,
    "ADD": handle_add,
    "SUB": handle_sub,
    "MUL": handle_mul,
    "DIV": handle_div,
    "MOD": handle_mod,
    "POW": handle_pow,
    "UNM": handle_unm,
    "BNOT": handle_bnot,
    "BAND": handle_band,
    "BOR": handle_bor,
    "BXOR": handle_bxor,
    "SHL": handle_shl,
    "SHR": handle_shr,
    "CONCAT": handle_concat,
    "EQ": handle_eq,
    "NE": handle_ne,
    "LT": handle_lt,
    "LE": handle_le,
    "GT": handle_gt,
    "GE": handle_ge,
    "NOT": handle_not,
    "NEWTABLE": handle_newtable,
    "SETTABLE": handle_settable,
    "GETTABLE": handle_gettable,
    "LEN": handle_len,
    "VARARG": handle_vararg,
    "CLOSURE": handle_closure,
    "SELF": handle_self,
    "SETLIST": handle_setlist,
    "JMP": handle_jmp,
    "JMPIF": handle_jmpif,
    "JMPIFNOT": handle_jmpifnot,
    "TEST": handle_test,
    "TESTSET": handle_testset,
    "FORPREP": handle_forprep,
    "FORLOOP": handle_forloop,
    "CALL": handle_call,
    "TAILCALL": handle_call,
    "RETURN": handle_return,
    "TFORLOOP": handle_unimplemented,
    "CLOSE": handle_close,
}

__all__ = ["OPCODE_HANDLERS", "OpcodeHandler", "HandlerResult", "VMClosure"]
