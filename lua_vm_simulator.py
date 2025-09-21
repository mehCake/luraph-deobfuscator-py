from __future__ import annotations

"""Register-based Lua VM simulator operating on canonical VM IR."""

from dataclasses import dataclass, field
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from src.exceptions import VMEmulationError
from src.ir import VMFunction, VMInstruction


logger = logging.getLogger(__name__)


@dataclass
class VMFrame:
    func: VMFunction
    registers: List[Any]
    pc: int = 0
    upvalues: Dict[int, Any] = field(default_factory=dict)
    varargs: List[Any] = field(default_factory=list)


class LuaClosure:
    """Callable capturing upvalues for nested VM functions."""

    def __init__(self, simulator: "LuaVMSimulator", proto: VMFunction, upvalues: Dict[int, Any]):
        self._simulator = simulator
        self._proto = proto
        self._upvalues = upvalues

    def __call__(self, *args: Any) -> Any:  # pragma: no cover - thin wrapper
        return self._simulator._call_function(self._proto, list(args), self._upvalues)


class LuaVMSimulator:
    """Execute :class:`VMFunction` objects produced by the opcode lifter."""

    def __init__(
        self,
        *,
        max_steps: int = 100_000,
        trace: bool = False,
        trace_hook: Optional[Callable[[VMInstruction, VMFrame], None]] = None,
        env: Optional[Dict[str, Any]] = None,
        loop_threshold: int = 64,
    ) -> None:
        self.max_steps = max_steps
        self.trace_enabled = trace
        self.trace_hook = trace_hook
        self.trace_log: List[str] = []
        self._globals: Dict[str, Any] = {}
        self._loop_threshold = max(1, loop_threshold)
        self._install_default_globals()
        if env:
            self._globals.update(env)
        self._frames: List[VMFrame] = []
        self.analysis: Dict[str, Any] = {}
        self._halt_reason: Optional[str] = None
        self._recorded_dummy_pcs: Set[int] = set()
        self._recorded_anti_debug: Set[str] = set()

    # ------------------------------------------------------------------
    def run(self, function: VMFunction, args: Optional[Sequence[Any]] = None) -> Any:
        """Execute ``function`` and return the last ``RETURN`` value."""

        self._reset_analysis()
        self.trace_log = []
        self._frames = [self._create_frame(function, list(args or []))]
        result: Any = None
        steps = 0

        while self._frames:
            frame = self._frames[-1]
            if frame.pc >= len(frame.func.instructions):
                self._frames.pop()
                continue

            instr = frame.func.instructions[frame.pc]
            if self.trace_enabled:
                log_line = f"{len(self._frames)-1}:{frame.pc:04d} {instr.opcode}"
                self.trace_log.append(log_line)
                if self.trace_hook:
                    self.trace_hook(instr, frame)

            current_pc = frame.pc
            frame.pc += 1
            handler = getattr(self, f"_op_{instr.opcode.lower()}", None)
            if handler is None:
                raise VMEmulationError(f"unsupported opcode: {instr.opcode}")
            result = handler(frame, instr)

            self._update_loop_analysis(instr, current_pc)

            steps += 1
            if steps > self.max_steps:
                self._mark_dummy_loop(frame.pc, instr.opcode, "step_limit")
                raise VMEmulationError("step limit exceeded")

            if result is not None and not self._frames:
                self._finalize_analysis()
                return result

            if self._halt_reason:
                break

        self._finalize_analysis()
        return result

    # ------------------------------------------------------------------
    def _create_frame(self, func: VMFunction, args: List[Any], upvalues: Optional[Dict[int, Any]] = None) -> VMFrame:
        register_count = max(func.register_count, len(args)) or 8
        registers = [None] * register_count
        for index, value in enumerate(args):
            if index < len(registers):
                registers[index] = value
        frame = VMFrame(func=func, registers=registers)
        frame.upvalues = dict(upvalues or {})
        if func.num_params and len(args) > func.num_params:
            frame.varargs = list(args[func.num_params :])
        elif func.is_vararg and len(args) > func.num_params:
            frame.varargs = list(args[func.num_params :])
        return frame

    def _call_function(self, func: VMFunction, args: List[Any], upvalues: Optional[Dict[int, Any]] = None) -> Any:
        self._frames.append(self._create_frame(func, args, upvalues))
        return None

    # ------------------------------------------------------------------
    def _reset_analysis(self) -> None:
        self.analysis = {"dummy_loops": [], "anti_debug_checks": []}
        self._halt_reason = None
        self._self_loop_counter = 0
        self._recorded_dummy_pcs = set()
        self._recorded_anti_debug = set()

    def _install_default_globals(self) -> None:
        def stub_print(*_: Any) -> None:
            return None

        def stub_pcall(func: Any, *args: Any) -> Any:
            self._mark_anti_debug("pcall")
            if not callable(func):
                return (False, "pcall: not callable")
            try:
                result = func(*args)
            except Exception as exc:  # pragma: no cover - defensive
                return (False, exc)
            if isinstance(result, tuple):
                return (True, *result)
            if isinstance(result, list):
                return (True, *result)
            if result is None:
                return (True,)
            return (True, result)

        def stub_xpcall(func: Any, err_handler: Any, *args: Any) -> Any:
            self._mark_anti_debug("xpcall")
            if not callable(func):
                return (False, "xpcall: not callable")
            try:
                result = func(*args)
            except Exception as exc:  # pragma: no cover - defensive
                if callable(err_handler):
                    handled = err_handler(exc)
                    if isinstance(handled, tuple):
                        return (False, *handled)
                    if isinstance(handled, list):
                        return (False, *handled)
                    if handled is None:
                        return (False,)
                    return (False, handled)
                return (False, exc)
            if isinstance(result, tuple):
                return (True, *result)
            if isinstance(result, list):
                return (True, *result)
            if result is None:
                return (True,)
            return (True, result)

        def stub_debug_getinfo(*_: Any) -> Dict[str, Any]:
            self._mark_anti_debug("debug.getinfo")
            return {"currentline": 0, "what": "Lua"}

        def stub_debug_traceback(*_: Any) -> str:
            self._mark_anti_debug("debug.traceback")
            return ""

        def stub_debug_sethook(*_: Any) -> None:
            self._mark_anti_debug("debug.sethook")
            return None

        def stub_debug_gethook(*_: Any) -> None:
            self._mark_anti_debug("debug.gethook")
            return None

        def stub_collectgarbage(*_: Any) -> int:
            self._mark_anti_debug("collectgarbage")
            return 0

        def stub_coroutine_running(*_: Any) -> tuple[Any, bool]:
            self._mark_anti_debug("coroutine.running")
            return None, False

        def stub_os_clock(*_: Any) -> float:
            self._mark_anti_debug("os.clock")
            return 0.0

        def stub_string_dump(*_: Any) -> str:
            self._mark_anti_debug("string.dump")
            return ""

        def stub_getfenv(*_: Any) -> Dict[str, Any]:
            self._mark_anti_debug("getfenv")
            return {}

        self._globals["print"] = stub_print
        self._globals["pcall"] = stub_pcall
        self._globals["xpcall"] = stub_xpcall
        self._globals["collectgarbage"] = stub_collectgarbage
        self._globals["getfenv"] = stub_getfenv
        self._globals.setdefault("debug", {})
        self._globals["debug"].update(
            {
                "getinfo": stub_debug_getinfo,
                "traceback": stub_debug_traceback,
                "sethook": stub_debug_sethook,
                "gethook": stub_debug_gethook,
            }
        )
        self._globals.setdefault("coroutine", {})
        self._globals["coroutine"].update({"running": stub_coroutine_running})
        self._globals.setdefault("os", {})
        self._globals["os"].update({"clock": stub_os_clock})
        self._globals.setdefault("string", {})
        self._globals["string"].update({"dump": stub_string_dump})

    def _mark_dummy_loop(self, pc: int, opcode: str, reason: str) -> None:
        if pc not in self._recorded_dummy_pcs:
            self.analysis.setdefault("dummy_loops", []).append(
                {"pc": pc, "opcode": opcode, "reason": reason}
            )
            self._recorded_dummy_pcs.add(pc)
        self._halt_reason = "dummy_loop"

    def _mark_anti_debug(self, name: str) -> None:
        if name not in self._recorded_anti_debug:
            self.analysis.setdefault("anti_debug_checks", []).append(name)
            self._recorded_anti_debug.add(name)

    def _update_loop_analysis(self, instr: VMInstruction, original_pc: int) -> None:
        if instr.opcode == "JMP" and self._frames:
            frame = self._frames[-1]
            if frame.pc == original_pc:
                self._self_loop_counter += 1
                if self._self_loop_counter >= self._loop_threshold:
                    self._mark_dummy_loop(original_pc, instr.opcode, "self_loop")
                    self._frames.clear()
            else:
                self._self_loop_counter = 0
        elif instr.opcode not in {"TEST", "TESTSET"}:
            self._self_loop_counter = 0

    def _finalize_analysis(self) -> None:
        if self._halt_reason and "halt_reason" not in self.analysis:
            self.analysis["halt_reason"] = self._halt_reason

    # Operand helpers
    def _read_register(self, frame: VMFrame, index: Optional[int]) -> Any:
        if index is None:
            return None
        if index >= len(frame.registers):
            frame.registers.extend([None] * (index - len(frame.registers) + 1))
        return frame.registers[index]

    def _write_register(self, frame: VMFrame, index: Optional[int], value: Any) -> None:
        if index is None:
            return
        if index >= len(frame.registers):
            frame.registers.extend([None] * (index - len(frame.registers) + 1))
        frame.registers[index] = value

    def _operand_value(self, frame: VMFrame, instr: VMInstruction, name: str, raw: Optional[int]) -> Any:
        mode = instr.aux.get(f"{name}_mode", "register")
        if mode == "register":
            return self._read_register(frame, raw)
        if mode == "const":
            key = f"const_{name}"
            if key in instr.aux:
                return instr.aux[key]
            index = instr.aux.get(f"{name}_index", raw)
            if isinstance(index, int) and 0 <= index < len(frame.func.constants):
                return frame.func.constants[index]
            return index
        if mode == "immediate":
            return instr.aux.get(f"immediate_{name}", raw)
        if mode == "rk":
            key = f"const_{name}"
            if key in instr.aux:
                return instr.aux[key]
            return self._read_register(frame, raw)
        if mode == "upvalue":
            if raw is None:
                return None
            return frame.upvalues.get(raw)
        return raw

    def _store_result(self, frame: VMFrame, instr: VMInstruction, value: Any) -> None:
        self._write_register(frame, instr.a, value)

    # ------------------------------------------------------------------
    # Arithmetic helpers with metamethod fallbacks
    def _binary_operation(
        self,
        frame: VMFrame,
        instr: VMInstruction,
        operation: Callable[[Any, Any], Any],
        metamethod: str,
    ) -> None:
        left = self._operand_value(frame, instr, "b", instr.b)
        right = self._operand_value(frame, instr, "c", instr.c)
        try:
            result = operation(left, right)
        except Exception:
            result = self._invoke_metamethod(frame, left, right, metamethod)
        self._store_result(frame, instr, result)

    def _unary_operation(
        self,
        frame: VMFrame,
        instr: VMInstruction,
        operation: Callable[[Any], Any],
        metamethod: str,
    ) -> None:
        operand = self._operand_value(frame, instr, "b", instr.b)
        try:
            result = operation(operand)
        except Exception:
            result = self._invoke_metamethod(frame, operand, None, metamethod)
        self._store_result(frame, instr, result)

    def _invoke_metamethod(self, frame: VMFrame, left: Any, right: Any, name: str) -> Any:
        for candidate in (left, right):
            if isinstance(candidate, dict) and name in candidate:
                method = candidate[name]
                if isinstance(method, str):
                    method = self._globals.get(method)
                if callable(method):
                    if right is None:
                        return method(candidate)
                    return method(left, right)
        raise VMEmulationError(f"metamethod {name} not found")

    # ------------------------------------------------------------------
    # Opcode handlers
    def _op_loadk(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "b", instr.b)
        self._store_result(frame, instr, value)

    def _op_loadn(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "b", instr.b)
        self._store_result(frame, instr, value)

    def _op_loadb(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = bool(self._operand_value(frame, instr, "b", instr.b))
        self._store_result(frame, instr, value)

    def _op_loadnil(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._store_result(frame, instr, None)

    def _op_move(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "b", instr.b)
        self._store_result(frame, instr, value)

    def _op_getglobal(self, frame: VMFrame, instr: VMInstruction) -> None:
        name = self._operand_value(frame, instr, "b", instr.b)
        self._store_result(frame, instr, self._globals.get(name))

    def _op_setglobal(self, frame: VMFrame, instr: VMInstruction) -> None:
        name = self._operand_value(frame, instr, "b", instr.b)
        value = self._operand_value(frame, instr, "a", instr.a)
        if isinstance(name, str):
            self._globals[name] = value

    def _op_getupval(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "b", instr.b)
        self._store_result(frame, instr, value)

    def _op_setupval(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "a", instr.a)
        index = instr.aux.get("upvalue_index", instr.b or 0)
        frame.upvalues[index] = value

    def _op_newtable(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._store_result(frame, instr, {})

    def _op_settable(self, frame: VMFrame, instr: VMInstruction) -> None:
        table = self._operand_value(frame, instr, "a", instr.a)
        key = self._operand_value(frame, instr, "b", instr.b)
        value = self._operand_value(frame, instr, "c", instr.c)
        if isinstance(table, dict):
            if key in table or "__newindex" not in table:
                table[key] = value
            else:
                self._invoke_newindex(frame, table, key, value)

    def _invoke_newindex(self, frame: VMFrame, table: Dict[Any, Any], key: Any, value: Any) -> None:
        handler = table.get("__newindex")
        if isinstance(handler, str):
            handler = self._globals.get(handler)
        if callable(handler):
            handler(table, key, value)
        elif isinstance(handler, dict):
            handler[key] = value
        else:
            table[key] = value

    def _op_gettable(self, frame: VMFrame, instr: VMInstruction) -> None:
        table = self._operand_value(frame, instr, "b", instr.b)
        key = self._operand_value(frame, instr, "c", instr.c)
        if isinstance(table, dict):
            if key in table:
                value = table[key]
            else:
                value = self._invoke_index(frame, table, key)
        else:
            value = None
        self._store_result(frame, instr, value)

    def _invoke_index(self, frame: VMFrame, table: Dict[Any, Any], key: Any) -> Any:
        handler = table.get("__index")
        if handler is None:
            return None
        if isinstance(handler, str):
            handler = self._globals.get(handler)
        if callable(handler):
            return handler(table, key)
        if isinstance(handler, dict):
            return handler.get(key)
        return None

    def _op_self(self, frame: VMFrame, instr: VMInstruction) -> None:
        table = self._operand_value(frame, instr, "b", instr.b)
        key = self._operand_value(frame, instr, "c", instr.c)
        self._write_register(frame, instr.a, table)
        next_reg = None if instr.a is None else instr.a + 1
        method = None
        if isinstance(table, dict):
            method = table.get(key)
        elif table is not None:
            method = getattr(table, key, None)
        self._write_register(frame, next_reg, method)

    def _op_len(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "b", instr.b)
        try:
            result = len(value)
        except Exception:
            result = self._invoke_metamethod(frame, value, None, "__len")
        self._store_result(frame, instr, result)

    def _op_concat(self, frame: VMFrame, instr: VMInstruction) -> None:
        left = self._operand_value(frame, instr, "b", instr.b)
        right = self._operand_value(frame, instr, "c", instr.c)
        self._store_result(frame, instr, f"{left}{right}")

    def _op_not(self, frame: VMFrame, instr: VMInstruction) -> None:
        value = self._operand_value(frame, instr, "b", instr.b)
        self._store_result(frame, instr, not bool(value))

    def _op_band(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: int(a) & int(b), "__band")

    def _op_bor(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: int(a) | int(b), "__bor")

    def _op_bxor(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: int(a) ^ int(b), "__bxor")

    def _op_bnot(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._unary_operation(frame, instr, lambda a: ~int(a), "__bnot")

    def _op_shl(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: int(a) << int(b), "__shl")

    def _op_shr(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: int(a) >> int(b), "__shr")

    def _op_add(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: a + b, "__add")

    def _op_sub(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: a - b, "__sub")

    def _op_mul(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: a * b, "__mul")

    def _op_div(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: a / b, "__div")

    def _op_mod(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: a % b, "__mod")

    def _op_pow(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._binary_operation(frame, instr, lambda a, b: a ** b, "__pow")

    def _op_unm(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._unary_operation(frame, instr, lambda a: -a, "__unm")

    def _comparison(self, frame: VMFrame, instr: VMInstruction, op: Callable[[Any, Any], bool]) -> None:
        left = self._operand_value(frame, instr, "b", instr.b)
        right = self._operand_value(frame, instr, "c", instr.c)
        try:
            result = op(left, right)
        except Exception:
            result = self._invoke_metamethod(frame, left, right, "__eq")
        self._store_result(frame, instr, result)

    def _op_eq(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._comparison(frame, instr, lambda a, b: a == b)

    def _op_ne(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._comparison(frame, instr, lambda a, b: a != b)

    def _op_lt(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._comparison(frame, instr, lambda a, b: a < b)

    def _op_le(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._comparison(frame, instr, lambda a, b: a <= b)

    def _op_gt(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._comparison(frame, instr, lambda a, b: a > b)

    def _op_ge(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._comparison(frame, instr, lambda a, b: a >= b)

    def _jump(self, frame: VMFrame, instr: VMInstruction, condition: Optional[bool]) -> None:
        offset = int(instr.aux.get("offset", instr.b or 0))
        if condition is None or condition:
            frame.pc += offset

    def _op_jmp(self, frame: VMFrame, instr: VMInstruction) -> None:
        self._jump(frame, instr, True)

    def _op_jmpif(self, frame: VMFrame, instr: VMInstruction) -> None:
        condition = bool(self._operand_value(frame, instr, "a", instr.a))
        self._jump(frame, instr, condition)

    def _op_jmpifnot(self, frame: VMFrame, instr: VMInstruction) -> None:
        condition = not bool(self._operand_value(frame, instr, "a", instr.a))
        self._jump(frame, instr, condition)

    def _op_test(self, frame: VMFrame, instr: VMInstruction) -> None:
        expectation = bool(self._operand_value(frame, instr, "b", instr.b))
        value = bool(self._operand_value(frame, instr, "a", instr.a))
        if value != expectation:
            frame.pc += 1

    def _op_testset(self, frame: VMFrame, instr: VMInstruction) -> None:
        expectation = bool(self._operand_value(frame, instr, "c", instr.c))
        value = bool(self._operand_value(frame, instr, "b", instr.b))
        if value == expectation:
            self._store_result(frame, instr, self._operand_value(frame, instr, "b", instr.b))
        else:
            frame.pc += 1

    def _op_forprep(self, frame: VMFrame, instr: VMInstruction) -> None:
        base = instr.a or 0
        start = self._read_register(frame, base)
        step = self._read_register(frame, base + 2)
        if start is None:
            start = 0
        if step is None:
            step = 1
        self._write_register(frame, base, start - step)
        self._jump(frame, instr, True)

    def _op_forloop(self, frame: VMFrame, instr: VMInstruction) -> None:
        base = instr.a or 0
        step = self._read_register(frame, base + 2) or 1
        value = (self._read_register(frame, base) or 0) + step
        limit = self._read_register(frame, base + 1) or 0
        self._write_register(frame, base, value)
        self._write_register(frame, base + 3, value)
        if (step >= 0 and value <= limit) or (step < 0 and value >= limit):
            frame.pc += int(instr.aux.get("offset", instr.b or 0))

    def _op_tforloop(self, frame: VMFrame, instr: VMInstruction) -> None:
        base = instr.a or 0
        iterator = self._read_register(frame, base)
        state = self._read_register(frame, base + 1)
        control = self._read_register(frame, base + 2)
        if not callable(iterator):
            raise VMEmulationError("iterator not callable")
        result = iterator(state, control)
        if isinstance(result, tuple):
            values = list(result)
        elif isinstance(result, list):
            values = list(result)
        elif result is None:
            values = []
        else:
            values = [result]
        if not values or values[0] is None:
            target = instr.aux.get("target")
            if isinstance(target, int):
                frame.pc = target
            return
        control_value = values[0]
        self._write_register(frame, base + 2, control_value)
        count = int(instr.aux.get("immediate_c", instr.c or len(values)))
        for idx in range(count):
            value = values[idx] if idx < len(values) else None
            self._write_register(frame, base + 3 + idx, value)
        offset = int(instr.aux.get("offset", instr.b or 0))
        if offset:
            frame.pc += offset

    def _op_call(self, frame: VMFrame, instr: VMInstruction) -> None:
        base = instr.a or 0
        arg_count = int(instr.aux.get("immediate_b", instr.b or 0))
        ret_count = int(instr.aux.get("immediate_c", instr.c or 0))
        func = self._read_register(frame, base)
        args = [self._read_register(frame, base + i) for i in range(1, max(arg_count, 1))]
        result = None
        if callable(func):
            result = func(*args)
        if ret_count == 0:
            return
        if ret_count == 1:
            self._write_register(frame, base, result)
        else:
            results = result if isinstance(result, (list, tuple)) else [result]
            for offset, value in enumerate(results[:ret_count]):
                self._write_register(frame, base + offset, value)

    def _op_tailcall(self, frame: VMFrame, instr: VMInstruction) -> Any:
        self._op_call(frame, instr)
        self._frames.pop()
        return None

    def _op_return(self, frame: VMFrame, instr: VMInstruction) -> Any:
        base = instr.a or 0
        count = int(instr.aux.get("immediate_b", instr.b or 0))
        if count <= 0:
            result = None
        else:
            result = self._read_register(frame, base)
        self._frames.pop()
        return result

    def _op_vararg(self, frame: VMFrame, instr: VMInstruction) -> None:
        base = instr.a or 0
        count = int(instr.aux.get("immediate_b", instr.b or 0))
        for idx in range(count):
            value = frame.varargs[idx] if idx < len(frame.varargs) else None
            self._write_register(frame, base + idx, value)

    def _op_closure(self, frame: VMFrame, instr: VMInstruction) -> None:
        proto_index = instr.aux.get("proto_index", instr.b or 0)
        if proto_index >= len(frame.func.prototypes):
            raise VMEmulationError("closure prototype out of range")
        proto = frame.func.prototypes[proto_index]
        bindings: Dict[int, Any] = {}
        for idx, spec in enumerate(instr.aux.get("upvalues", [])):
            kind = spec.get("type", "register")
            source = spec.get("index", idx)
            if kind == "register":
                bindings[idx] = self._read_register(frame, source)
            else:
                bindings[idx] = frame.upvalues.get(source)
        closure = LuaClosure(self, proto, bindings)
        self._store_result(frame, instr, closure)

    def _op_setlist(self, frame: VMFrame, instr: VMInstruction) -> None:
        table = self._operand_value(frame, instr, "a", instr.a)
        count = int(instr.aux.get("immediate_b", instr.b or 0))
        for offset in range(count):
            value = self._read_register(frame, (instr.a or 0) + 1 + offset)
            if isinstance(table, dict):
                table[offset + 1] = value

    def _op_close(self, frame: VMFrame, instr: VMInstruction) -> None:  # pragma: no cover - stub
        _ = instr


__all__ = ["LuaVMSimulator", "LuaClosure"]
