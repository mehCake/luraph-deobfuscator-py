from __future__ import annotations

"""Structure canonical VM IR back into pseudo-Lua source."""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from src import simple_graph as nx

from src.ir import VMFunction, VMInstruction
from src.lua_ast import (
    Assign,
    BinOp,
    Call,
    CallStmt,
    Chunk,
    Expr,
    ForNumeric,
    If,
    LocalAssign,
    Name,
    Number,
    Return,
    Stmt,
    String,
    render_chunk,
)


def _register_name(index: int) -> str:
    base = ord("a") + index
    if base <= ord("z"):
        return chr(base)
    return f"r{index}"


def _literal(value: object) -> Expr:
    if isinstance(value, bool):
        return Number(1 if value else 0)
    if isinstance(value, (int, float)):
        return Number(int(value))
    if isinstance(value, str):
        return String(value)
    return Name(str(value))


@dataclass
class BasicBlock:
    start: int
    end: int


class Devirtualizer:
    """Translate VM programs into readable pseudo Lua."""

    def __init__(self, function: Any) -> None:
        self.instructions: List[VMInstruction]
        self._stack_vm: Any | None = None
        self.defined: Dict[int, bool] = {}

        if isinstance(function, VMFunction):
            self.mode = "canonical"
            self.function = function
            self.instructions = list(function.instructions)
            self.cfg = self._build_cfg()
            self._var_idx = 0
        else:
            # Stack-based compatibility path used by legacy helpers.
            self.mode = "stack"
            self._stack_vm = function
            self.instructions = []
            self.cfg = nx.DiGraph()
            self._var_idx = 0

    # ------------------------------------------------------------------
    def render(self) -> str:
        if self.mode == "stack":
            return self._render_stack_vm()
        body, _ = self._emit_block(0, len(self.instructions))
        chunk = Chunk(body=body)
        return render_chunk(chunk)

    # ------------------------------------------------------------------
    def _build_cfg(self) -> nx.DiGraph:
        graph: nx.DiGraph = nx.DiGraph()
        for idx, instr in enumerate(self.instructions):
            graph.add_node(idx)
            if idx + 1 < len(self.instructions):
                graph.add_edge(idx, idx + 1)
            if instr.opcode in {"JMP", "JMPIF", "JMPIFNOT"}:
                offset = int(instr.aux.get("offset", instr.b or 0))
                target = idx + offset + (1 if instr.opcode != "JMP" else 0)
                if 0 <= target < len(self.instructions):
                    graph.add_edge(idx, target)
            if instr.opcode in {"FORPREP", "FORLOOP"}:
                offset = int(instr.aux.get("offset", instr.b or 0))
                target = idx + offset
                if 0 <= target < len(self.instructions):
                    graph.add_edge(idx, target)
        return graph

    # ------------------------------------------------------------------
    def _emit_block(self, start: int, end: int) -> Tuple[List[Stmt], int]:
        stmts: List[Stmt] = []
        idx = start
        while idx < end:
            instr = self.instructions[idx]
            if instr.opcode == "FORPREP":
                loop_end = idx + int(instr.aux.get("offset", instr.b or 0))
                body, _ = self._emit_block(idx + 1, loop_end)
                reg = instr.a or 0
                var_name = _register_name(reg + 3)
                start_expr = Name(_register_name(reg))
                stop_expr = Name(_register_name(reg + 1))
                step_expr = Name(_register_name(reg + 2))
                stmts.append(ForNumeric(var=var_name, start=start_expr, stop=stop_expr, step=step_expr, body=body))
                idx = loop_end
                continue
            if instr.opcode in {"JMPIF", "JMPIFNOT"}:
                target = idx + 1 + int(instr.aux.get("offset", instr.b or 0))
                body, new_idx = self._emit_block(idx + 1, target)
                cond_reg = instr.a or 0
                condition: Expr = Name(_register_name(cond_reg))
                if instr.opcode == "JMPIFNOT":
                    condition = Call(Name("not"), [condition])  # invert via call expression
                stmts.append(If(test=condition, body=body))
                idx = new_idx
                continue
            if instr.opcode == "JMP":
                idx += int(instr.aux.get("offset", instr.b or 0))
                continue
            if instr.opcode == "RETURN":
                base = instr.a or 0
                expr = Name(_register_name(base))
                stmts.append(Return(values=[expr]))
                idx += 1
                continue
            assign = self._translate_instruction(instr)
            if assign is not None:
                stmts.append(assign)
            idx += 1
        return stmts, idx

    def _translate_instruction(self, instr: VMInstruction) -> Optional[Stmt]:
        if instr.opcode == "LOADK":
            value = instr.aux.get("const_b")
            target_name = _register_name(instr.a or 0)
            if not self.defined.get(instr.a or 0):
                self.defined[instr.a or 0] = True
                return LocalAssign(targets=[target_name], values=[_literal(value)])
            return Assign(targets=[Name(target_name)], values=[_literal(value)])
        if instr.opcode == "MOVE":
            src = Name(_register_name(instr.b or 0))
            target_name = _register_name(instr.a or 0)
            if not self.defined.get(instr.a or 0):
                self.defined[instr.a or 0] = True
                return LocalAssign(targets=[target_name], values=[src])
            return Assign(targets=[Name(target_name)], values=[src])
        if instr.opcode in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "BAND", "BOR", "BXOR"}:
            op_map = {
                "ADD": "+",
                "SUB": "-",
                "MUL": "*",
                "DIV": "/",
                "MOD": "%",
                "POW": "^",
                "BAND": "&",
                "BOR": "|",
                "BXOR": "~",
            }
            left = Name(_register_name(instr.b or 0))
            right = Name(_register_name(instr.c or 0))
            target_name = _register_name(instr.a or 0)
            target = Name(target_name)
            result_expr = BinOp(left=left, op=op_map[instr.opcode], right=right)
            if not self.defined.get(instr.a or 0):
                self.defined[instr.a or 0] = True
                return LocalAssign(targets=[target_name], values=[result_expr])
            return Assign(targets=[target], values=[result_expr])
        if instr.opcode == "CALL":
            func = Name(_register_name(instr.a or 0))
            arg_count = int(instr.aux.get("immediate_b", instr.b or 0))
            args: List[Expr] = [
                Name(_register_name((instr.a or 0) + i))
                for i in range(1, max(arg_count, 1))
            ]
            return CallStmt(call=Call(func=func, args=args))
        if instr.opcode == "GETGLOBAL":
            value = instr.aux.get("const_b")
            target_name = _register_name(instr.a or 0)
            expr = Name(str(value)) if isinstance(value, str) else _literal(value)
            if not self.defined.get(instr.a or 0):
                self.defined[instr.a or 0] = True
                return LocalAssign(targets=[target_name], values=[expr])
            return Assign(targets=[Name(target_name)], values=[expr])
        return None

    # Stack VM compatibility -------------------------------------------------
    def _new_var(self) -> str:
        name = _register_name(self._var_idx)
        self._var_idx += 1
        return name

    def _render_stack_vm(self) -> str:
        vm = self._stack_vm
        if vm is None or not hasattr(vm, "state"):
            return ""
        state = getattr(vm, "state")
        bytecode = getattr(state, "bytecode", [])
        constants = getattr(state, "constants", [])
        lines: List[str] = []
        stack: List[Dict[str, Any]] = []

        for raw in bytecode:
            if not raw:
                continue
            op, *args = raw
            if op == "LOADK":
                const = constants[args[0]]
                name = self._new_var()
                lines.append(f"local {name} = {const!r}")
                stack.append({"var": name, "value": const})
            elif op == "LOADN":
                value = args[0]
                name = self._new_var()
                lines.append(f"local {name} = {value}")
                stack.append({"var": name, "value": value})
            elif op == "GETGLOBAL":
                name = constants[args[0]]
                stack.append({"var": name, "value": name})
            elif op == "ADD":
                right = stack.pop() if stack else {"var": "b"}
                left = stack.pop() if stack else {"var": "a"}
                name = self._new_var()
                lv = left.get("value")
                rv = right.get("value")
                if isinstance(lv, (int, float)) and isinstance(rv, (int, float)):
                    value = lv + rv
                    lines.append(f"local {name} = {value}")
                    stack.append({"var": name, "value": value})
                else:
                    lines.append(f"local {name} = {left['var']} + {right['var']}")
                    stack.append({"var": name})
            elif op == "CALL":
                argc = args[0]
                call_args = [stack.pop() for _ in range(argc)][::-1]
                func = stack.pop()
                arg_str = ", ".join(v["var"] for v in call_args)
                lines.append(f"{func['var']}({arg_str})")
                stack.append(func)
            elif op == "RETURN":
                if stack:
                    ret = stack.pop()
                    lines.append(f"return {ret['var']}")

        return "\n".join(lines)


__all__ = ["Devirtualizer"]
