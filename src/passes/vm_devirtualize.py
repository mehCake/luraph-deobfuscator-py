"""Devirtualise VM IR into a structured Lua AST."""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, MutableMapping, Optional, Sequence, Set, Tuple

from ..utils_pkg import ast as lua_ast
from ..utils_pkg.ir import IRInstruction, IRModule
from .variable_rename import rename_chunk

LOG = logging.getLogger(__name__)

_UNKNOWN = object()

_BINOP_SYMBOLS: Dict[str, str] = {
    "ADD": "+",
    "SUB": "-",
    "MUL": "*",
    "DIV": "/",
    "MOD": "%",
    "POW": "^",
    "CONCAT": "..",
}

_COMPARISON_SYMBOLS: Dict[str, str] = {
    "LT": "<",
    "LE": "<=",
    "GT": ">",
    "GE": ">=",
    "EQ": "==",
    "NE": "~=",
    "NOTEQ": "~=",
    "NEQ": "~=",
}


@dataclass(frozen=True)
class _BlockResult:
    statements: List[lua_ast.Stmt]
    next_pc: Optional[int]
    pcs: List[int]
    opcodes: List[str]
    assigned: Set[int]


class DevirtualizeError(Exception):
    """Raised when IR cannot be lowered into Lua source."""


class IRDevirtualizer:
    """Translate :class:`IRModule` programs into Lua AST chunks."""

    def __init__(self, module: IRModule, const_pool: Optional[Sequence[Any]] = None) -> None:
        self.module = module
        self.const_pool: List[Any] = list(const_pool or module.constants or [])
        self._seen_registers: Set[int] = set()
        self._recorded_pcs: Set[int] = set()
        self._pc_mapping: List[Dict[str, Any]] = []
        self._collected_pcs: Set[int] = set()
        self._register_state: Dict[int, Any] = {}
        self._instructions: Dict[int, IRInstruction] = {}
        self._pc_successor: Dict[int, int] = {}

    # ------------------------------------------------------------------
    def lower(self) -> Tuple[lua_ast.Chunk, Dict[str, Any]]:
        reachable_labels = self._reachable_blocks()
        unreachable_labels = [label for label in self.module.blocks if label not in reachable_labels]
        unreachable_pcs = [
            inst.pc
            for label in unreachable_labels
            for inst in self.module.blocks[label].instructions
        ]

        self._instructions = self._collect_instructions(reachable_labels)
        entry_pc: Optional[int] = None
        if not self._instructions and self.module.instructions:
            self._instructions = {inst.pc: inst for inst in self.module.instructions}
            if self._instructions:
                entry_pc = min(self._instructions)
        if not self._instructions:
            metadata = {
                "pc_mapping": [],
                "unreachable_blocks": len(unreachable_labels),
                "eliminated_instructions": len(unreachable_pcs),
            }
            if unreachable_pcs:
                metadata["unreachable_pcs"] = sorted(unreachable_pcs)
            return lua_ast.Chunk(), metadata

        self._initialise_successors()
        entry_block = self.module.blocks.get(self.module.entry)
        if entry_pc is None:
            if entry_block is None:
                entry_pc = min(self._instructions)
            else:
                entry_pc = entry_block.start_pc

        self._seen_registers.clear()
        self._recorded_pcs.clear()
        self._pc_mapping.clear()
        self._collected_pcs.clear()
        self._register_state.clear()

        block_result = self._parse_linear(entry_pc, None, self._register_state, self._seen_registers)
        chunk = lua_ast.Chunk(body=block_result.statements)
        chunk.metadata["original_pcs"] = sorted(self._collected_pcs)

        metadata: Dict[str, Any] = {
            "pc_mapping": sorted(self._pc_mapping, key=lambda entry: entry["pc"]),
            "unreachable_blocks": len(unreachable_labels),
            "eliminated_instructions": len(unreachable_pcs),
        }
        if unreachable_pcs:
            metadata["unreachable_pcs"] = sorted(unreachable_pcs)

        return chunk, metadata

    # ------------------------------------------------------------------
    def _reachable_blocks(self) -> Set[str]:
        if not self.module.blocks:
            return set()
        start = self.module.entry
        if start not in self.module.blocks:
            return set()
        visited: Set[str] = set()
        queue: deque[str] = deque([start])
        while queue:
            label = queue.popleft()
            if label in visited:
                continue
            block = self.module.blocks.get(label)
            if block is None:
                continue
            visited.add(label)
            for successor in block.successors:
                if successor in self.module.blocks and successor not in visited:
                    queue.append(successor)
        return visited

    # ------------------------------------------------------------------
    def _collect_instructions(self, labels: Iterable[str]) -> Dict[int, IRInstruction]:
        mapping: Dict[int, IRInstruction] = {}
        order = [label for label in self.module.order if label in labels]
        if not order:
            order = list(labels)
        for label in order:
            block = self.module.blocks.get(label)
            if block is None:
                continue
            for inst in block.instructions:
                mapping[inst.pc] = inst
        return mapping

    # ------------------------------------------------------------------
    def _initialise_successors(self) -> None:
        pcs = sorted(self._instructions)
        self._pc_successor = {}
        for index, pc in enumerate(pcs[:-1]):
            self._pc_successor[pc] = pcs[index + 1]

    # ------------------------------------------------------------------
    def _parse_linear(
        self,
        start_pc: int,
        stop_pc: Optional[int],
        state: MutableMapping[int, Any],
        seen: Set[int],
    ) -> _BlockResult:
        statements: List[lua_ast.Stmt] = []
        pcs: List[int] = []
        opcodes: List[str] = []
        assigned: Set[int] = set()

        pc: Optional[int] = start_pc
        while pc is not None and pc in self._instructions:
            if stop_pc is not None and pc >= stop_pc:
                break
            inst = self._instructions[pc]
            opcode = inst.opcode
            if opcode == "Test":
                stmt, next_pc, used_pcs, used_ops, written = self._handle_test(inst, state, stop_pc, seen)
                statements.append(stmt)
                pcs.extend(used_pcs)
                opcodes.extend(used_ops)
                assigned.update(written)
                pc = next_pc
                continue
            if opcode == "TForLoop":
                stmt, next_pc, used_pcs, used_ops, written = self._handle_tforloop(inst, state, seen)
                statements.append(stmt)
                pcs.extend(used_pcs)
                opcodes.extend(used_ops)
                assigned.update(written)
                pc = next_pc
                continue
            if opcode == "Return":
                stmt, used_pcs, used_ops = self._handle_return(inst, state)
                statements.append(stmt)
                pcs.extend(used_pcs)
                opcodes.extend(used_ops)
                pc = None
                break
            if opcode == "Closure":
                stmt, next_pc, used_pcs, used_ops, written = self._handle_closure(inst, state, seen)
                statements.append(stmt)
                pcs.extend(used_pcs)
                opcodes.extend(used_ops)
                assigned.update(written)
                pc = next_pc
                continue
            if opcode == "Jump":
                jump_target = inst.args.get("target")
                self._record_instruction(inst)
                pcs.append(inst.pc)
                opcodes.append(inst.opcode)
                if isinstance(jump_target, int):
                    pc = jump_target
                else:
                    pc = self._next_pc(inst.pc)
                continue
            stmt, next_pc, used_pcs, used_ops, written = self._handle_simple(inst, state, seen)
            statements.append(stmt)
            pcs.extend(used_pcs)
            opcodes.extend(used_ops)
            assigned.update(written)
            pc = next_pc

        return _BlockResult(statements, pc, pcs, opcodes, assigned)

    # ------------------------------------------------------------------
    def _handle_simple(
        self, inst: IRInstruction, state: MutableMapping[int, Any], seen: Set[int]
    ) -> Tuple[lua_ast.Stmt, Optional[int], List[int], List[str], Set[int]]:
        if inst.opcode == "LoadK":
            return self._handle_loadk(inst, state, seen)
        if inst.opcode == "BinOp":
            return self._handle_binop(inst, state, seen)
        LOG.debug("Unhandled opcode %s at pc 0x%04X", inst.opcode, inst.pc)
        stmt = lua_ast.CallStmt(lua_ast.Call(lua_ast.Name("noop")))
        self._attach_metadata(stmt, [inst.pc], [inst.opcode])
        self._record_instruction(inst)
        return stmt, self._next_pc(inst.pc), [inst.pc], [inst.opcode], set()

    # ------------------------------------------------------------------
    def _handle_loadk(
        self, inst: IRInstruction, state: MutableMapping[int, Any], seen: Set[int]
    ) -> Tuple[lua_ast.Stmt, Optional[int], List[int], List[str], Set[int]]:
        dest = self._normalise_register(inst.dest, inst.args)
        const_value = inst.args.get("const_value")
        if const_value is None:
            const_index = inst.args.get("const_index")
            if isinstance(const_index, int) and 0 <= const_index < len(self.const_pool):
                const_value = self.const_pool[const_index]
        state[dest] = const_value if dest is not None else _UNKNOWN
        target = lua_ast.Name(self._register_name(dest))
        value = self._literal(const_value)
        is_local = dest not in seen
        seen.add(dest)
        stmt = lua_ast.Assignment([target], [value], is_local=is_local)
        self._record_instruction(inst)
        self._attach_metadata(stmt, [inst.pc], [inst.opcode])
        return stmt, self._next_pc(inst.pc), [inst.pc], [inst.opcode], {dest}

    # ------------------------------------------------------------------
    def _handle_binop(
        self, inst: IRInstruction, state: MutableMapping[int, Any], seen: Set[int]
    ) -> Tuple[lua_ast.Stmt, Optional[int], List[int], List[str], Set[int]]:
        dest = self._normalise_register(inst.dest, inst.args)
        op = inst.args.get("op", "")
        symbol = _BINOP_SYMBOLS.get(op, op)
        lhs_index = inst.args.get("lhs")
        rhs_index = inst.args.get("rhs")
        left = self._register_expr(lhs_index, state)
        right = self._register_expr(rhs_index, state)
        expr: lua_ast.Expr = lua_ast.BinOp(left, symbol, right)
        if isinstance(left, lua_ast.Literal) and isinstance(right, lua_ast.Literal):
            try:
                expr = self._literal(self._evaluate_binop(symbol, left.value, right.value))
            except Exception:  # pragma: no cover - fallback
                expr = lua_ast.BinOp(left, symbol, right)
        is_local = dest not in seen
        seen.add(dest)
        stmt = lua_ast.Assignment([lua_ast.Name(self._register_name(dest))], [expr], is_local=is_local)
        state[dest] = expr.value if isinstance(expr, lua_ast.Literal) else _UNKNOWN
        self._record_instruction(inst)
        self._attach_metadata(stmt, [inst.pc], [inst.opcode])
        return stmt, self._next_pc(inst.pc), [inst.pc], [inst.opcode], {dest}

    # ------------------------------------------------------------------
    def _evaluate_binop(self, symbol: str, left: Any, right: Any) -> Any:
        if symbol == "+":
            return left + right
        if symbol == "-":
            return left - right
        if symbol == "*":
            return left * right
        if symbol == "/":
            return left / right
        if symbol == "%":
            return left % right
        if symbol == "^":
            return left ** right
        if symbol == "..":
            return f"{left}{right}"
        raise ValueError(symbol)

    # ------------------------------------------------------------------
    def _handle_return(
        self, inst: IRInstruction, state: MutableMapping[int, Any]
    ) -> Tuple[lua_ast.Stmt, List[int], List[str]]:
        base = inst.args.get("base")
        count = inst.args.get("count", 0)
        values: List[lua_ast.Expr] = []
        if count and isinstance(base, int):
            for index in range(base, base + count):
                values.append(self._register_expr(index, state))
        stmt = lua_ast.Return(values)
        self._record_instruction(inst)
        self._attach_metadata(stmt, [inst.pc], [inst.opcode])
        return stmt, [inst.pc], [inst.opcode]

    # ------------------------------------------------------------------
    def _handle_test(
        self,
        inst: IRInstruction,
        state: MutableMapping[int, Any],
        stop_pc: Optional[int],
        seen: Set[int],
    ) -> Tuple[lua_ast.Stmt, Optional[int], List[int], List[str], Set[int]]:
        false_target = inst.args.get("target")
        if not isinstance(false_target, int):
            false_target = self._next_pc(inst.pc)
        condition = self._condition_expr(inst, state)
        true_start = self._next_pc(inst.pc)
        jump_pc, jump_inst = self._find_jump(true_start, false_target)
        pcs: List[int] = [inst.pc]
        opcodes: List[str] = [inst.opcode]
        written: Set[int] = set()
        self._record_instruction(inst)
        base_seen = set(seen)

        if jump_inst is not None:
            self._record_instruction(jump_inst)
            pcs.append(jump_inst.pc)
            opcodes.append(jump_inst.opcode)

        if jump_inst is not None and isinstance(jump_inst.args.get("target"), int):
            jump_target = jump_inst.args["target"]
            if jump_target <= inst.pc:
                body_state = dict(state)
                body_result = self._parse_linear(true_start, jump_pc, body_state, set(base_seen))
                loop_stmt = lua_ast.While(condition, body_result.statements)
                loop_pcs = pcs + body_result.pcs
                loop_ops = opcodes + body_result.opcodes
                self._attach_metadata(loop_stmt, loop_pcs, loop_ops)
                for reg in body_result.assigned:
                    state[reg] = _UNKNOWN
                    seen.add(reg)
                written.update(body_result.assigned)
                next_pc = false_target
                return loop_stmt, next_pc, loop_pcs, loop_ops, written

        then_state = dict(state)
        then_result = self._parse_linear(true_start, jump_pc or false_target, then_state, set(base_seen))
        else_stmts: List[lua_ast.Stmt] = []
        else_assigned: Set[int] = set()
        else_pcs: List[int] = []
        else_ops: List[str] = []
        exit_pc = false_target

        if jump_inst is not None and jump_inst.args.get("target") and jump_inst.args["target"] > false_target:
            exit_pc = int(jump_inst.args["target"])
            else_state = dict(state)
            else_result = self._parse_linear(false_target, exit_pc, else_state, set(base_seen))
            else_stmts = else_result.statements
            else_assigned = else_result.assigned
            else_pcs = else_result.pcs
            else_ops = else_result.opcodes

        if_stmt = lua_ast.If(condition, then_result.statements, else_stmts)
        branch_pcs = pcs + then_result.pcs + else_pcs
        branch_ops = opcodes + then_result.opcodes + else_ops
        self._attach_metadata(if_stmt, branch_pcs, branch_ops)

        for reg in then_result.assigned.union(else_assigned):
            state[reg] = _UNKNOWN
            seen.add(reg)
        written.update(then_result.assigned)
        written.update(else_assigned)

        next_pc = exit_pc
        return if_stmt, next_pc, branch_pcs, branch_ops, written

    # ------------------------------------------------------------------
    def _handle_tforloop(
        self, inst: IRInstruction, state: MutableMapping[int, Any], seen: Set[int]
    ) -> Tuple[lua_ast.Stmt, Optional[int], List[int], List[str], Set[int]]:
        base = inst.args.get("base", 0)
        false_target = inst.args.get("target")
        if not isinstance(false_target, int):
            false_target = self._next_pc(inst.pc)
        body_start = self._next_pc(inst.pc)
        jump_pc, jump_inst = self._find_jump(body_start, false_target)
        pcs = [inst.pc]
        opcodes = [inst.opcode]
        self._record_instruction(inst)
        if jump_inst is not None:
            self._record_instruction(jump_inst)
            pcs.append(jump_inst.pc)
            opcodes.append(jump_inst.opcode)
        loop_end = jump_pc or false_target
        body_state = dict(state)
        body_result = self._parse_linear(body_start, loop_end, body_state, set(seen))
        iterables = [
            self._register_expr(base + offset, state)
            for offset in range(3)
        ]
        nvars = inst.args.get("nvars", 1)
        loop_vars = [self._register_name(base + 3 + index) for index in range(int(nvars) or 1)]
        loop_stmt = lua_ast.GenericFor(loop_vars, iterables, body_result.statements)
        loop_pcs = pcs + body_result.pcs
        loop_ops = opcodes + body_result.opcodes
        self._attach_metadata(loop_stmt, loop_pcs, loop_ops)
        assigned = set(body_result.assigned)
        for var in loop_vars:
            try:
                reg_index = int(var[1:])
            except ValueError:
                continue
            assigned.add(reg_index)
            state[reg_index] = _UNKNOWN
            seen.add(reg_index)
        for reg in body_result.assigned:
            state[reg] = _UNKNOWN
            seen.add(reg)
        next_pc = false_target
        return loop_stmt, next_pc, loop_pcs, loop_ops, assigned

    # ------------------------------------------------------------------
    def _handle_closure(
        self, inst: IRInstruction, state: MutableMapping[int, Any], seen: Set[int]
    ) -> Tuple[lua_ast.Stmt, Optional[int], List[int], List[str], Set[int]]:
        dest = self._normalise_register(inst.dest, inst.args)
        proto_index = inst.args.get("proto")
        body: List[lua_ast.Stmt] = []
        proto_module = None
        if isinstance(proto_index, int):
            proto_module = self.module.prototypes.get(proto_index)
        if proto_module is not None:
            nested = IRDevirtualizer(proto_module, proto_module.constants)
            chunk, _ = nested.lower()
            body = chunk.body
        name = lua_ast.Name(self._register_name(dest))
        stmt = lua_ast.FunctionDef(name, [], body, is_local=dest not in seen)
        self._record_instruction(inst)
        seen.add(dest)
        state[dest] = _UNKNOWN
        self._attach_metadata(stmt, [inst.pc], [inst.opcode])
        return stmt, self._next_pc(inst.pc), [inst.pc], [inst.opcode], {dest}

    # ------------------------------------------------------------------
    def _record_instruction(self, inst: IRInstruction) -> None:
        if inst.pc in self._recorded_pcs:
            return
        self._pc_mapping.append({"pc": inst.pc, "opcode": inst.opcode})
        self._collected_pcs.add(inst.pc)
        self._recorded_pcs.add(inst.pc)

    # ------------------------------------------------------------------
    def _attach_metadata(self, stmt: lua_ast.Stmt, pcs: Iterable[int], opcodes: Iterable[str]) -> None:
        unique_pcs = sorted({pc for pc in pcs if isinstance(pc, int)})
        unique_ops = sorted({op for op in opcodes if isinstance(op, str)})
        if unique_pcs:
            stmt.metadata.setdefault("original_pcs", unique_pcs)
        if unique_ops:
            stmt.metadata.setdefault("ir_opcodes", unique_ops)

    # ------------------------------------------------------------------
    def _register_expr(self, index: Optional[int], state: MutableMapping[int, Any]) -> lua_ast.Expr:
        if not isinstance(index, int):
            return lua_ast.Literal(None)
        value = state.get(index, _UNKNOWN)
        if value is _UNKNOWN:
            return lua_ast.Name(self._register_name(index))
        return self._literal(value)

    # ------------------------------------------------------------------
    def _register_name(self, index: Optional[int]) -> str:
        if not isinstance(index, int):
            return "R0"
        return f"R{index}"

    # ------------------------------------------------------------------
    def _literal(self, value: Any) -> lua_ast.Literal:
        return lua_ast.Literal(value)

    # ------------------------------------------------------------------
    def _next_pc(self, pc: int) -> Optional[int]:
        return self._pc_successor.get(pc)

    # ------------------------------------------------------------------
    def _normalise_register(self, value: Optional[int], args: Dict[str, Any]) -> int:
        if isinstance(value, int):
            return value
        candidate = args.get("dest")
        if isinstance(candidate, int):
            return candidate
        candidate = args.get("register")
        if isinstance(candidate, int):
            return candidate
        return 0

    # ------------------------------------------------------------------
    def _condition_expr(self, inst: IRInstruction, state: MutableMapping[int, Any]) -> lua_ast.Expr:
        if "op" in inst.args and inst.args.get("lhs") is not None:
            op = inst.args.get("op")
            symbol = _COMPARISON_SYMBOLS.get(op, op)
            lhs = self._register_expr(inst.args.get("lhs"), state)
            rhs = self._register_expr(inst.args.get("rhs"), state)
            return lua_ast.BinOp(lhs, symbol, rhs)
        if "reg" in inst.args:
            return self._register_expr(inst.args.get("reg"), state)
        return lua_ast.Literal(True)

    # ------------------------------------------------------------------
    def _find_jump(
        self, start_pc: Optional[int], stop_pc: Optional[int]
    ) -> Tuple[Optional[int], Optional[IRInstruction]]:
        pc = start_pc
        while pc is not None and pc in self._instructions:
            if stop_pc is not None and pc >= stop_pc:
                break
            inst = self._instructions[pc]
            if inst.opcode == "Jump":
                return pc, inst
            pc = self._next_pc(pc)
        return None, None


# ----------------------------------------------------------------------

def run(ctx: "Context") -> Dict[str, Any]:  # type: ignore[name-defined]
    """Pipeline entry-point used by tests and the CLI."""

    module = ctx.ir_module
    if module is None:
        raise DevirtualizeError("Context is missing IR module for devirtualisation")

    devirt = IRDevirtualizer(module, module.constants)
    chunk, metadata = devirt.lower()
    rename_stats = rename_chunk(chunk)
    replacements = int(rename_stats.get("replacements", 0))
    metadata["identifier_mapping"] = rename_stats.get("mapping", [])
    metadata["renamed_count"] = replacements
    metadata["renamed_identifiers"] = replacements > 0

    source = lua_ast.to_source(chunk)
    metadata["lua_lines"] = source.count("\n") + (1 if source else 0)

    ctx.stage_output = source
    ctx.reconstructed_lua = source
    ctx.report.variables_renamed = replacements
    ctx.record_metadata("vm_devirtualize", metadata)

    return metadata


__all__ = ["IRDevirtualizer", "DevirtualizeError", "run"]
