"""Lower VM IR into a Lua AST and pretty-printed pseudo source."""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from variable_renamer import VariableRenamer

from .. import utils
from ..utils_pkg import ast as lua_ast
from ..utils_pkg.ir import IRBasicBlock, IRInstruction, IRModule
from ..versions import VersionHandler, decode_constant_pool, get_handler

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class _LoweringContext:
    registers: Dict[int, lua_ast.Expr] = field(default_factory=dict)
    defined: set[int] = field(default_factory=set)

    def clone(self) -> "_LoweringContext":
        return _LoweringContext(dict(self.registers), set(self.defined))


class _RegisterNamer:
    def __init__(self) -> None:
        self._cache: Dict[int, str] = {}

    def name(self, index: int) -> str:
        if index not in self._cache:
            self._cache[index] = f"R{index}"
        return self._cache[index]


class IRDevirtualizer:
    """Translate ``IRModule`` instructions into a Lua AST."""

    def __init__(self, module: IRModule, constants: Sequence[Any]) -> None:
        self.module = module
        self.constants = list(constants)
        self.instructions: List[IRInstruction] = list(module.instructions)
        self._pc_to_index: Dict[int, int] = {inst.pc: idx for idx, inst in enumerate(self.instructions)}
        self.blocks: Dict[str, IRBasicBlock] = dict(module.blocks or {})
        self.block_order: List[str] = list(module.order or [])
        entry: Optional[str] = module.entry if module.entry in self.blocks else None
        if entry is None and self.block_order:
            candidate = self.block_order[0]
            entry = candidate if candidate in self.blocks else None
        if entry is None and self.blocks:
            entry = next(iter(self.blocks))
        self.entry_block: Optional[str] = entry
        self._namer = _RegisterNamer()
        self._unknown = 0
        self._loop_count = 0
        self._branch_count = 0
        self._closure_count = 0
        self._prototype_modules: Dict[int, IRModule] = getattr(module, "prototypes", {}) or {}
        self._prototype_cache: Dict[int, List[lua_ast.Stmt]] = {}
        self._closure_aliases: Dict[int, str] = {}
        self._reachable_blocks, self._reachable_pcs = self._analyse_cfg()
        self._unreachable_blocks = set(self.blocks) - self._reachable_blocks
        self._unreachable_pcs = {
            inst.pc for inst in self.instructions if inst.pc not in self._reachable_pcs
        }

        self._handlers = {
            "LoadK": self._handle_loadk,
            "LoadNil": self._handle_loadnil,
            "Move": self._handle_move,
            "NewTable": self._handle_newtable,
            "GetTable": self._handle_gettable,
            "SetTable": self._handle_settable,
            "BinOp": self._handle_binop,
            "UnOp": self._handle_unop,
            "Call": self._handle_call,
            "Return": self._handle_return,
            "Jump": self._handle_jump,
            "Test": self._handle_test,
            "ForPrep": self._handle_forprep,
            "ForLoop": self._handle_forloop,
            "TForLoop": self._handle_tforloop,
            "VarArg": self._handle_vararg,
            "UpvalGet": self._handle_upval_get,
            "UpvalSet": self._handle_upval_set,
            "GlobalGet": self._handle_global_get,
            "GlobalSet": self._handle_global_set,
            "Closure": self._handle_closure,
        }

    # ------------------------------------------------------------------
    def _analyse_cfg(self) -> Tuple[set[str], set[int]]:
        blocks = self.blocks
        if not blocks:
            pcs = {inst.pc for inst in self.instructions}
            return set(), pcs

        start = self.entry_block
        if start is None:
            for label in self.block_order:
                if label in blocks:
                    start = label
                    break
        if start is None and blocks:
            start = next(iter(blocks))

        reachable_blocks: set[str] = set()
        reachable_pcs: set[int] = set()

        if start is None:
            for inst in self.instructions:
                reachable_pcs.add(inst.pc)
            return reachable_blocks, reachable_pcs

        stack: List[str] = [start]
        while stack:
            label = stack.pop()
            if label in reachable_blocks:
                continue
            block = blocks.get(label)
            if block is None:
                continue
            reachable_blocks.add(label)
            for inst in block.instructions:
                reachable_pcs.add(inst.pc)
            for succ in block.successors:
                if succ not in reachable_blocks and succ in blocks:
                    stack.append(succ)

        if not reachable_pcs:
            for inst in self.instructions:
                reachable_pcs.add(inst.pc)

        return reachable_blocks, reachable_pcs

    # ------------------------------------------------------------------
    def lower(self) -> Tuple[lua_ast.Chunk, Dict[str, Any]]:
        ctx = _LoweringContext()
        body, _ = self._lower_range(ctx, 0, len(self.instructions))
        chunk = lua_ast.Chunk(body=body)
        metadata = {
            "statements": self._count_statements(body),
            "unknown_instructions": self._unknown,
            "loops": self._loop_count,
            "branches": self._branch_count,
        }
        if self.blocks:
            metadata["reachable_blocks"] = len(self._reachable_blocks)
            if self._unreachable_blocks:
                metadata["unreachable_blocks"] = len(self._unreachable_blocks)
        eliminated = len(self._unreachable_pcs)
        if eliminated:
            metadata["eliminated_instructions"] = eliminated
        if self._closure_count:
            metadata["closures"] = self._closure_count
        return chunk, metadata

    # ------------------------------------------------------------------
    def _lower_range(
        self,
        ctx: _LoweringContext,
        start: int,
        end: int,
    ) -> Tuple[List[lua_ast.Stmt], int]:
        statements: List[lua_ast.Stmt] = []
        idx = start
        while idx < end:
            inst = self.instructions[idx]
            if self.blocks and inst.pc not in self._reachable_pcs:
                idx += 1
                continue
            handler = self._handlers.get(inst.opcode)
            if handler is None:
                self._unknown += 1
                idx += 1
                continue
            idx = handler(ctx, idx, end, statements)
        return statements, idx

    # --- Helpers -----------------------------------------------------
    def _literal(self, value: Any) -> lua_ast.Expr:
        if isinstance(value, lua_ast.Expr):
            return value
        if isinstance(value, (int, float, str, bool)) or value is None:
            return lua_ast.Literal(value)
        return lua_ast.Name(repr(value))

    def _register_name(self, index: int | None) -> str:
        if index is None:
            return "var_0"
        return self._namer.name(index)

    def _expr_for_register(self, ctx: _LoweringContext, index: int | None) -> lua_ast.Expr:
        if index is None:
            return lua_ast.Literal(None)
        expr = ctx.registers.get(index)
        if expr is None:
            expr = lua_ast.Name(self._register_name(index))
            ctx.registers[index] = expr
        return expr

    def _expr_from_value(self, ctx: _LoweringContext, value: Any) -> lua_ast.Expr:
        if isinstance(value, int):
            return self._expr_for_register(ctx, value)
        if isinstance(value, (str, bytes)):
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8")
                except Exception:
                    value = value.hex()
            return self._literal(value)
        if isinstance(value, (float, bool)) or value is None:
            return self._literal(value)
        return self._literal(value)

    def _assign_register(
        self,
        ctx: _LoweringContext,
        reg: int | None,
        expr: lua_ast.Expr,
        *,
        allow_local: bool = True,
    ) -> Optional[lua_ast.Assignment]:
        if reg is None:
            return None
        name = self._register_name(reg)
        existing = ctx.registers.get(reg)
        if existing is expr or (
            isinstance(existing, lua_ast.Name)
            and isinstance(expr, lua_ast.Name)
            and existing.ident == expr.ident
        ):
            return None
        is_local = allow_local and reg not in ctx.defined
        ctx.registers[reg] = expr
        if is_local:
            ctx.defined.add(reg)
        return lua_ast.Assignment(targets=[lua_ast.Name(name)], values=[expr], is_local=is_local)

    def _lower_prototype_body(self, proto_index: int | None) -> List[lua_ast.Stmt]:
        if not isinstance(proto_index, int):
            return []
        cached = self._prototype_cache.get(proto_index)
        if cached is not None:
            return [copy.deepcopy(stmt) for stmt in cached]
        module = self._prototype_modules.get(proto_index)
        if not isinstance(module, IRModule):
            self._prototype_cache[proto_index] = []
            return []
        nested = IRDevirtualizer(module, module.constants)
        chunk, _ = nested.lower()
        body = chunk.body
        self._prototype_cache[proto_index] = body
        return [copy.deepcopy(stmt) for stmt in body]

    def _fetch_constant(self, index: int | None) -> Any:
        if index is None:
            return None
        if 0 <= index < len(self.constants):
            return self.constants[index]
        return None

    def _condition_expr(self, ctx: _LoweringContext, inst: IRInstruction) -> lua_ast.Expr:
        args = inst.args
        op = args.get("op")
        if "lhs" in args and "rhs" in args:
            lhs = self._expr_from_value(ctx, args.get("lhs"))
            rhs = self._expr_from_value(ctx, args.get("rhs"))
            op_map = {"EQ": "==", "LT": "<", "LE": "<="}
            if isinstance(op, str):
                symbol = op_map.get(op, "==")
            else:
                symbol = "=="
            return lua_ast.BinOp(lhs, symbol, rhs)
        if "dest" in args:
            return self._expr_from_value(ctx, args.get("dest"))
        if "reg" in args:
            return self._expr_from_value(ctx, args.get("reg"))
        return lua_ast.Name("cond")

    def _negate(self, expr: lua_ast.Expr) -> lua_ast.Expr:
        if isinstance(expr, lua_ast.UnOp) and expr.op == "not":
            return expr.operand
        return lua_ast.UnOp("not", expr)

    def _fold_binop(self, op: str, left: lua_ast.Expr, right: lua_ast.Expr) -> lua_ast.Expr:
        if isinstance(left, lua_ast.Literal) and isinstance(right, lua_ast.Literal):
            lval = left.value
            rval = right.value
            if isinstance(lval, (int, float)) and isinstance(rval, (int, float)):
                try:
                    if op == "ADD":
                        return lua_ast.Literal(lval + rval)
                    if op == "SUB":
                        return lua_ast.Literal(lval - rval)
                    if op == "MUL":
                        return lua_ast.Literal(lval * rval)
                    if op == "DIV" and rval != 0:
                        return lua_ast.Literal(lval / rval)
                    if op == "MOD" and rval != 0:
                        return lua_ast.Literal(lval % rval)
                    if op == "POW":
                        return lua_ast.Literal(lval ** rval)
                except Exception:
                    pass
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
            "SHL": "<<",
            "SHR": ">>",
        }
        return lua_ast.BinOp(left, op_map.get(op, op.lower()), right)

    def _count_statements(self, stmts: Sequence[lua_ast.Stmt]) -> int:
        total = 0
        for stmt in stmts:
            total += 1
            if isinstance(stmt, lua_ast.If):
                total += self._count_statements(stmt.body)
                total += self._count_statements(stmt.orelse)
            elif isinstance(stmt, lua_ast.NumericFor):
                total += self._count_statements(stmt.body)
            elif isinstance(stmt, lua_ast.While):
                total += self._count_statements(stmt.body)
            elif isinstance(stmt, lua_ast.FunctionDef):
                total += self._count_statements(stmt.body)
        return total

    # --- Instruction handlers ----------------------------------------
    def _handle_loadk(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest") or inst.dest
        value = inst.args.get("const_value")
        if value is None and "const_index" in inst.args:
            value = self._fetch_constant(inst.args.get("const_index"))
        expr = self._literal(value)
        assign = self._assign_register(ctx, dest, expr)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_loadnil(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        start_reg = inst.args.get("start", 0)
        end_reg = inst.args.get("end", start_reg)
        for reg in range(start_reg, end_reg + 1):
            assign = self._assign_register(ctx, reg, lua_ast.Literal(None))
            if assign:
                out.append(assign)
        return idx + 1

    def _handle_move(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest")
        src = inst.args.get("src")
        expr = self._expr_for_register(ctx, src)
        assign = self._assign_register(ctx, dest, expr, allow_local=False)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_newtable(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest") or inst.dest
        expr = lua_ast.TableConstructor()
        assign = self._assign_register(ctx, dest, expr)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_gettable(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest") or inst.dest
        table_reg = inst.args.get("table") or inst.args.get("lhs")
        key_reg = inst.args.get("key") or inst.args.get("index")
        table_expr = self._expr_for_register(ctx, table_reg)
        key_expr = self._expr_from_value(ctx, key_reg)
        expr = lua_ast.TableAccess(table_expr, key_expr)
        assign = self._assign_register(ctx, dest, expr)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_settable(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        table_reg = inst.args.get("table")
        key = inst.args.get("key")
        value = inst.args.get("value")
        table_expr = self._expr_for_register(ctx, table_reg)
        key_expr = self._expr_from_value(ctx, key)
        value_expr = self._expr_from_value(ctx, value)
        target = lua_ast.TableAccess(table_expr, key_expr)
        out.append(lua_ast.Assignment(targets=[target], values=[value_expr], is_local=False))
        return idx + 1

    def _handle_binop(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest") or inst.dest
        lhs = self._expr_from_value(ctx, inst.args.get("lhs"))
        rhs = self._expr_from_value(ctx, inst.args.get("rhs"))
        expr = self._fold_binop(inst.args.get("op", ""), lhs, rhs)
        assign = self._assign_register(ctx, dest, expr, allow_local=False)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_unop(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest") or inst.dest
        src_expr = self._expr_from_value(ctx, inst.args.get("src"))
        op_map = {"UNM": "-", "BNOT": "~", "NOT": "not", "LEN": "#"}
        op = inst.args.get("op")
        rendered = op_map.get(op or "", "not")
        expr = lua_ast.UnOp(rendered, src_expr)
        assign = self._assign_register(ctx, dest, expr, allow_local=False)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_call(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        base = inst.args.get("base")
        nargs = inst.args.get("nargs")
        nret = inst.args.get("nret")
        func_expr = self._expr_for_register(ctx, base)
        args: List[lua_ast.Expr] = []
        if isinstance(nargs, int) and nargs > 1:
            for offset in range(1, nargs):
                args.append(self._expr_for_register(ctx, (base or 0) + offset))
        call = lua_ast.Call(func_expr, args)
        if isinstance(nret, int) and nret > 0:
            targets: List[lua_ast.Expr] = []
            is_local = False
            for offset in range(nret):
                reg = (base or 0) + offset
                name = self._register_name(reg)
                targets.append(lua_ast.Name(name))
                if reg not in ctx.defined:
                    ctx.defined.add(reg)
                    is_local = True
                ctx.registers[reg] = lua_ast.Name(name)
            out.append(lua_ast.Assignment(targets=targets, values=[call], is_local=is_local))
        else:
            out.append(lua_ast.CallStmt(call))
        return idx + 1

    def _handle_return(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        base = inst.args.get("base") or 0
        count = inst.args.get("count")
        values: List[lua_ast.Expr] = []
        if isinstance(count, int) and count > 0:
            for offset in range(count):
                values.append(self._expr_for_register(ctx, base + offset))
        elif isinstance(count, int) and count == 0:
            values.append(self._expr_for_register(ctx, base))
        else:
            values.append(self._expr_for_register(ctx, base))
        out.append(lua_ast.Return(values))
        return end

    def _handle_jump(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        target_pc = inst.args.get("target")
        target_idx = self._pc_to_index.get(target_pc) if target_pc is not None else None
        if target_idx is None:
            return idx + 1
        if self.blocks and isinstance(target_pc, int) and target_pc not in self._reachable_pcs:
            return end
        if target_idx <= idx:
            # Backwards jump – treat as loop terminator.
            return end
        return target_idx

    def _handle_test(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        target_pc = inst.args.get("target")
        target_idx = self._pc_to_index.get(target_pc) if target_pc is not None else None
        if target_idx is None or target_idx <= idx:
            return idx + 1
        cond = self._condition_expr(ctx, inst)
        conditional = inst.args.get("conditional")
        if conditional == "JMPIF":
            cond = self._negate(cond)

        if self.blocks and isinstance(target_pc, int) and target_pc not in self._reachable_pcs:
            branch_ctx = ctx.clone()
            body, _ = self._lower_range(branch_ctx, idx + 1, target_idx)
            if body:
                out.append(lua_ast.If(test=cond, body=body, orelse=[]))
                ctx.registers.update(branch_ctx.registers)
                ctx.defined.update(branch_ctx.defined)
                self._branch_count += 1
            return target_idx

        branch_ctx = ctx.clone()
        body, _ = self._lower_range(branch_ctx, idx + 1, target_idx)

        jump_idx = target_idx - 1 if target_idx - 1 >= 0 else None
        if jump_idx is not None:
            jump_inst = self.instructions[jump_idx]
            if jump_inst.opcode == "Jump":
                jump_target_pc = jump_inst.args.get("target")
                jump_target_idx = (
                    self._pc_to_index.get(jump_target_pc)
                    if jump_target_pc is not None
                    else None
                )
                if jump_target_idx is not None:
                    if jump_target_idx <= idx:
                        loop_ctx = branch_ctx
                        out.append(lua_ast.While(test=cond, body=body))
                        ctx.registers.update(loop_ctx.registers)
                        ctx.defined.update(loop_ctx.defined)
                        self._loop_count += 1
                        return target_idx
                    if jump_target_idx > target_idx:
                        else_ctx = ctx.clone()
                        else_body, _ = self._lower_range(
                            else_ctx, target_idx, jump_target_idx
                        )
                        out.append(lua_ast.If(test=cond, body=body, orelse=else_body))
                        ctx.registers.update(branch_ctx.registers)
                        ctx.registers.update(else_ctx.registers)
                        ctx.defined.update(branch_ctx.defined)
                        ctx.defined.update(else_ctx.defined)
                        self._branch_count += 1
                        return jump_target_idx

        out.append(lua_ast.If(test=cond, body=body, orelse=[]))
        ctx.registers.update(branch_ctx.registers)
        ctx.defined.update(branch_ctx.defined)
        self._branch_count += 1
        return target_idx

    def _find_forloop(self, start: int, reg: int | None) -> Optional[int]:
        if reg is None:
            return None
        for idx in range(start + 1, len(self.instructions)):
            instr = self.instructions[idx]
            if instr.opcode == "ForLoop" and instr.args.get("reg") == reg:
                return idx
        return None

    def _handle_forprep(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        reg = inst.args.get("reg")
        loop_end = self._find_forloop(idx, reg)
        if loop_end is None:
            return idx + 1
        start_expr = self._expr_for_register(ctx, reg)
        stop_expr = self._expr_for_register(ctx, (reg or 0) + 1)
        step_expr = self._expr_for_register(ctx, (reg or 0) + 2)
        loop_ctx = ctx.clone()
        body, _ = self._lower_range(loop_ctx, idx + 1, loop_end)
        var_name = self._register_name((reg or 0) + 3)
        out.append(
            lua_ast.NumericFor(
                var=var_name,
                start=start_expr,
                stop=stop_expr,
                step=step_expr,
                body=body,
            )
        )
        self._loop_count += 1
        return loop_end + 1

    def _handle_forloop(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        return idx + 1

    def _handle_tforloop(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        # Luraph v14.4.1 introduces iterator loops that reach the VM as
        # ``TForLoop`` instructions.  We reconstruct them as generic ``for``
        # statements so the rendered Lua matches what the bootstrap would have
        # executed after decrypting the payload.
        inst = self.instructions[idx]
        base = inst.args.get("base")
        target_pc = inst.args.get("target")
        target_idx = self._pc_to_index.get(target_pc) if target_pc is not None else None
        if target_idx is None or target_idx <= idx:
            return idx + 1
        count = inst.args.get("nvars")
        var_count = count if isinstance(count, int) and count > 0 else 1
        loop_ctx = ctx.clone()
        body, _ = self._lower_range(loop_ctx, idx + 1, target_idx)
        var_names = [
            self._register_name((base or 0) + 3 + offset)
            for offset in range(var_count)
        ]
        iterables = [
            self._expr_for_register(ctx, base),
            self._expr_for_register(ctx, (base or 0) + 1),
            self._expr_for_register(ctx, (base or 0) + 2),
        ]
        out.append(
            lua_ast.GenericFor(
                vars=var_names,
                iterables=iterables,
                body=body,
            )
        )
        ctx.registers.update(loop_ctx.registers)
        ctx.defined.update(loop_ctx.defined)
        self._loop_count += 1
        return target_idx

    def _handle_vararg(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest")
        expr = lua_ast.Name("...")
        assign = self._assign_register(ctx, dest, expr)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_upval_get(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("reg")
        index = inst.args.get("index")
        expr = lua_ast.Name(f"uv{(index or 0) + 1}")
        assign = self._assign_register(ctx, dest, expr)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_upval_set(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        src = self._expr_for_register(ctx, inst.args.get("reg"))
        index = inst.args.get("index")
        target = lua_ast.Name(f"uv{(index or 0) + 1}")
        out.append(lua_ast.Assignment(targets=[target], values=[src], is_local=False))
        return idx + 1

    def _handle_global_get(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("reg") or inst.dest
        index = inst.args.get("index")
        value = self._fetch_constant(index)
        if isinstance(value, str):
            expr: lua_ast.Expr = lua_ast.Name(value)
        else:
            expr = self._literal(value)
        assign = self._assign_register(ctx, dest, expr)
        if assign:
            out.append(assign)
        return idx + 1

    def _handle_global_set(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        src = self._expr_for_register(ctx, inst.args.get("reg"))
        value = self._fetch_constant(inst.args.get("index"))
        if isinstance(value, str):
            target_expr: lua_ast.Expr = lua_ast.Name(value)
        else:
            target_expr = self._literal(value)
        out.append(lua_ast.Assignment(targets=[target_expr], values=[src], is_local=False))
        return idx + 1

    def _handle_closure(
        self,
        ctx: _LoweringContext,
        idx: int,
        end: int,
        out: List[lua_ast.Stmt],
    ) -> int:
        inst = self.instructions[idx]
        dest = inst.args.get("dest") if inst.args.get("dest") is not None else inst.dest
        proto = inst.args.get("proto")
        reg_index = dest if isinstance(dest, int) else None
        target_name = self._register_name(reg_index if reg_index is not None else 0)
        alias = self._closure_aliases.get(proto) if isinstance(proto, int) else None
        if alias is None:
            self._closure_count += 1
            if isinstance(proto, int):
                self._closure_aliases[proto] = target_name
            body = self._lower_prototype_body(proto if isinstance(proto, int) else None)
            func_def = lua_ast.FunctionDef(
                name=lua_ast.Name(target_name),
                params=[],
                body=body,
                is_local=True,
            )
            out.append(func_def)
            if reg_index is not None:
                ctx.registers[reg_index] = lua_ast.Name(target_name)
                ctx.defined.add(reg_index)
        else:
            expr = lua_ast.Name(alias)
            assign = self._assign_register(ctx, reg_index, expr)
            if assign:
                out.append(assign)
        return idx + 1


def run(ctx: "Context") -> Dict[str, Any]:  # type: ignore[name-defined]
    """Lower the IR module stored on ``ctx`` into Lua source."""

    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover - typing helper
        from ..pipeline import Context

    module = ctx.ir_module
    if module is None:
        return {"available": False}

    constants = module.constants
    version = ctx.detected_version
    handler: VersionHandler | None = ctx.version_handler
    if handler is None and version is not None and not version.is_unknown:
        try:
            candidate = get_handler(version.name)
        except KeyError:
            candidate = None
        if isinstance(candidate, VersionHandler):
            handler = candidate
            ctx.version_handler = handler

    if handler is not None:
        decoder = handler.const_decoder()
        if decoder is not None:
            constants = decode_constant_pool(decoder, constants)

    devirt = IRDevirtualizer(module, constants)
    chunk, metadata = devirt.lower()
    raw_source = lua_ast.to_source(chunk)
    if ctx.artifacts:
        ctx.write_artifact("vm_devirtualize_ast", raw_source)

    renamer = VariableRenamer()
    renamed = renamer.rename_variables(raw_source)
    formatter = utils.LuaFormatter()
    pretty = formatter.format_source(renamed)

    metadata["renamed_identifiers"] = renamed != raw_source
    metadata["formatted"] = pretty != renamed

    ctx.stage_output = pretty
    if ctx.artifacts:
        ctx.write_artifact("vm_devirtualize_pretty", pretty)
    return metadata | {"lines": len(pretty.splitlines())}


__all__ = ["run", "IRDevirtualizer"]

