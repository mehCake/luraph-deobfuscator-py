"""Lift raw VM bytecode into a structured intermediate representation."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..versions import OpSpec, VersionHandler, get_handler
from ..utils_pkg.byteops import Endian, read_uint, sign_extend
from ..utils_pkg.ir import IRBasicBlock, IRInstruction, IRModule

LOG = logging.getLogger(__name__)

ConstPool = Sequence[Any]


@dataclass
class _DecodedInstruction:
    pc: int
    offset: int
    opcode: int
    spec: OpSpec | None
    operands: Dict[str, int]
    ir: IRInstruction


class VMLifter:
    """Parse VM bytecode using opcode tables supplied by version handlers."""

    def __init__(self, *, default_endianness: str = "little") -> None:
        self.default_endianness = default_endianness

    # ------------------------------------------------------------------
    def lift(
        self,
        bytecode: bytes,
        op_table: Mapping[int, OpSpec],
        consts: ConstPool,
        *,
        endianness: str | None = None,
        step_limit: int | None = None,
        time_limit: float | None = None,
    ) -> IRModule:
        end_str = (endianness or self.default_endianness or "little").lower()
        endian_value: Endian = "big" if end_str == "big" else "little"
        instructions: List[_DecodedInstruction] = []
        register_types: Dict[int, str] = {}
        current_types: Dict[int, str] = {}
        warnings: List[str] = []

        pc = 0
        offset = 0
        word_size = 4
        length = len(bytecode)
        parsed = 0
        cap = step_limit if step_limit and step_limit > 0 else None
        timeout = time_limit if time_limit and time_limit > 0 else None
        start_time = time.perf_counter()

        while offset < length:
            if cap is not None and parsed >= cap:
                warning = f"step limit {cap} reached during VM lift"
                warnings.append(warning)
                LOG.warning(warning)
                break
            if timeout is not None and (time.perf_counter() - start_time) >= timeout:
                warning = f"time limit {timeout:.3f}s reached during VM lift"
                warnings.append(warning)
                LOG.warning(warning)
                break
            start = offset
            remaining = length - start
            if remaining < 1:
                break

            opcode = bytecode[start]
            spec = op_table.get(opcode)

            operand_bytes = bytecode[start + 1 : start + word_size]
            actual_size = len(operand_bytes)
            offset = start + (word_size if remaining >= word_size else 1 + actual_size)

            if spec is None:
                operands: Dict[str, int] = {}
                ir = IRInstruction(
                    pc=pc,
                    opcode="Unknown",
                    args={"opcode": opcode, "raw": list(operand_bytes)},
                )
                warnings.append(f"unknown opcode 0x{opcode:02x} at pc {pc}")
                LOG.debug("unknown opcode 0x%02x at pc=%d", opcode, pc)
            else:
                operands = self._decode_operands(spec, operand_bytes, endian_value)
                ir = self._build_ir(
                    spec.mnemonic.upper(),
                    operands,
                    pc,
                    consts,
                    register_types,
                    current_types,
                )

            instructions.append(
                _DecodedInstruction(
                    pc=pc,
                    offset=start,
                    opcode=opcode,
                    spec=spec,
                    operands=operands,
                    ir=ir,
                )
            )
            pc += 1
            parsed += 1

        blocks, order = self._build_blocks(instructions)

        module = IRModule(
            blocks=blocks,
            order=order,
            entry=order[0] if order else "entry",
            register_types=dict(sorted(register_types.items())),
            constants=list(consts),
            instructions=[item.ir for item in instructions],
            warnings=warnings,
            bytecode_size=len(bytecode),
        )
        return module

    # ------------------------------------------------------------------
    def _decode_operands(
        self,
        spec: OpSpec,
        operand_bytes: bytes,
        endianness: Endian,
    ) -> Dict[str, int]:
        result: Dict[str, int] = {}
        cursor = 0
        total = len(operand_bytes)

        def read_byte() -> int:
            nonlocal cursor
            if cursor >= total:
                return 0
            value = operand_bytes[cursor]
            cursor += 1
            return value

        def read_remaining(width: int) -> int:
            nonlocal cursor
            width = max(width, 1)
            available = total - cursor
            if available <= 0:
                cursor = total
                return 0
            width = min(width, available)
            value = read_uint(operand_bytes, cursor, width, endian=endianness)
            cursor += width
            return value

        for name in spec.operands:
            key = name.lower()
            if key in {"a", "b", "c"}:
                result[name] = read_byte()
            elif key in {"ax", "bx", "cx"}:
                remaining = total - cursor
                result[name] = read_remaining(remaining or 3)
            elif key == "sbx":
                remaining = total - cursor
                width = remaining or 2
                raw = read_uint(operand_bytes, cursor, width, endian=endianness)
                cursor += width
                result[name] = sign_extend(raw, width * 8)
            elif key == "offset":
                remaining = total - cursor
                width = remaining or 2
                raw = read_uint(operand_bytes, cursor, width, endian=endianness)
                cursor += width
                result[name] = sign_extend(raw, width * 8)
            else:
                remaining = total - cursor
                result[name] = read_remaining(remaining or 1)

        return result

    # ------------------------------------------------------------------
    def _build_ir(
        self,
        mnemonic: str,
        operands: Mapping[str, int],
        pc: int,
        consts: ConstPool,
        register_types: Dict[int, str],
        current_types: Dict[int, str],
    ) -> IRInstruction:
        op = mnemonic.upper()

        if op == "LOADK":
            dest = operands.get("a")
            index = operands.get("b")
            value = consts[index] if isinstance(index, int) and 0 <= index < len(consts) else None
            self._set_register_type(dest, self._value_type(value), register_types, current_types)
            return IRInstruction(
                pc=pc,
                opcode="LoadK",
                args={"dest": dest, "const_index": index, "const_value": value},
                dest=dest,
            )

        if op in {"LOADN", "LOADB"}:
            dest = operands.get("a")
            imm = operands.get("b")
            value_type = "number" if op == "LOADN" else "boolean"
            if op == "LOADB" and imm is not None:
                value = bool(imm)
            else:
                value = imm
            self._set_register_type(dest, value_type, register_types, current_types)
            return IRInstruction(
                pc=pc,
                opcode="LoadK",
                args={"dest": dest, "const_value": value, "immediate": imm},
                dest=dest,
            )

        if op == "LOADBOOL":
            dest = operands.get("a")
            value = bool(operands.get("b", 0))
            self._set_register_type(dest, "boolean", register_types, current_types)
            return IRInstruction(
                pc=pc,
                opcode="LoadK",
                args={"dest": dest, "const_value": value, "immediate": operands.get("b")},
                dest=dest,
            )

        if op == "LOADNIL":
            start = operands.get("a", 0)
            end = operands.get("b", start)
            for reg in range(start, end + 1):
                self._set_register_type(reg, "nil", register_types, current_types)
            return IRInstruction(
                pc=pc,
                opcode="LoadNil",
                args={"start": start, "end": end},
            )

        if op == "MOVE":
            dest = operands.get("a")
            src = operands.get("b")
            source_type = (
                current_types.get(src, "unknown") if isinstance(src, int) else "unknown"
            )
            self._set_register_type(dest, source_type, register_types, current_types)
            self._note_register(src, register_types)
            sources = [src] if isinstance(src, int) else []
            return IRInstruction(
                pc=pc,
                opcode="Move",
                args={"dest": dest, "src": src},
                dest=dest,
                sources=sources,
            )

        if op == "NEWTABLE":
            dest = operands.get("a")
            self._set_register_type(dest, "table", register_types, current_types)
            return IRInstruction(pc=pc, opcode="NewTable", args={"dest": dest}, dest=dest)

        if op in {"GETTABLE", "SELF"}:
            dest = operands.get("a")
            table = operands.get("b")
            index = operands.get("c")
            self._note_register(table, register_types)
            self._note_register(index, register_types)
            self._set_register_type(dest, "unknown", register_types, current_types)
            args = {"dest": dest, "table": table, "index": index}
            if op == "SELF":
                args["method"] = True
            sources = [reg for reg in (table, index) if isinstance(reg, int)]
            return IRInstruction(
                pc=pc,
                opcode="GetTable",
                args=args,
                dest=dest,
                sources=sources,
            )

        if op == "SETTABLE":
            dest = operands.get("a")
            key = operands.get("b")
            value = operands.get("c")
            self._note_register(dest, register_types)
            self._note_register(key, register_types)
            self._note_register(value, register_types)
            sources = [reg for reg in (dest, key, value) if isinstance(reg, int)]
            return IRInstruction(
                pc=pc,
                opcode="SetTable",
                args={"table": dest, "key": key, "value": value},
                sources=sources,
            )

        if op in {"ADD", "SUB", "MUL", "DIV", "MOD", "POW", "BAND", "BOR", "BXOR", "SHL", "SHR"}:
            dest = operands.get("a")
            lhs = operands.get("b")
            rhs = operands.get("c")
            self._note_register(lhs, register_types)
            self._note_register(rhs, register_types)
            result_type = "number"
            if op in {"BAND", "BOR", "BXOR", "SHL", "SHR"}:
                result_type = "integer"
            self._set_register_type(dest, result_type, register_types, current_types)
            sources = [reg for reg in (lhs, rhs) if isinstance(reg, int)]
            return IRInstruction(
                pc=pc,
                opcode="BinOp",
                args={"op": op, "dest": dest, "lhs": lhs, "rhs": rhs},
                dest=dest,
                sources=sources,
            )

        if op in {"UNM", "BNOT", "NOT", "LEN"}:
            dest = operands.get("a")
            src = operands.get("b")
            self._note_register(src, register_types)
            result_type = "number" if op in {"UNM", "LEN"} else "boolean"
            self._set_register_type(dest, result_type, register_types, current_types)
            sources = [src] if isinstance(src, int) else []
            return IRInstruction(
                pc=pc,
                opcode="UnOp",
                args={"op": op, "dest": dest, "src": src},
                dest=dest,
                sources=sources,
            )

        if op in {"EQ", "LT", "LE"}:
            lhs = operands.get("b")
            rhs = operands.get("c")
            self._note_register(lhs, register_types)
            self._note_register(rhs, register_types)
            sources = [reg for reg in (lhs, rhs) if isinstance(reg, int)]
            return IRInstruction(
                pc=pc,
                opcode="Test",
                args={"op": op, "lhs": lhs, "rhs": rhs},
                sources=sources,
            )

        if op in {"TEST", "TESTSET"}:
            dest = operands.get("a")
            other = operands.get("b")
            cond = operands.get("c")
            self._note_register(dest, register_types)
            self._note_register(other, register_types)
            sources = [reg for reg in (dest, other) if isinstance(reg, int)]
            return IRInstruction(
                pc=pc,
                opcode="Test",
                args={"op": op, "dest": dest, "other": other, "cond": cond},
                sources=sources,
            )

        if op in {"JMP", "JMPIF", "JMPIFNOT"}:
            raw_offset = operands.get("offset")
            if isinstance(raw_offset, int):
                offset_value = raw_offset
            else:
                fallback = operands.get("a")
                offset_value = fallback if isinstance(fallback, int) else 0
            target = pc + 1 + offset_value
            opcode = "Jump" if op == "JMP" else "Test"
            branch_args: Dict[str, Any] = {"offset": offset_value, "target": target}
            if op != "JMP":
                branch_args["conditional"] = op
            return IRInstruction(pc=pc, opcode=opcode, args=branch_args)

        if op in {"FORPREP", "FORLOOP"}:
            loop_reg_value = operands.get("a")
            loop_reg = loop_reg_value if isinstance(loop_reg_value, int) else None
            raw_offset = operands.get("offset")
            offset_value = raw_offset if isinstance(raw_offset, int) else 0
            target = pc + 1 + offset_value
            self._note_register(loop_reg, register_types)
            opcode = "ForPrep" if op == "FORPREP" else "ForLoop"
            return IRInstruction(
                pc=pc,
                opcode=opcode,
                args={"reg": loop_reg, "target": target, "offset": offset_value},
            )

        if op == "TFORLOOP":
            base_value = operands.get("a")
            base = base_value if isinstance(base_value, int) else None
            raw_offset = operands.get("offset")
            offset_value = raw_offset if isinstance(raw_offset, int) else 0
            target = pc + 1 + offset_value
            count = operands.get("c")
            nvars = count if isinstance(count, int) else 0
            self._note_register(base, register_types)
            return IRInstruction(
                pc=pc,
                opcode="TForLoop",
                args={
                    "base": base,
                    "target": target,
                    "offset": offset_value,
                    "nvars": nvars,
                },
            )

        if op in {"CALL", "TAILCALL"}:
            base = operands.get("a")
            nargs = operands.get("b")
            nret = operands.get("c")
            self._note_register(base, register_types)
            opcode = "Call"
            args = {"base": base, "nargs": nargs, "nret": nret, "tail": op == "TAILCALL"}
            return IRInstruction(pc=pc, opcode=opcode, args=args)

        if op == "RETURN":
            base = operands.get("a")
            count = operands.get("b")
            self._note_register(base, register_types)
            return IRInstruction(pc=pc, opcode="Return", args={"base": base, "count": count})

        if op == "VARARG":
            dest = operands.get("a")
            count = operands.get("b")
            self._set_register_type(dest, "vararg", register_types, current_types)
            return IRInstruction(pc=pc, opcode="VarArg", args={"dest": dest, "count": count})

        if op in {"CLOSURE", "NEWCLOSURE"}:
            dest = operands.get("a")
            proto = operands.get("b")
            self._set_register_type(dest, "function", register_types, current_types)
            return IRInstruction(pc=pc, opcode="Closure", args={"dest": dest, "proto": proto}, dest=dest)

        if op in {"GETUPVAL", "SETUPVAL"}:
            dest = operands.get("a")
            index = operands.get("b")
            opcode = "UpvalGet" if op == "GETUPVAL" else "UpvalSet"
            if op == "GETUPVAL":
                self._set_register_type(dest, "unknown", register_types, current_types)
            else:
                self._note_register(dest, register_types)
            return IRInstruction(pc=pc, opcode=opcode, args={"reg": dest, "index": index})

        if op in {"GETGLOBAL", "SETGLOBAL"}:
            dest = operands.get("a")
            index = operands.get("b")
            opcode = "GlobalGet" if op == "GETGLOBAL" else "GlobalSet"
            if opcode == "GlobalGet":
                self._set_register_type(dest, "unknown", register_types, current_types)
            else:
                self._note_register(dest, register_types)
            return IRInstruction(pc=pc, opcode=opcode, args={"reg": dest, "index": index})

        if op == "SETLIST":
            dest = operands.get("a")
            count = operands.get("b")
            block = operands.get("c")
            self._note_register(dest, register_types)
            return IRInstruction(pc=pc, opcode="SetTable", args={"table": dest, "count": count, "block": block})

        if op == "CLOSE":
            close_reg_value = operands.get("a")
            close_reg = close_reg_value if isinstance(close_reg_value, int) else None
            self._note_register(close_reg, register_types)
            return IRInstruction(pc=pc, opcode="Close", args={"reg": close_reg})

        if op == "PUSHK":
            index = operands.get("a")
            value = consts[index] if isinstance(index, int) and 0 <= index < len(consts) else None
            return IRInstruction(
                pc=pc,
                opcode="LoadK",
                args={"const_index": index, "const_value": value},
            )

        return IRInstruction(
            pc=pc,
            opcode="Unknown",
            args={"mnemonic": mnemonic, "operands": dict(operands)},
        )

    # ------------------------------------------------------------------
    def _build_blocks(
        self, instructions: Sequence[_DecodedInstruction]
    ) -> Tuple[Dict[str, IRBasicBlock], List[str]]:
        if not instructions:
            empty = IRBasicBlock("entry", 0, [], [])
            return {"entry": empty}, ["entry"]

        leaders = {0}
        for idx, decoded in enumerate(instructions):
            ir = decoded.ir
            next_idx = idx + 1
            if ir.opcode in {"Jump"}:
                target = ir.args.get("target")
                if isinstance(target, int) and 0 <= target < len(instructions):
                    leaders.add(target)
                if next_idx < len(instructions):
                    leaders.add(next_idx)
            elif ir.opcode in {"Test", "ForPrep", "ForLoop"}:
                target = ir.args.get("target")
                if isinstance(target, int) and 0 <= target < len(instructions):
                    leaders.add(target)
                if next_idx < len(instructions):
                    leaders.add(next_idx)
            elif ir.opcode == "Return":
                continue
            else:
                if next_idx < len(instructions):
                    leaders.add(next_idx)

        ordered = sorted(leaders)
        blocks: Dict[str, IRBasicBlock] = {}
        label_map: Dict[int, str] = {index: f"block_{i}" for i, index in enumerate(ordered)}

        for i, start in enumerate(ordered):
            end = ordered[i + 1] if i + 1 < len(ordered) else len(instructions)
            label = label_map[start]
            block_insts = [inst.ir for inst in instructions[start:end]]
            block = IRBasicBlock(label=label, start_pc=start, instructions=block_insts)
            if block_insts:
                succ_indices = self._successors(start, block_insts[-1], len(instructions))
                block.successors = [label_map[idx] for idx in succ_indices if idx in label_map]
            blocks[label] = block

        order = [label_map[idx] for idx in ordered]
        return blocks, order

    # ------------------------------------------------------------------
    def _successors(
        self, start: int, inst: IRInstruction, instruction_count: int
    ) -> List[int]:
        if inst.opcode == "Jump":
            target = inst.args.get("target")
            return [target] if isinstance(target, int) else []
        if inst.opcode in {"Test", "ForPrep"}:
            target = inst.args.get("target")
            succs: List[int] = []
            if isinstance(target, int):
                succs.append(target)
            if start + 1 < instruction_count:
                succs.append(start + 1)
            return succs
        if inst.opcode == "ForLoop":
            target = inst.args.get("target")
            if isinstance(target, int):
                return [target, start + 1] if start + 1 < instruction_count else [target]
            if start + 1 < instruction_count:
                return [start + 1]
            return []
        if inst.opcode == "Return":
            return []
        if start + 1 < instruction_count:
            return [start + 1]
        return []

    # ------------------------------------------------------------------
    def _set_register_type(
        self,
        index: Optional[int],
        value_type: str | None,
        register_types: Dict[int, str],
        current_types: Dict[int, str],
    ) -> None:
        if index is None:
            return
        if value_type is None:
            register_types.setdefault(index, "unknown")
            current_types.pop(index, None)
            return
        existing = register_types.get(index)
        if existing is None or existing == "unknown":
            register_types[index] = value_type
        elif existing != value_type:
            register_types[index] = "mixed"
        current_types[index] = value_type

    def _note_register(self, index: Optional[int], register_types: Dict[int, str]) -> None:
        if index is None:
            return
        register_types.setdefault(index, "unknown")

    def _value_type(self, value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if value is None:
            return "nil"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, (list, dict)):
            return "table"
        return value.__class__.__name__ if value is not None else "unknown"


def run(ctx: "Context") -> Dict[str, Any]:  # type: ignore[name-defined]
    """Lift the VM payload stored on ``ctx`` into an IR module."""

    from typing import TYPE_CHECKING

    if TYPE_CHECKING:  # pragma: no cover - typing helper
        from ..pipeline import Context

    ctx.ensure_raw_input()

    if ctx.vm.bytecode is None or not ctx.vm.bytecode:
        ctx.ir_module = None
        return {"available": False}

    version = ctx.detected_version
    handler: VersionHandler | None = None
    if version is not None and not version.is_unknown:
        try:
            candidate = get_handler(version.name)
        except KeyError:
            candidate = None
        if isinstance(candidate, VersionHandler):
            handler = candidate

    op_table = handler.opcode_table() if handler else {}
    endianness = ctx.vm.meta.get("endianness") if ctx.vm.meta else None

    lifter = VMLifter()
    options = ctx.options if isinstance(ctx.options, dict) else {}
    raw_step_limit = options.get("vm_lift_step_limit")
    raw_time_limit = options.get("vm_lift_time_limit")
    step_limit: Optional[int] = None
    time_limit: Optional[float] = None
    if isinstance(raw_step_limit, int):
        step_limit = raw_step_limit if raw_step_limit > 0 else None
    elif isinstance(raw_step_limit, str) and raw_step_limit.isdigit():
        value = int(raw_step_limit)
        step_limit = value if value > 0 else None
    if isinstance(raw_time_limit, (int, float)):
        time_limit = float(raw_time_limit) if raw_time_limit > 0 else None
    elif isinstance(raw_time_limit, str):
        try:
            parsed_time = float(raw_time_limit)
        except ValueError:
            parsed_time = 0.0
        time_limit = parsed_time if parsed_time > 0 else None
    module = lifter.lift(
        ctx.vm.bytecode,
        op_table,
        ctx.vm.const_pool or [],
        endianness=endianness,
        step_limit=step_limit,
        time_limit=time_limit,
    )

    ctx.ir_module = module

    metadata: Dict[str, Any] = {
        "instructions": module.instruction_count,
        "blocks": module.block_count,
        "registers": len(module.register_types),
        "bytecode_size": module.bytecode_size,
    }
    if step_limit is not None:
        metadata["step_limit"] = step_limit
    if time_limit is not None:
        metadata["time_limit"] = time_limit
    unknown_count = sum(1 for inst in module.instructions if inst.opcode == "Unknown")
    if unknown_count:
        metadata["unknown_opcodes"] = unknown_count
    if module.warnings:
        metadata["warnings"] = list(module.warnings)
        if any("step limit" in warning for warning in module.warnings):
            metadata["step_limit_hit"] = True
        if any("time limit" in warning for warning in module.warnings):
            metadata["time_limit_hit"] = True

    if ctx.artifacts and module.instructions:
        serialised = {
            "entry": module.entry,
            "order": module.order,
            "register_types": module.register_types,
            "blocks": [
                {
                    "label": block.label,
                    "start_pc": block.start_pc,
                    "successors": block.successors,
                    "instructions": [
                        {"pc": inst.pc, "opcode": inst.opcode, "args": inst.args}
                        for inst in block.instructions
                    ],
                }
                for block in module.blocks.values()
            ],
            "warnings": module.warnings,
        }
        ctx.write_artifact("vm_lift_ir", json.dumps(serialised, indent=2), extension=".json")

    return metadata


__all__ = ["VMLifter", "run"]
