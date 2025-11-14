"""Inline Lua emitter for lightweight inspection of lifted IR programs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Optional, Sequence

from .lifter import BasicBlock, IRProgram, IROp, IROperand

SBX_BIAS = 131071
RK_THRESHOLD = 256


def _ensure_program(payload: Mapping[str, Any]) -> IRProgram:
    """Reconstruct an :class:`IRProgram` from a dictionary payload."""

    program_data = payload.get("program", payload)
    blocks_payload = program_data.get("blocks", [])
    blocks: list[BasicBlock] = []

    for block_payload in blocks_payload:
        block_id = block_payload.get("id") or block_payload.get("block_id")
        if not block_id:
            raise ValueError("IR block is missing an identifier")

        block = BasicBlock(
            block_id=block_id,
            start_index=int(block_payload.get("start_index", 0)),
            end_index=int(block_payload.get("end_index", 0)),
        )
        raw_offsets = block_payload.get("raw_offsets")
        if isinstance(raw_offsets, Iterable):
            block.raw_offsets = [int(value) for value in raw_offsets]
        else:
            block.raw_offsets = list(range(block.start_index, block.end_index + 1))

        block.fallthrough = block_payload.get("fallthrough")
        block.jump = block_payload.get("jump")
        block.successors = list(block_payload.get("successors", []))
        block.predecessors = list(block_payload.get("predecessors", []))
        block.metadata.update(block_payload.get("metadata", {}))

        for op_payload in block_payload.get("ops", []):
            operands = [
                IROperand(
                    field=str(operand.get("field")),
                    value=operand.get("value"),
                    kind=str(operand.get("kind", "reg")),
                    resolved=operand.get("resolved"),
                )
                for operand in op_payload.get("operands", [])
            ]
            block.ops.append(
                IROp(
                    mnemonic=str(op_payload.get("mnemonic", "UNKNOWN")),
                    operands=operands,
                    index=int(op_payload.get("index", block.start_index)),
                    raw=op_payload.get("raw"),
                    metadata=dict(op_payload.get("metadata", {})),
                )
            )

        blocks.append(block)

    metadata = dict(program_data.get("metadata", {}))
    entry_block = program_data.get("entry_block")
    program = IRProgram(blocks=blocks, metadata=metadata, entry_block=entry_block)
    return program


def _lua_literal(value: Any) -> str:
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        escaped = (
            value.replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'
    return f'"{repr(value)}"'


def _format_comment(op: IROp, offset: Optional[int]) -> str:
    parts: list[str] = [f"idx={op.index}"]
    if offset is not None:
        parts.append(f"offset=0x{offset:04X}")
    if op.raw is not None:
        parts.append(f"raw=0x{op.raw:08X}")
    comment = op.metadata.get("comment")
    if comment:
        parts.append(str(comment))
    return f" -- [{' '.join(parts)}]"


def _register_index(operand: IROperand) -> Optional[int]:
    if operand.value is None:
        return None
    return int(operand.value) + 1


def _const_index(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    index = int(value)
    if index >= RK_THRESHOLD:
        index -= RK_THRESHOLD
    return index + 1


def _operand_expr(operand: IROperand) -> Optional[str]:
    kind = operand.kind.lower()
    value = operand.value

    if kind in {"reg", "count"}:
        reg = _register_index(operand)
        if reg is None:
            return None
        return f"regs[{reg}]"

    if kind == "const":
        if operand.resolved is not None:
            return _lua_literal(operand.resolved)
        index = _const_index(value)
        if index is None:
            return "nil"
        return f"consts[{index}]"

    if kind in {"boolean", "immediate", "skipflag"}:
        if operand.resolved is not None:
            return _lua_literal(operand.resolved)
        if value is None:
            return None
        if kind == "boolean":
            return "true" if int(value) else "false"
        return repr(int(value))

    if kind == "offset":
        if value is None:
            return None
        signed = int(value)
        if signed >= SBX_BIAS:
            signed -= SBX_BIAS
        return repr(signed)

    if operand.resolved is not None:
        return _lua_literal(operand.resolved)

    if value is not None:
        return repr(int(value))

    return None


_ARITHMETIC_OPS: Mapping[str, str] = {
    "ADD": "+",
    "SUB": "-",
    "MUL": "*",
    "DIV": "/",
    "MOD": "%",
    "POW": "^",
}


def _translate_operation(op: IROp, offset: Optional[int]) -> str:
    mnemonic = op.mnemonic.upper()
    operands = list(op.operands)

    if mnemonic == "MOVE" and len(operands) >= 2:
        target = _register_index(operands[0])
        source = _operand_expr(operands[1])
        if target is not None and source is not None:
            return f"regs[{target}] = {source}{_format_comment(op, offset)}"

    if mnemonic == "LOADK" and len(operands) >= 2:
        target = _register_index(operands[0])
        value_expr = _operand_expr(operands[1])
        if target is not None and value_expr is not None:
            return f"regs[{target}] = {value_expr}{_format_comment(op, offset)}"

    if mnemonic == "LOADBOOL" and len(operands) >= 2:
        target = _register_index(operands[0])
        bool_expr = _operand_expr(operands[1])
        if target is not None and bool_expr is not None:
            comment = _format_comment(op, offset)
            skip_flag = operands[2].value if len(operands) >= 3 else None
            if skip_flag:
                comment = comment[:-1] + f" skip={int(skip_flag)}]"
            return f"regs[{target}] = {bool_expr}{comment}"

    if mnemonic in _ARITHMETIC_OPS and len(operands) >= 3:
        target = _register_index(operands[0])
        left = _operand_expr(operands[1])
        right = _operand_expr(operands[2])
        if target is not None and left is not None and right is not None:
            op_symbol = _ARITHMETIC_OPS[mnemonic]
            return (
                f"regs[{target}] = ({left}) {op_symbol} ({right})"
                f"{_format_comment(op, offset)}"
            )

    comment = _format_comment(op, offset)
    details = ", ".join(
        f"{operand.field}={_operand_expr(operand) or 'nil'}" for operand in operands if operand.field
    )
    return f"-- {mnemonic} {details}{comment}"


def emit_inline(program: IRProgram, *, wrap: bool = False, indent: str = "    ") -> str:
    """Render pseudo-Lua for *program* with optional execution wrapper."""

    if not program.blocks:
        return "return function(state) return state end" if wrap else "-- empty program"

    lines: list[str] = []
    block_indent = ""
    instruction_indent = ""

    if wrap:
        lines.append("return function(state)")
        block_indent = indent
        instruction_indent = indent * 2
        lines.append(f"{block_indent}local regs = state.regs or {{}}")
        lines.append(f"{block_indent}local consts = state.consts or {{}}")
        lines.append(f"{block_indent}local pc = state.pc or 0")
    else:
        instruction_indent = indent

    for block_index, block in enumerate(program.blocks):
        if block_index and not wrap:
            lines.append("")
        lines.append(f"{block_indent}-- block {block.block_id} [{block.start_index}:{block.end_index}]")
        if wrap:
            lines.append(f"{block_indent}-- successors: {', '.join(block.successors) if block.successors else '[]'}")

        offset_map: MutableMapping[int, int] = {}
        if block.raw_offsets:
            for relative, raw in enumerate(block.raw_offsets):
                offset_map[block.start_index + relative] = int(raw)

        for op in block.ops:
            offset = offset_map.get(op.index)
            translated = _translate_operation(op, offset)
            lines.append(f"{instruction_indent}{translated}")

        if block_index + 1 < len(program.blocks):
            lines.append("")

    if wrap:
        lines.append(f"{block_indent}state.regs = regs")
        lines.append(f"{block_indent}state.consts = consts")
        lines.append(f"{block_indent}state.pc = pc")
        lines.append(f"{block_indent}return state")
        lines.append("end")

    return "\n".join(lines)


def emit_inline_from_dict(payload: Mapping[str, Any], *, wrap: bool = False, indent: str = "    ") -> str:
    program = _ensure_program(payload)
    return emit_inline(program, wrap=wrap, indent=indent)


def _load_json(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Render pseudo-Lua from lifted IR JSON")
    parser.add_argument("lift_result", type=Path, help="Path to lift result JSON")
    parser.add_argument("--output", type=Path, help="Optional path for the emitted Lua")
    parser.add_argument("--wrap", action="store_true", help="Wrap the snippet in an executable function")
    args = parser.parse_args(argv)

    payload = _load_json(args.lift_result)
    emitted = emit_inline_from_dict(payload, wrap=args.wrap)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(emitted + "\n", encoding="utf-8")
    else:
        print(emitted)

    return 0


__all__ = ["emit_inline", "emit_inline_from_dict"]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
