"""Inline constant propagation helpers for pseudo-Lua output.

The routines in this module operate on lifted VM IR and a decoded constant
pool.  They identify constants that are safe to inline – typically short
strings and small numeric literals – and materialise those values directly in
the IR operands.  This keeps generated pseudo-Lua compact while avoiding the
code bloat that results from inlining highly-shared constants.

Only lightweight heuristics are applied: callers can control the maximum usage
count a constant may have before it is left as a ``consts[?]`` reference, the
maximum string length that will be inlined, and the numeric magnitude deemed
"small".  The helpers never execute untrusted code and only operate on the IR
structures produced by the lifter.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..vm.inline_emitter import emit_inline
from ..vm.lifter import BasicBlock, IRProgram, IROp, IROperand
from .prettify import Provenance, format_pseudo_lua

LOGGER = logging.getLogger(__name__)

RK_THRESHOLD = 256

DEFAULT_MAX_USAGE = 3
DEFAULT_MAX_STRING_LENGTH = 256
DEFAULT_MAX_NUMERIC_ABS = 10_000
DEFAULT_OUTPUT = Path("out/deobfuscated_inlined.lua")


@dataclass
class InlineSummary:
    """Metrics describing what changed during constant inlining."""

    operands_considered: int = 0
    inlined: int = 0
    skipped_usage: int = 0
    skipped_type: int = 0
    missing_constant: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "operands_considered": self.operands_considered,
            "inlined": self.inlined,
            "skipped_usage": self.skipped_usage,
            "skipped_type": self.skipped_type,
            "missing_constant": self.missing_constant,
        }


def inline_constants(
    program: IRProgram,
    constants: Sequence[Any],
    *,
    max_usage: int = DEFAULT_MAX_USAGE,
    max_string_length: int = DEFAULT_MAX_STRING_LENGTH,
    max_numeric_abs: float = DEFAULT_MAX_NUMERIC_ABS,
) -> Tuple[IRProgram, InlineSummary]:
    """Return ``program`` with eligible constants inlined.

    The returned program is a deep copy – the original IR is never mutated.  A
    :class:`InlineSummary` detailing the decisions is returned alongside the
    new program.  Constants are inlined when:

    * They are strings whose length is below ``max_string_length``.
    * They are numeric and ``abs(value) <= max_numeric_abs``.
    * They are referenced ``max_usage`` times or fewer (unless ``max_usage`` is
      negative, in which case the usage check is skipped).

    Unsupported constant types or those exceeding the limits remain as
    ``consts[?]`` references so that downstream tooling can decide how to
    handle them.
    """

    usage_counts = _count_constant_usage(program)
    decisions: Dict[int, str] = {}

    for index, count in usage_counts.items():
        if index < 0:
            continue
        if index >= len(constants):
            decisions[index] = "missing"
            continue
        value = constants[index]
        if max_usage >= 0 and count > max_usage:
            decisions[index] = "usage"
            continue
        if _is_safe_constant(value, max_string_length=max_string_length, max_numeric_abs=max_numeric_abs):
            decisions[index] = "inline"
        else:
            decisions[index] = "type"

    summary = InlineSummary()
    new_blocks: List[BasicBlock] = []

    for block in program.blocks:
        updated_ops: List[IROp] = []
        for op in block.ops:
            new_operands: List[IROperand] = []
            for operand in op.operands:
                const_index = _operand_constant_index(operand)
                if const_index is None:
                    new_operands.append(operand)
                    continue

                decision = decisions.get(const_index)
                summary.operands_considered += 1

                if decision == "inline":
                    value = constants[const_index]
                    new_operands.append(replace(operand, resolved=value))
                    summary.inlined += 1
                elif decision == "usage":
                    new_operands.append(replace(operand, resolved=None))
                    summary.skipped_usage += 1
                elif decision == "type":
                    new_operands.append(replace(operand, resolved=None))
                    summary.skipped_type += 1
                else:
                    new_operands.append(replace(operand, resolved=None))
                    summary.missing_constant += 1

            updated_ops.append(replace(op, operands=tuple(new_operands)))

        new_block = replace(
            block,
            ops=updated_ops,
            raw_offsets=list(block.raw_offsets),
            successors=list(block.successors),
            predecessors=list(block.predecessors),
            metadata=dict(block.metadata),
        )
        new_blocks.append(new_block)

    new_program = IRProgram(
        blocks=new_blocks,
        metadata=dict(program.metadata),
        entry_block=program.entry_block,
    )
    return new_program, summary


def inline_constants_payload(
    payload: Mapping[str, Any],
    constants: Sequence[Any],
    **options: Any,
) -> Tuple[IRProgram, InlineSummary]:
    """Convenience wrapper accepting a mapping payload from the lifter."""

    program = _ensure_program(payload)
    return inline_constants(program, constants, **options)


def write_inlined_lua(
    program: IRProgram,
    *,
    output_path: Path = DEFAULT_OUTPUT,
    provenance: Optional[Provenance] = None,
    indent_width: int = 4,
    max_column: int = 120,
) -> Path:
    """Emit formatted pseudo-Lua for ``program`` and return the output path."""

    emitted = emit_inline(program)
    prov = provenance or Provenance(summary="inline constants")
    formatted = format_pseudo_lua(emitted, provenance=prov, indent_width=indent_width, max_column=max_column)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(formatted + "\n", encoding="utf-8")
    LOGGER.info("Wrote inlined pseudo-Lua to %s", output_path)
    return output_path


def _is_safe_constant(
    value: Any,
    *,
    max_string_length: int,
    max_numeric_abs: float,
) -> bool:
    if isinstance(value, str):
        return len(value) <= max_string_length
    if isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return abs(value) <= max_numeric_abs
    return False


def _count_constant_usage(program: IRProgram) -> Dict[int, int]:
    counts: Dict[int, int] = {}
    for block in program.blocks:
        for op in block.ops:
            for operand in op.operands:
                index = _operand_constant_index(operand)
                if index is None:
                    continue
                counts[index] = counts.get(index, 0) + 1
    return counts


def _operand_constant_index(operand: IROperand) -> Optional[int]:
    value = operand.value
    if value is None:
        return None
    kind = operand.kind.lower()
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    if kind == "const":
        if numeric >= RK_THRESHOLD:
            numeric -= RK_THRESHOLD
        return numeric if numeric >= 0 else None
    if kind == "reg" and numeric >= RK_THRESHOLD:
        return numeric - RK_THRESHOLD
    return None


def _ensure_program(payload: Mapping[str, Any]) -> IRProgram:
    program_data = payload.get("program", payload)
    blocks_payload = program_data.get("blocks", [])
    blocks: List[BasicBlock] = []

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
                    operands=tuple(operands),
                    index=int(op_payload.get("index", block.start_index)),
                    raw=op_payload.get("raw"),
                    metadata=dict(op_payload.get("metadata", {})),
                )
            )

        blocks.append(block)

    metadata = dict(program_data.get("metadata", {}))
    entry_block = program_data.get("entry_block")
    return IRProgram(blocks=blocks, metadata=metadata, entry_block=entry_block)


def _load_constants(path: Path) -> Sequence[Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, Mapping):
        payload = data.get("constants")
        if payload is None:
            raise ValueError("mapping constant files must contain a 'constants' key")
        data = payload
    if not isinstance(data, list):
        raise ValueError("constant pool must be a list")
    return data


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Inline constants into lifted IR and emit pseudo-Lua")
    parser.add_argument("ir", type=Path, help="Path to lifted IR JSON payload")
    parser.add_argument("constants", type=Path, help="Path to decoded constant pool (JSON list)")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Destination for the formatted pseudo-Lua (default: out/deobfuscated_inlined.lua)",
    )
    parser.add_argument("--max-usage", type=int, default=DEFAULT_MAX_USAGE, help="Maximum usages before constants stay indirect")
    parser.add_argument("--max-string-length", type=int, default=DEFAULT_MAX_STRING_LENGTH, help="Longest string literal to inline")
    parser.add_argument(
        "--max-numeric-abs",
        type=float,
        default=DEFAULT_MAX_NUMERIC_ABS,
        help="Inline numeric constants whose absolute value is within this bound",
    )
    parser.add_argument(
        "--indent-width",
        type=int,
        default=4,
        help="Indent width for formatted output",
    )
    parser.add_argument(
        "--max-column",
        type=int,
        default=120,
        help="Maximum column width when formatting output",
    )

    args = parser.parse_args(argv)

    with args.ir.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    constants = _load_constants(args.constants)
    program, summary = inline_constants_payload(
        payload,
        constants,
        max_usage=args.max_usage,
        max_string_length=args.max_string_length,
        max_numeric_abs=args.max_numeric_abs,
    )

    LOGGER.info("Inline summary: %s", summary.as_dict())

    write_inlined_lua(
        program,
        output_path=args.output,
        provenance=Provenance(summary="inline constants"),
        indent_width=args.indent_width,
        max_column=args.max_column,
    )
    return 0


__all__ = [
    "InlineSummary",
    "inline_constants",
    "inline_constants_payload",
    "write_inlined_lua",
    "main",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
