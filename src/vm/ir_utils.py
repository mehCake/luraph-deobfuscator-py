"""Utilities for analysing and presenting lifted VM IR programs."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Dict, List, Mapping, Sequence

from .lifter import BasicBlock, IRProgram

LOGGER = logging.getLogger(__name__)


def pretty_print_ir(program: IRProgram, *, include_metadata: bool = False) -> str:
    """Return a human readable representation of an ``IRProgram``.

    The printer mirrors the ordering of ``program.blocks`` and produces a
    textual listing that is convenient for quick inspection or logging.  The
    output intentionally avoids colour codes so that it can be safely written to
    log files or Markdown reports.
    """

    meta_items = sorted(program.metadata.items()) if program.metadata else []
    metadata_repr = ", ".join(f"{key}={value}" for key, value in meta_items)
    header = [
        f"; IR entry={program.entry_block or 'unknown'} blocks={len(program.blocks)}",
    ]
    if metadata_repr:
        header[0] += f" [{metadata_repr}]"

    lines: List[str] = header

    for block in program.blocks:
        lines.append(f"{block.block_id}:")
        if include_metadata and block.metadata:
            meta_summary = ", ".join(
                f"{key}={value}" for key, value in sorted(block.metadata.items())
            )
            lines.append(f"  ; metadata: {meta_summary}")

        successors = _unique_successors(block)
        if successors:
            lines.append(f"  ; successors: {', '.join(successors)}")

        for op in block.ops:
            operand_text = []
            for operand in op.operands:
                piece = f"{operand.kind}:{operand.field}"
                if operand.value is not None:
                    piece += f"={operand.value}"
                if operand.resolved is not None:
                    piece += f" ({operand.resolved!r})"
                operand_text.append(piece)
            operand_repr = ", ".join(operand_text)
            lines.append(f"  {op.mnemonic:<10} {operand_repr}")

    return "\n".join(lines)


def compute_cfg(program: IRProgram) -> Mapping[str, Mapping[str, Sequence[str]]]:
    """Return dictionaries describing the control-flow graph of ``program``.

    The result is a mapping with two keys: ``successors`` and ``predecessors``.
    Each key maps block identifiers to a list of adjacent block IDs.  Successor
    lists respect the explicit ``fallthrough`` and ``jump`` properties in
    addition to the ``successors`` field stored on ``BasicBlock`` instances.
    """

    successors: Dict[str, List[str]] = {}
    predecessors: Dict[str, List[str]] = {}

    for block in program.blocks:
        block_successors = _unique_successors(block)
        successors[block.block_id] = block_successors
        for succ in block_successors:
            predecessors.setdefault(succ, []).append(block.block_id)

    for block_id in successors:
        predecessors.setdefault(block_id, [])

    for mapping in (successors, predecessors):
        for block_id, items in mapping.items():
            deduped = list(dict.fromkeys(items))
            mapping[block_id] = deduped

    return {"successors": successors, "predecessors": predecessors}


def collapse_trivial_blocks(
    program: IRProgram,
    *,
    preserve_metadata: bool = True,
) -> IRProgram:
    """Simplify ``program`` by removing empty bridge blocks.

    A block qualifies as trivial when it contains no operations, is not the
    entry block, and forwards control unconditionally to a single successor.
    Blocks with metadata are preserved by default; callers can set
    ``preserve_metadata`` to ``False`` to override this guard.
    """

    blocks: Dict[str, BasicBlock] = {
        block.block_id: _clone_block(block) for block in program.blocks
    }
    order: List[str] = [block.block_id for block in program.blocks]

    changed = True
    while changed:
        changed = False
        temp_program = IRProgram(
            blocks=[blocks[block_id] for block_id in order if block_id in blocks],
            metadata=dict(program.metadata),
            entry_block=program.entry_block,
        )
        cfg = compute_cfg(temp_program)

        for block_id in list(order):
            block = blocks.get(block_id)
            if block is None:
                continue
            if block_id == program.entry_block:
                continue
            if block.ops:
                continue
            if preserve_metadata and block.metadata:
                continue

            succs = cfg["successors"].get(block_id, [])
            preds = cfg["predecessors"].get(block_id, [])
            if len(succs) != 1:
                continue
            successor = succs[0]

            for pred_id in preds:
                pred = blocks.get(pred_id)
                if pred is None:
                    continue
                if pred.fallthrough == block_id:
                    pred.fallthrough = successor
                if pred.jump == block_id:
                    pred.jump = successor
                pred.successors = [
                    successor if candidate == block_id else candidate
                    for candidate in pred.successors
                ]
                pred.successors = list(dict.fromkeys(pred.successors))

            order.remove(block_id)
            del blocks[block_id]
            changed = True
            LOGGER.debug("Collapsed trivial block %s -> %s", block_id, successor)
            break

    final_program = IRProgram(
        blocks=[blocks[block_id] for block_id in order if block_id in blocks],
        metadata=dict(program.metadata),
        entry_block=program.entry_block,
    )

    cfg = compute_cfg(final_program)
    for block in final_program.blocks:
        block.successors = list(cfg["successors"].get(block.block_id, []))
        block.predecessors = list(cfg["predecessors"].get(block.block_id, []))

    return final_program


def _clone_block(block: BasicBlock) -> BasicBlock:
    """Return a shallow copy of ``block`` suitable for mutation."""

    cloned = replace(
        block,
        ops=list(block.ops),
        raw_offsets=list(block.raw_offsets),
        successors=list(block.successors),
        predecessors=list(block.predecessors),
        metadata=dict(block.metadata),
    )
    return cloned


def _unique_successors(block: BasicBlock) -> List[str]:
    """Return successor IDs derived from ``block`` without duplicates."""

    candidates: List[str] = []
    candidates.extend(block.successors)
    if block.fallthrough:
        candidates.append(block.fallthrough)
    if block.jump:
        candidates.append(block.jump)

    return [candidate for candidate in dict.fromkeys(candidates) if candidate]

