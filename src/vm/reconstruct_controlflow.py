"""Structured control-flow reconstruction from lifted IR basic blocks.

This module converts the block graph emitted by :mod:`src.vm.lifter` into a
hierarchical structure that mirrors high level control constructs.  It performs
lightweight dominator analysis to detect loops and branch joins, producing a
best-effort representation that downstream tooling can serialise or further
optimise.

The reconstructor also applies defensive heuristics to isolate trap / anti-
analysis handlers.  Blocks whose metadata or operands mention known trap
keywords are excluded from the normal control-flow tree and reported
separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from .lifter import BasicBlock, IRProgram

__all__ = [
    "BlockNode",
    "ControlFlowReconstructor",
    "IfNode",
    "emit_structured_lua",
    "reconstruct_control_flow",
    "SequenceNode",
    "StructuredProgram",
    "TrapNode",
    "WhileNode",
    "write_structured_artifacts",
]


_TRAP_KEYWORDS = (
    "trap",
    "sandbox",
    "debug",
    "tamper",
    "deob",
    "decompile",
    "unauthor",
    "anti",
    "halt",
    "panic",
)


def _normalise_text(value: object) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", "ignore").lower()
        except Exception:  # pragma: no cover - extremely defensive
            return ""
    if isinstance(value, str):
        return value.lower()
    return ""


def _trap_reason(block: BasicBlock) -> Optional[str]:
    def _match(text: str) -> Optional[str]:
        if not text:
            return None
        lowered = text.lower()
        if "assert(false" in lowered:
            return "assert_false"
        if "error(" in lowered:
            return "error_call"
        for keyword in _TRAP_KEYWORDS:
            if keyword in lowered:
                return keyword
        return None

    for value in block.metadata.values():
        reason = _match(_normalise_text(value))
        if reason:
            return f"metadata:{reason}"

    for op in block.ops:
        reason = _match(op.mnemonic.lower())
        if reason:
            return f"mnemonic:{reason}"
        comment = op.metadata.get("comment") if isinstance(op.metadata, Mapping) else None
        if comment:
            reason = _match(_normalise_text(comment))
            if reason:
                return f"comment:{reason}"
        for operand in op.operands:
            resolved = getattr(operand, "resolved", None)
            reason = _match(_normalise_text(resolved))
            if reason:
                return f"operand:{reason}"

    if not block.successors and not block.fallthrough and not block.jump:
        for op in block.ops:
            if op.mnemonic.upper() in {"CALL", "TAILCALL"}:
                for operand in op.operands:
                    resolved = getattr(operand, "resolved", None)
                    if isinstance(resolved, str):
                        lowered = resolved.lower()
                        if lowered in {"error", "assert", "trap"}:
                            return f"call:{lowered}"
    return None


@dataclass
class BlockNode:
    """Leaf node referencing a single basic block."""

    block: BasicBlock

    def as_dict(self) -> MutableMapping[str, object]:
        return {
            "type": "block",
            "id": self.block.block_id,
            "start": self.block.start_index,
            "end": self.block.end_index,
            "successors": list(self.block.successors),
            "metadata": dict(self.block.metadata),
        }


@dataclass
class SequenceNode:
    """Ordered collection of child nodes executed sequentially."""

    nodes: List[StructuredNode] = field(default_factory=list)

    def as_dict(self) -> MutableMapping[str, object]:
        return {"type": "sequence", "nodes": [node.as_dict() for node in self.nodes]}

    @property
    def is_empty(self) -> bool:
        return not self.nodes


@dataclass
class IfNode:
    """Conditional construct with optional else branch."""

    condition: BlockNode
    then_branch: SequenceNode
    else_branch: Optional[SequenceNode]
    join: Optional[str]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "type": "if",
            "condition": self.condition.as_dict(),
            "then": self.then_branch.as_dict(),
            "join": self.join,
        }
        if self.else_branch is not None:
            payload["else"] = self.else_branch.as_dict()
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass
class WhileNode:
    """Loop construct derived from a natural loop in the CFG."""

    header: BlockNode
    body: SequenceNode
    exit: Optional[str]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "type": "while",
            "header": self.header.as_dict(),
            "body": self.body.as_dict(),
            "exit": self.exit,
        }
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload


@dataclass
class TrapNode:
    """Summary of a trap / anti-analysis handler that was isolated."""

    block: BasicBlock
    reason: str

    def as_dict(self) -> MutableMapping[str, object]:
        return {
            "type": "trap",
            "id": self.block.block_id,
            "reason": self.reason,
            "metadata": dict(self.block.metadata),
        }


StructuredNode = BlockNode | IfNode | WhileNode | SequenceNode


@dataclass
class StructuredProgram:
    """Result of the reconstruction process."""

    entry: Optional[str]
    body: SequenceNode
    traps: Tuple[TrapNode, ...]
    metadata: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> MutableMapping[str, object]:
        payload: MutableMapping[str, object] = {
            "type": "program",
            "entry": self.entry,
            "body": self.body.as_dict(),
            "traps": [trap.as_dict() for trap in self.traps],
        }
        if self.metadata:
            payload["metadata"] = dict(self.metadata)
        return payload

    def to_ast(self) -> MutableMapping[str, object]:
        """Return a JSON-serialisable AST-like structure."""

        def _node_ast(node: StructuredNode) -> MutableMapping[str, object]:
            data = node.as_dict()
            data.setdefault("metadata", {})
            metadata = data["metadata"]

            if isinstance(node, IfNode):
                uncertain: List[str] = []
                if node.join is None:
                    uncertain.append("missing_join")
                if node.then_branch.is_empty:
                    uncertain.append("empty_then")
                if node.else_branch is None or node.else_branch.is_empty:
                    uncertain.append("missing_else")
                if uncertain:
                    metadata["uncertain"] = uncertain
            elif isinstance(node, WhileNode):
                if node.exit is None:
                    metadata.setdefault("uncertain", []).append("missing_exit")
                if node.body.is_empty:
                    metadata.setdefault("uncertain", []).append("empty_body")

            for key, value in list(metadata.items()):
                if isinstance(value, set):
                    metadata[key] = sorted(value)

            if isinstance(node, SequenceNode):
                data["nodes"] = [_node_ast(child) for child in node.nodes]
            elif isinstance(node, IfNode):
                data["condition"] = _node_ast(node.condition)
                data["then"] = _node_ast(node.then_branch)
                if node.else_branch is not None:
                    data["else"] = _node_ast(node.else_branch)
            elif isinstance(node, WhileNode):
                data["header"] = _node_ast(node.header)
                data["body"] = _node_ast(node.body)
            return data

        ast = self.as_dict()
        ast["body"] = _node_ast(self.body)
        ast["traps"] = [trap.as_dict() for trap in self.traps]
        return ast


class ControlFlowReconstructor:
    """Analyse an :class:`IRProgram` and reconstruct structured control flow."""

    def __init__(self, program: IRProgram) -> None:
        self.program = program
        self.block_map: Dict[str, BasicBlock] = {block.block_id: block for block in program.blocks}
        self.order: Dict[str, int] = {block.block_id: index for index, block in enumerate(program.blocks)}
        self.trap_blocks: Set[str] = set()
        self.trap_reasons: Dict[str, str] = {}
        self.traps: List[TrapNode] = []
        self._detect_traps()
        self.successors: Dict[str, Tuple[str, ...]] = {}
        self.predecessors: Dict[str, Tuple[str, ...]] = {}
        self._build_graph()
        self.dominators: Dict[str, Set[str]] = {}
        self.postdominators: Dict[str, Set[str]] = {}
        self.immediate_postdom: Dict[str, Optional[str]] = {}
        self.loop_nodes: Dict[str, Set[str]] = {}
        self._analyse_graph()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reconstruct(self) -> StructuredProgram:
        entry = self._select_entry()
        visited: Set[str] = set()
        nodes: List[StructuredNode] = []
        if entry:
            sequence, consumed = self._build_sequence(entry, stop=None, visited=visited, allowed=None)
            nodes.extend(sequence.nodes)
            visited.update(consumed)
        for block_id in self.block_map:
            if block_id in self.trap_blocks or block_id in visited:
                continue
            sequence, consumed = self._build_sequence(block_id, stop=None, visited=visited, allowed=None)
            if sequence.nodes:
                nodes.extend(sequence.nodes)
            visited.update(consumed)

        metadata: Dict[str, object] = {
            "blocks": len(self.block_map),
            "traps": len(self.traps),
        }
        return StructuredProgram(entry=entry, body=SequenceNode(nodes), traps=tuple(self.traps), metadata=metadata)

    # ------------------------------------------------------------------
    # Graph analysis helpers
    # ------------------------------------------------------------------

    def _detect_traps(self) -> None:
        for block in self.program.blocks:
            reason = _trap_reason(block)
            if reason:
                self.trap_blocks.add(block.block_id)
                self.trap_reasons[block.block_id] = reason
                self.traps.append(TrapNode(block=block, reason=reason))

    def _build_graph(self) -> None:
        successors: Dict[str, List[str]] = {}
        predecessors: Dict[str, List[str]] = {block_id: [] for block_id in self.block_map}

        for block in self.program.blocks:
            if block.block_id in self.trap_blocks:
                continue
            succs: List[str] = []
            for candidate in block.successors:
                if candidate in self.block_map and candidate not in self.trap_blocks:
                    succs.append(candidate)
            self.successors[block.block_id] = tuple(dict.fromkeys(succs))
            for succ in self.successors[block.block_id]:
                predecessors.setdefault(succ, []).append(block.block_id)

        for block_id in list(predecessors):
            preds = [pred for pred in predecessors.get(block_id, []) if pred not in self.trap_blocks]
            self.predecessors[block_id] = tuple(dict.fromkeys(preds))

    def _analyse_graph(self) -> None:
        nodes = [block_id for block_id in self.block_map if block_id not in self.trap_blocks]
        if not nodes:
            return

        entry = self._select_entry()
        if entry:
            self.dominators = self._compute_dominators(entry, nodes)
        else:
            self.dominators = {node: {node} for node in nodes}

        exit_nodes = [node for node in nodes if not self.successors.get(node)]
        self.postdominators = self._compute_postdominators(nodes, exit_nodes)
        self.immediate_postdom = self._compute_immediate_postdom()
        self.loop_nodes = self._detect_loops()

    def _compute_dominators(self, entry: str, nodes: Sequence[str]) -> Dict[str, Set[str]]:
        dom: Dict[str, Set[str]] = {node: set(nodes) for node in nodes}
        dom[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for node in nodes:
                if node == entry:
                    continue
                preds = self.predecessors.get(node, ())
                if not preds:
                    new_dom = {node}
                else:
                    intersection = set(nodes)
                    for pred in preds:
                        intersection &= dom.get(pred, set(nodes))
                    new_dom = {node} | intersection
                if new_dom != dom[node]:
                    dom[node] = new_dom
                    changed = True
        return dom

    def _compute_postdominators(
        self, nodes: Sequence[str], exit_nodes: Sequence[str]
    ) -> Dict[str, Set[str]]:
        postdom: Dict[str, Set[str]] = {node: set(nodes) for node in nodes}
        for exit_node in exit_nodes:
            postdom[exit_node] = {exit_node}

        changed = True
        while changed:
            changed = False
            for node in nodes:
                succs = self.successors.get(node, ())
                if not succs:
                    continue
                intersection = set(nodes)
                for succ in succs:
                    intersection &= postdom.get(succ, set(nodes))
                new_postdom = {node} | intersection
                if new_postdom != postdom[node]:
                    postdom[node] = new_postdom
                    changed = True
        return postdom

    def _compute_immediate_postdom(self) -> Dict[str, Optional[str]]:
        immediate: Dict[str, Optional[str]] = {}
        for node, doms in self.postdominators.items():
            candidates = doms - {node}
            chosen: Optional[str] = None
            for candidate in sorted(candidates, key=lambda item: self.order.get(item, 0)):
                if all(
                    candidate == other or candidate not in self.postdominators.get(other, set())
                    for other in candidates
                ):
                    chosen = candidate
                    break
            immediate[node] = chosen
        return immediate

    def _detect_loops(self) -> Dict[str, Set[str]]:
        loops: Dict[str, Set[str]] = {}
        for node, succs in self.successors.items():
            for succ in succs:
                if succ == node:
                    loops.setdefault(succ, set()).add(node)
                    continue
                dom_set = self.dominators.get(node)
                if dom_set and succ in dom_set:
                    header = succ
                    body = self._natural_loop(header, node)
                    existing = loops.setdefault(header, set())
                    existing.update(body)
        return loops

    def _natural_loop(self, header: str, node: str) -> Set[str]:
        loop_nodes = {header}
        stack = [node]
        while stack:
            current = stack.pop()
            if current in loop_nodes:
                continue
            loop_nodes.add(current)
            for pred in self.predecessors.get(current, ()):  # pragma: no branch - small sets
                stack.append(pred)
        return loop_nodes

    # ------------------------------------------------------------------
    # Reconstruction helpers
    # ------------------------------------------------------------------

    def _select_entry(self) -> Optional[str]:
        entry = self.program.entry_block
        if entry and entry not in self.trap_blocks:
            return entry
        for block in self.program.blocks:
            if block.block_id not in self.trap_blocks:
                return block.block_id
        return None

    def _build_sequence(
        self,
        start: Optional[str],
        *,
        stop: Optional[str],
        visited: Set[str],
        allowed: Optional[Set[str]],
    ) -> Tuple[SequenceNode, Set[str]]:
        nodes: List[StructuredNode] = []
        consumed: Set[str] = set()
        current = start
        while current and current != stop:
            if allowed is not None and current not in allowed:
                break
            if current in visited or current in consumed:
                break
            if current in self.trap_blocks:
                consumed.add(current)
                visited.add(current)
                current = self._next_after_trap(current, allowed, stop)
                continue

            node, next_block, used = self._build_node(current, visited, allowed, stop)
            nodes.append(node)
            consumed.update(used)
            visited.update(used)
            if next_block is None or next_block == current:
                break
            current = next_block
        return SequenceNode(nodes), consumed

    def _build_node(
        self,
        block_id: str,
        visited: Set[str],
        allowed: Optional[Set[str]],
        stop: Optional[str],
    ) -> Tuple[StructuredNode, Optional[str], Set[str]]:
        if block_id in self.loop_nodes:
            node, exit_id, consumed = self._build_loop_node(block_id, visited, allowed, stop)
            return node, exit_id, consumed

        block = self.block_map[block_id]
        control = block.metadata.get("control") if isinstance(block.metadata, Mapping) else {}
        if isinstance(control, Mapping) and control.get("type") == "cond":
            return self._build_if_node(block_id, visited, allowed, stop)

        next_block = self._default_successor(block_id, visited, allowed, stop)
        return BlockNode(block), next_block, {block_id}

    def _build_loop_node(
        self,
        header_id: str,
        visited: Set[str],
        allowed: Optional[Set[str]],
        stop: Optional[str],
    ) -> Tuple[WhileNode, Optional[str], Set[str]]:
        loop_nodes = set(self.loop_nodes.get(header_id, {header_id}))
        header_block = self.block_map[header_id]
        body_nodes = loop_nodes - {header_id}
        body_start: Optional[str] = None
        for succ in self.successors.get(header_id, ()):  # pragma: no branch - tiny list
            if succ in body_nodes:
                body_start = succ
                break
        body_sequence, consumed = self._build_sequence(
            body_start,
            stop=header_id,
            visited=visited,
            allowed=body_nodes if body_nodes else None,
        )
        consumed |= {header_id}
        exit_id = self.immediate_postdom.get(header_id)
        metadata: Dict[str, object] = {"loop_size": len(loop_nodes)}
        return WhileNode(header=BlockNode(header_block), body=body_sequence, exit=exit_id, metadata=metadata), exit_id, consumed

    def _build_if_node(
        self,
        block_id: str,
        visited: Set[str],
        allowed: Optional[Set[str]],
        stop: Optional[str],
    ) -> Tuple[IfNode, Optional[str], Set[str]]:
        block = self.block_map[block_id]
        join = self.immediate_postdom.get(block_id)
        true_succ = block.fallthrough or next(iter(self.successors.get(block_id, ())), None)
        false_succ = block.jump
        then_branch, then_consumed = self._build_sequence(
            true_succ,
            stop=join,
            visited=visited,
            allowed=allowed,
        )
        else_branch: Optional[SequenceNode] = None
        consumed = {block_id} | then_consumed
        if false_succ and false_succ != true_succ:
            else_branch_node, else_consumed = self._build_sequence(
                false_succ,
                stop=join,
                visited=visited,
                allowed=allowed,
            )
            consumed |= else_consumed
            if else_branch_node.nodes:
                else_branch = else_branch_node
        metadata: Dict[str, object] = {
            "successors": list(self.successors.get(block_id, ())),
        }
        return (
            IfNode(condition=BlockNode(block), then_branch=then_branch, else_branch=else_branch, join=join, metadata=metadata),
            join,
            consumed,
        )

    def _default_successor(
        self, block_id: str, visited: Set[str], allowed: Optional[Set[str]], stop: Optional[str]
    ) -> Optional[str]:
        for candidate in self.successors.get(block_id, ()):  # pragma: no branch - tiny list
            if candidate == stop:
                return stop
            if allowed is not None and candidate not in allowed:
                continue
            if candidate in self.trap_blocks:
                continue
            if candidate in visited:
                continue
            return candidate
        return stop

    def _next_after_trap(
        self, block_id: str, allowed: Optional[Set[str]], stop: Optional[str]
    ) -> Optional[str]:
        block = self.block_map.get(block_id)
        if not block:
            return stop
        for candidate in block.successors:
            if candidate == stop:
                return stop
            if candidate in self.trap_blocks:
                continue
            if allowed is not None and candidate not in allowed:
                continue
            return candidate
        return stop


def reconstruct_control_flow(program: IRProgram) -> StructuredProgram:
    """Convenience wrapper returning :class:`StructuredProgram`."""

    reconstructor = ControlFlowReconstructor(program)
    return reconstructor.reconstruct()


def _block_offsets(block: BasicBlock) -> Dict[int, int]:
    offsets: Dict[int, int] = {}
    raw_offsets = getattr(block, "raw_offsets", None)
    if isinstance(raw_offsets, Iterable):
        for relative, raw in enumerate(raw_offsets):
            offsets[block.start_index + relative] = int(raw)
    return offsets


def _format_operation_comment(block: BasicBlock, op_index: int) -> str:
    offsets = _block_offsets(block)
    op = block.ops[op_index]
    offset = offsets.get(op.index)
    parts = [f"idx={op.index}"]
    if offset is None:
        offset = op.index
    parts.append(f"offset=0x{int(offset):04X}")
    if op.raw is not None:
        parts.append(f"raw=0x{int(op.raw):08X}")
    return " -- [" + " ".join(parts) + "]"


def _emit_block_function(block: BasicBlock, indent: str = "    ") -> List[str]:
    lines = [f"local function block_{block.block_id}()"]
    block_indent = indent
    lines.append(
        f"{block_indent}-- block {block.block_id} [{block.start_index}:{block.end_index}]"
    )
    offsets = _block_offsets(block)
    for index, op in enumerate(block.ops):
        operands = []
        for operand in op.operands:
            if not operand.field:
                continue
            resolved = getattr(operand, "resolved", None)
            if resolved is not None:
                operand_value = repr(resolved)
            elif operand.value is not None:
                operand_value = repr(operand.value)
            else:
                operand_value = "nil"
            operands.append(f"{operand.field}={operand_value}")
        detail = " ".join(operands)
        comment = _format_operation_comment(block, index)
        prefix = f"{block_indent}-- {op.mnemonic}"
        if detail:
            prefix += f" {detail}"
        lines.append(f"{prefix}{comment}")
    if not block.ops:
        lines.append(f"{block_indent}-- (no operations)")
    lines.append("end")
    return lines


def _emit_sequence(
    sequence: SequenceNode,
    *,
    indent_level: int,
    indent: str,
    annotate_uncertain: bool,
) -> List[str]:
    lines: List[str] = []
    prefix = indent * indent_level
    for node in sequence.nodes:
        if isinstance(node, BlockNode):
            lines.append(f"{prefix}block_{node.block.block_id}()")
        elif isinstance(node, IfNode):
            comment = []
            if annotate_uncertain and node.join is None:
                comment.append("missing join")
            if annotate_uncertain and (node.else_branch is None or node.else_branch.is_empty):
                comment.append("missing else branch")
            suffix = ""
            if comment:
                suffix = " -- TODO: " + ", ".join(comment)
            lines.append(
                f"{prefix}if block_{node.condition.block.block_id}() then{suffix}"
            )
            then_lines = _emit_sequence(
                node.then_branch,
                indent_level=indent_level + 1,
                indent=indent,
                annotate_uncertain=annotate_uncertain,
            )
            if then_lines:
                lines.extend(then_lines)
            else:
                lines.append(indent * (indent_level + 1) + "-- TODO: empty then branch")
            if node.else_branch is not None and node.else_branch.nodes:
                lines.append(f"{prefix}else")
                else_lines = _emit_sequence(
                    node.else_branch,
                    indent_level=indent_level + 1,
                    indent=indent,
                    annotate_uncertain=annotate_uncertain,
                )
                lines.extend(else_lines)
            elif annotate_uncertain:
                lines.append(prefix + "else -- TODO: synthesize else branch")
                lines.append(indent * (indent_level + 1) + "-- (no statements)")
            lines.append(f"{prefix}end")
        elif isinstance(node, WhileNode):
            comment = []
            if annotate_uncertain and node.exit is None:
                comment.append("missing exit block")
            if annotate_uncertain and node.body.is_empty:
                comment.append("empty loop body")
            suffix = ""
            if comment:
                suffix = " -- TODO: " + ", ".join(comment)
            lines.append(
                f"{prefix}while block_{node.header.block.block_id}() do{suffix}"
            )
            body_lines = _emit_sequence(
                node.body,
                indent_level=indent_level + 1,
                indent=indent,
                annotate_uncertain=annotate_uncertain,
            )
            if body_lines:
                lines.extend(body_lines)
            else:
                lines.append(indent * (indent_level + 1) + "-- TODO: empty loop body")
            lines.append(f"{prefix}end")
    return lines


def emit_structured_lua(
    structured: StructuredProgram,
    *,
    candidate: Optional[str] = None,
    indent: str = "    ",
    annotate_uncertain: bool = True,
) -> str:
    """Render a pseudo-Lua representation of *structured* control flow."""

    header = [
        "-- Structured pseudo-Lua representation",
        f"-- entry: {structured.entry or 'unknown'}",
    ]
    if candidate:
        header.append(f"-- candidate: {candidate}")
    if structured.traps:
        header.append("-- isolated trap handlers: " + ", ".join(t.block.block_id for t in structured.traps))

    block_lines: List[str] = []
    emitted_blocks: Set[str] = set()
    for node in structured.body.nodes:
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, BlockNode):
                if current.block.block_id in emitted_blocks:
                    continue
                block_lines.extend(_emit_block_function(current.block, indent=indent))
                block_lines.append("")
                emitted_blocks.add(current.block.block_id)
            elif isinstance(current, SequenceNode):
                stack.extend(reversed(current.nodes))
            elif isinstance(current, IfNode):
                stack.append(current.condition)
                stack.append(current.then_branch)
                if current.else_branch is not None:
                    stack.append(current.else_branch)
            elif isinstance(current, WhileNode):
                stack.append(current.header)
                stack.append(current.body)

    body_lines = _emit_sequence(
        structured.body,
        indent_level=0,
        indent=indent,
        annotate_uncertain=annotate_uncertain,
    )

    lines = header + [""]
    if block_lines:
        lines.extend(block_lines)
    lines.append("local function structured_main()")
    if body_lines:
        lines.extend(indent + line if line else line for line in body_lines)
    else:
        lines.append(indent + "-- (no body)" )
    lines.append("end")
    lines.append("")
    lines.append("return {")
    lines.append(f"{indent}entry = '{structured.entry or 'unknown'}',")
    lines.append(f"{indent}run = structured_main,")
    if structured.traps:
        trap_list = ", ".join(repr(trap.block.block_id) for trap in structured.traps)
        lines.append(f"{indent}traps = {{{trap_list}}},")
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def write_structured_artifacts(
    structured: StructuredProgram,
    *,
    candidate: str,
    output_dir: Path,
    annotate_uncertain: bool = True,
) -> Dict[str, Path]:
    """Write pseudo-Lua and AST artefacts for *structured* program."""

    ast_payload = structured.to_ast()
    structured_dir = output_dir / "structured"
    structured_dir.mkdir(parents=True, exist_ok=True)

    lua_path = structured_dir / f"{candidate}.lua"
    lua_text = emit_structured_lua(
        structured,
        candidate=candidate,
        annotate_uncertain=annotate_uncertain,
    )
    lua_path.write_text(lua_text, encoding="utf-8")

    json_path = structured_dir / f"{candidate}.json"
    json_path.write_text(json.dumps(ast_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    return {"lua": lua_path, "json": json_path}



