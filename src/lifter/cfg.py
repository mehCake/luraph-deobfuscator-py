"""Control-flow graph utilities for the structured lifter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

__all__ = [
    "Terminator",
    "BasicBlock",
    "LoopInfo",
    "CFG",
    "CFGBuilder",
]


@dataclass
class Terminator:
    """Describes the terminating control-flow behaviour of a basic block."""

    kind: str
    instruction_index: int
    true_target: Optional[int] = None
    false_target: Optional[int] = None
    target: Optional[int] = None
    join: Optional[int] = None
    loop: Optional["LoopInfo"] = None
    guard_index: Optional[int] = None
    condition: Optional[str] = None


@dataclass
class BasicBlock:
    """A basic block in the reconstructed control-flow graph."""

    id: int
    start: int
    end: int
    instructions: List[int]
    successors: List[int] = field(default_factory=list)
    predecessors: Set[int] = field(default_factory=set)
    terminator: Optional[Terminator] = None
    linear_successor: Optional[int] = None
    dominators: Set[int] = field(default_factory=set)
    postdominators: Set[int] = field(default_factory=set)
    edge_kinds: Dict[int, str] = field(default_factory=dict)


@dataclass
class LoopInfo:
    """Metadata describing a natural loop discovered in the CFG."""

    header: int
    body: Set[int] = field(default_factory=set)
    latches: Set[int] = field(default_factory=set)
    exits: Set[int] = field(default_factory=set)
    reducible: bool = True
    back_edges: Set[Tuple[int, int]] = field(default_factory=set)

    def include_body(self, nodes: Iterable[int]) -> None:
        for node in nodes:
            self.body.add(node)

    def add_back_edge(self, tail: int, head: int) -> None:
        self.back_edges.add((tail, head))
        self.latches.add(tail)


@dataclass
class CFG:
    """Control-flow graph representation for the lifter."""

    blocks: List[BasicBlock]
    entry: int
    block_for_instruction: Dict[int, int]
    loops: Dict[int, LoopInfo]

    def block(self, block_id: int) -> BasicBlock:
        return self.blocks[block_id]


class CFGBuilder:
    """Constructs a CFG with dominator, postdominator, and loop metadata."""

    def __init__(
        self,
        instructions: Sequence[Mapping[str, object]],
        translations: Sequence[Mapping[str, object] | object],
        *,
        labels: Mapping[int, str] | None = None,
        label_for: Optional[callable] = None,
    ) -> None:
        self._instructions = instructions
        self._translations = translations
        self._labels = labels or {}
        self._label_for = label_for

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> CFG:
        block_starts = self._collect_block_starts()
        blocks, block_for_instruction = self._create_blocks(block_starts)
        self._link_successors(blocks, block_for_instruction)
        self._compute_dominators(blocks)
        self._compute_postdominators(blocks)
        loops = self._discover_loops(blocks)
        self._attach_loop_metadata(blocks, loops)
        self._compute_join_points(blocks)
        self._classify_edges(blocks)
        return CFG(
            blocks=blocks,
            entry=0,
            block_for_instruction=block_for_instruction,
            loops=loops,
        )

    # ------------------------------------------------------------------
    # Block construction helpers
    # ------------------------------------------------------------------

    def _collect_block_starts(self) -> List[int]:
        block_starts: Set[int] = {0}
        for index, entry in enumerate(self._instructions):
            translation = self._translation_at(index)
            metadata = self._metadata_for(translation)
            control = metadata.get("control") if isinstance(metadata, Mapping) else None
            mnemonic = str(entry.get("mnemonic") or "").upper()
            next_index = index + 1
            if isinstance(control, Mapping):
                ctype = str(control.get("type") or "").lower()
                if ctype == "cond":
                    true_target = control.get("true_target")
                    false_target = control.get("false_target")
                    if isinstance(true_target, int):
                        block_starts.add(true_target)
                    if isinstance(false_target, int):
                        block_starts.add(false_target)
                    if next_index < len(self._instructions):
                        block_starts.add(next_index)
                elif ctype == "jump":
                    target = control.get("target")
                    if isinstance(target, int):
                        block_starts.add(target)
                    if next_index < len(self._instructions):
                        block_starts.add(next_index)
            elif mnemonic == "RETURN" and next_index < len(self._instructions):
                block_starts.add(next_index)
        ordered = sorted(i for i in block_starts if 0 <= i < len(self._instructions))
        return ordered

    def _create_blocks(
        self, block_starts: Iterable[int]
    ) -> Tuple[List[BasicBlock], Dict[int, int]]:
        block_for_instruction: Dict[int, int] = {}
        starts = list(block_starts)
        blocks: List[BasicBlock] = []
        for block_id, start in enumerate(starts):
            end = self._block_end(start, starts)
            instructions = list(range(start, end + 1))
            for idx in instructions:
                block_for_instruction[idx] = block_id
            block = BasicBlock(
                id=block_id,
                start=start,
                end=end,
                instructions=instructions,
            )
            if block_id + 1 < len(starts):
                block.linear_successor = block_id + 1
            blocks.append(block)
        return blocks, block_for_instruction

    def _block_end(self, start: int, starts: Sequence[int]) -> int:
        start_pos = starts.index(start)
        if start_pos + 1 < len(starts):
            return starts[start_pos + 1] - 1
        return len(self._instructions) - 1

    def _link_successors(
        self, blocks: List[BasicBlock], block_for_instruction: Mapping[int, int]
    ) -> None:
        for block in blocks:
            terminator = self._terminator_for_block(block, block_for_instruction)
            block.terminator = terminator
            if terminator.kind == "cond":
                true_target = terminator.true_target
                false_target = terminator.false_target
                if isinstance(true_target, int):
                    block.successors.append(true_target)
                if isinstance(false_target, int):
                    block.successors.append(false_target)
            elif terminator.kind == "jump":
                if isinstance(terminator.target, int):
                    block.successors.append(terminator.target)
            elif terminator.kind == "fallthrough":
                if block.linear_successor is not None:
                    block.successors.append(block.linear_successor)
            for succ in block.successors:
                if 0 <= succ < len(blocks):
                    blocks[succ].predecessors.add(block.id)

    def _terminator_for_block(
        self, block: BasicBlock, block_for_instruction: Mapping[int, int]
    ) -> Terminator:
        last_index = block.end
        if last_index >= len(self._translations):
            return Terminator(kind="fallthrough", instruction_index=last_index)
        translation = self._translation_at(last_index)
        metadata = self._metadata_for(translation)
        control = metadata.get("control") if isinstance(metadata, Mapping) else None
        if isinstance(control, Mapping):
            ctype = str(control.get("type") or "").lower()
            condition = control.get("condition")
            guard_index = control.get("guard_index")
            if ctype == "cond":
                true_target = self._target_to_block(control.get("true_target"), block_for_instruction)
                false_target = self._target_to_block(control.get("false_target"), block_for_instruction)
                return Terminator(
                    kind="cond",
                    instruction_index=last_index,
                    true_target=true_target,
                    false_target=false_target,
                    guard_index=guard_index if isinstance(guard_index, int) else None,
                    condition=str(condition) if condition is not None else None,
                )
            if ctype == "jump":
                target = self._target_to_block(control.get("target"), block_for_instruction)
                return Terminator(
                    kind="jump",
                    instruction_index=last_index,
                    target=target,
                )
        mnemonic = str(self._instructions[last_index].get("mnemonic") or "").upper()
        if mnemonic == "RETURN":
            return Terminator(kind="return", instruction_index=last_index)
        return Terminator(kind="fallthrough", instruction_index=last_index)

    def _target_to_block(
        self, target: object, block_for_instruction: Mapping[int, int]
    ) -> Optional[int]:
        if not isinstance(target, int):
            return None
        if target < 0 or target >= len(self._instructions):
            return None
        return block_for_instruction.get(target)

    def _translation_at(self, index: int) -> Mapping[str, object] | object:
        if index < 0 or index >= len(self._translations):
            return {}
        return self._translations[index]

    @staticmethod
    def _metadata_for(translation: Mapping[str, object] | object) -> Mapping[str, object]:
        if isinstance(translation, Mapping):
            return translation
        metadata = getattr(translation, "metadata", None)
        if isinstance(metadata, Mapping):
            return metadata
        return {}

    # ------------------------------------------------------------------
    # Dominator and postdominator computation
    # ------------------------------------------------------------------

    def _compute_dominators(self, blocks: List[BasicBlock]) -> None:
        num_blocks = len(blocks)
        if num_blocks == 0:
            return
        for block in blocks:
            block.dominators = set(range(num_blocks))
        entry = blocks[0]
        entry.dominators = {entry.id}
        changed = True
        while changed:
            changed = False
            for block in blocks[1:]:
                if not block.predecessors:
                    new_dom = {block.id}
                else:
                    intersection = set(range(num_blocks))
                    for pred in block.predecessors:
                        intersection &= blocks[pred].dominators
                    new_dom = {block.id} | intersection
                if new_dom != block.dominators:
                    block.dominators = new_dom
                    changed = True

    def _compute_postdominators(self, blocks: List[BasicBlock]) -> None:
        num_blocks = len(blocks)
        if num_blocks == 0:
            return
        exits = [block.id for block in blocks if not block.successors]
        for block in blocks:
            block.postdominators = set(range(num_blocks))
        if not exits:
            exits = [blocks[-1].id]
        for exit_id in exits:
            blocks[exit_id].postdominators = {exit_id}
        changed = True
        order = list(reversed(blocks))
        while changed:
            changed = False
            for block in order:
                if not block.successors:
                    continue
                intersection = set(range(num_blocks))
                for succ in block.successors:
                    intersection &= blocks[succ].postdominators
                new_postdom = {block.id} | intersection
                if new_postdom != block.postdominators:
                    block.postdominators = new_postdom
                    changed = True

    # ------------------------------------------------------------------
    # Loop discovery and edge classification
    # ------------------------------------------------------------------

    def _discover_loops(self, blocks: List[BasicBlock]) -> Dict[int, LoopInfo]:
        loops: Dict[int, LoopInfo] = {}
        for block in blocks:
            for succ in block.successors:
                if succ is None or succ < 0 or succ >= len(blocks):
                    continue
                if blocks[succ].id in block.dominators:
                    header = succ
                    loop = loops.setdefault(header, LoopInfo(header=header))
                    loop.add_back_edge(block.id, header)
                    loop_nodes = self._collect_natural_loop(blocks, header, block.id)
                    loop.include_body(loop_nodes)
        for loop in loops.values():
            loop.body.add(loop.header)
            for node in list(loop.body):
                if loop.header not in blocks[node].dominators:
                    loop.reducible = False
                for succ in blocks[node].successors:
                    if succ not in loop.body and succ is not None:
                        loop.exits.add(succ)
        return loops

    def _collect_natural_loop(
        self, blocks: Sequence[BasicBlock], header: int, latch: int
    ) -> Set[int]:
        body: Set[int] = {header, latch}
        worklist = [latch]
        while worklist:
            node = worklist.pop()
            for pred in blocks[node].predecessors:
                if pred not in body:
                    body.add(pred)
                    worklist.append(pred)
        return body

    def _attach_loop_metadata(
        self, blocks: List[BasicBlock], loops: Mapping[int, LoopInfo]
    ) -> None:
        for header, loop in loops.items():
            block = blocks[header]
            terminator = block.terminator
            if terminator and terminator.kind == "cond":
                terminator.loop = loop

    def _compute_join_points(self, blocks: List[BasicBlock]) -> None:
        for block in blocks:
            terminator = block.terminator
            if not terminator or terminator.kind != "cond":
                continue
            true_target = terminator.true_target
            false_target = terminator.false_target
            if true_target is None or false_target is None:
                continue
            true_postdom = blocks[true_target].postdominators
            false_postdom = blocks[false_target].postdominators
            common = (true_postdom & false_postdom) - {block.id}
            if not common:
                continue
            join = min(common)
            terminator.join = join

    def _classify_edges(self, blocks: List[BasicBlock]) -> None:
        for block in blocks:
            for succ in block.successors:
                if succ is None:
                    continue
                if succ in block.dominators:
                    kind = "back"
                elif block.id in blocks[succ].dominators:
                    kind = "forward"
                else:
                    kind = "cross"
                block.edge_kinds[succ] = kind

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _label_for(self, index: Optional[int]) -> str:
        if index is None:
            return "<invalid>"
        if self._label_for:
            return str(self._label_for(index))
        if index in self._labels:
            return self._labels[index]
        return f"label_{index:04d}"
