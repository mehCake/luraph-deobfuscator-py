"""Control-flow graph builder and structured emitter for lifted bytecode."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


@dataclass
class Terminator:
    """Represents the terminating control-flow behaviour of a basic block."""

    kind: str
    instruction_index: int
    true_target: Optional[int] = None
    false_target: Optional[int] = None
    target: Optional[int] = None
    join: Optional[int] = None
    loop_header: Optional[int] = None
    guard_index: Optional[int] = None


@dataclass
class BasicBlock:
    """Container for instructions that execute sequentially."""

    id: int
    start: int
    end: int
    instructions: List[int]
    successors: List[int] = field(default_factory=list)
    predecessors: Set[int] = field(default_factory=set)
    terminator: Optional[Terminator] = None
    linear_successor: Optional[int] = None


@dataclass
class CFG:
    blocks: List[BasicBlock]
    entry: int
    block_for_instruction: Dict[int, int]

    def block(self, block_id: int) -> BasicBlock:
        return self.blocks[block_id]


class CFGBuilder:
    """Builds a control-flow graph from linear instruction metadata."""

    def __init__(
        self,
        instructions: Sequence[Mapping[str, object]],
        translations: Sequence[Mapping[str, object]],
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
        self._compute_postdominators(blocks)
        return CFG(blocks=blocks, entry=0, block_for_instruction=block_for_instruction)

    # ------------------------------------------------------------------
    # Block construction helpers
    # ------------------------------------------------------------------

    def _collect_block_starts(self) -> List[int]:
        block_starts: Set[int] = {0}
        for index, entry in enumerate(self._instructions):
            translation = self._translations[index]
            metadata = dict(getattr(translation, "metadata", {}) or {})
            control = metadata.get("control") if isinstance(metadata, dict) else None
            mnemonic = str(entry.get("mnemonic") or "").upper()
            next_index = index + 1
            if control:
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
        translation = self._translations[last_index]
        metadata = dict(getattr(translation, "metadata", {}) or {})
        control = metadata.get("control") if isinstance(metadata, dict) else None
        if control:
            ctype = str(control.get("type") or "").lower()
            if ctype == "cond":
                true_target = control.get("true_target")
                false_target = control.get("false_target")
                guard_index = control.get("guard_index")
                terminator = Terminator(
                    kind="cond",
                    instruction_index=last_index,
                    true_target=self._target_to_block(true_target, block_for_instruction),
                    false_target=self._target_to_block(false_target, block_for_instruction),
                    guard_index=guard_index,
                )
                return terminator
            if ctype == "jump":
                target = control.get("target")
                terminator = Terminator(
                    kind="jump",
                    instruction_index=last_index,
                    target=self._target_to_block(target, block_for_instruction),
                )
                if isinstance(target, int) and target <= block.start:
                    terminator.loop_header = self._target_to_block(
                        target, block_for_instruction
                    )
                return terminator
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

    # ------------------------------------------------------------------
    # Post-dominator computation
    # ------------------------------------------------------------------

    def _compute_postdominators(self, blocks: List[BasicBlock]) -> None:
        num_blocks = len(blocks)
        if num_blocks == 0:
            return
        postdom: List[Set[int]] = [set(range(num_blocks)) for _ in range(num_blocks)]
        exits = [block.id for block in blocks if not block.successors]
        for exit_id in exits:
            postdom[exit_id] = {exit_id}

        changed = True
        while changed:
            changed = False
            for block in reversed(blocks):
                if not block.successors:
                    continue
                intersection = set(range(num_blocks))
                for succ in block.successors:
                    intersection &= postdom[succ]
                new_postdom = {block.id} | intersection
                if new_postdom != postdom[block.id]:
                    postdom[block.id] = new_postdom
                    changed = True

        for block in blocks:
            if not block.terminator:
                continue
            term = block.terminator
            if term.kind == "cond":
                true_target = term.true_target
                false_target = term.false_target
                if true_target is None or false_target is None:
                    continue
                common = postdom[true_target] & postdom[false_target]
                common.discard(block.id)
                if not common:
                    continue
                join_block = min(common)
                term.join = join_block


class StructuredEmitter:
    """Render structured Lua code from a CFG."""

    def __init__(
        self,
        cfg: CFG,
        translations: Sequence[Mapping[str, object]],
        instruction_records: Sequence[Dict[str, object]],
    ) -> None:
        self._cfg = cfg
        self._translations = translations
        self._instruction_records = instruction_records
        self._indent = 0
        self._lines: List[str] = []
        self._emitted: Set[int] = set()
        self._instruction_snippets: Dict[int, List[str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def emit(self) -> Tuple[List[str], Dict[int, str]]:
        self._emit_sequence(self._cfg.entry, exit_block=None)
        instruction_lua = {
            index: "\n".join(lines)
            for index, lines in self._instruction_snippets.items()
            if lines
        }
        return self._lines, instruction_lua

    # ------------------------------------------------------------------
    # Emission helpers
    # ------------------------------------------------------------------

    def _emit_sequence(self, start_block: Optional[int], exit_block: Optional[int]) -> None:
        block_id = start_block
        while block_id is not None and block_id != exit_block:
            if block_id in self._emitted:
                return
            block = self._cfg.block(block_id)
            self._emitted.add(block_id)

            terminator = block.terminator
            for instr_index in block.instructions:
                if (
                    terminator
                    and instr_index == terminator.instruction_index
                    and terminator.kind in {"cond", "jump"}
                ):
                    continue
                self._emit_instruction(instr_index)

            if terminator is None:
                block_id = block.linear_successor
                continue
            if terminator.kind == "cond":
                self._emit_conditional(block, terminator)
                block_id = terminator.join if terminator.join is not None else block.linear_successor
                continue
            if terminator.kind == "jump":
                loop_header = terminator.loop_header
                if loop_header is not None and loop_header <= block.id:
                    self._emit_loop(loop_header, block.id)
                    block_id = self._next_block_after(block.id)
                    continue
                block_id = terminator.target
                continue
            if terminator.kind == "return":
                self._emit_instruction(terminator.instruction_index)
                return
            if terminator.kind == "fallthrough":
                self._emit_instruction(terminator.instruction_index)
                block_id = block.linear_successor

    def _emit_loop(self, header_block: int, latch_block: int) -> None:
        latch_instr = self._cfg.block(latch_block).terminator
        latch_index = latch_instr.instruction_index if latch_instr else latch_block
        self._append_line("while true do")
        self._record_instruction_line(latch_index, "while true do")
        self._indent += 1
        self._emit_sequence(header_block, exit_block=latch_block)
        self._indent -= 1
        self._append_line("end")
        self._record_instruction_line(latch_index, "end")

    def _emit_conditional(self, block: BasicBlock, terminator: Terminator) -> None:
        condition_text = ""
        guard_index = terminator.guard_index
        if isinstance(guard_index, int) and guard_index < len(self._translations):
            guard_meta = getattr(self._translations[guard_index], "metadata", {}) or {}
            if isinstance(guard_meta, dict):
                condition_text = guard_meta.get("condition", "")
        if not condition_text:
            jmp_meta = getattr(self._translations[terminator.instruction_index], "metadata", {}) or {}
            if isinstance(jmp_meta, dict):
                condition_text = jmp_meta.get("condition", "")
        if not condition_text:
            condition_text = "cond"
        line = f"if {condition_text} then"
        self._append_line(line)
        self._record_instruction_line(terminator.instruction_index, line)

        self._indent += 1
        if terminator.true_target is not None and terminator.true_target != terminator.join:
            self._emit_sequence(terminator.true_target, exit_block=terminator.join)
        self._indent -= 1

        false_target = terminator.false_target
        if false_target is not None and false_target != terminator.join:
            self._append_line("else")
            self._record_instruction_line(terminator.instruction_index, "else")
            self._indent += 1
            self._emit_sequence(false_target, exit_block=terminator.join)
            self._indent -= 1

        self._append_line("end")
        self._record_instruction_line(terminator.instruction_index, "end")

    def _emit_instruction(self, instruction_index: int) -> None:
        if instruction_index >= len(self._translations):
            return
        translation = self._translations[instruction_index]
        fragments = getattr(translation, "lines", []) or []
        buffer: List[str] = []
        for fragment in fragments:
            if fragment == "{INDENT}":
                self._indent += 1
                continue
            if fragment == "{DEDENT}":
                self._indent = max(self._indent - 1, 0)
                continue
            self._append_line(fragment)
            buffer.append("  " * self._indent + fragment if fragment else fragment)
        if buffer:
            self._instruction_snippets.setdefault(instruction_index, []).extend(buffer)

    def _append_line(self, text: str) -> None:
        if text == "":
            self._lines.append("")
        else:
            self._lines.append("  " * self._indent + text)

    def _record_instruction_line(self, instruction_index: int, text: str) -> None:
        self._instruction_snippets.setdefault(instruction_index, []).append(
            "  " * self._indent + text
        )

    def _next_block_after(self, block_id: int) -> Optional[int]:
        if block_id + 1 >= len(self._cfg.blocks):
            return None
        return block_id + 1
