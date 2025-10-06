"""Structured emission helpers that turn a CFG into Lua statements."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set

from src.lifter.cfg import CFG, BasicBlock, LoopInfo, Terminator

__all__ = [
    "InstructionNode",
    "IfNode",
    "WhileNode",
    "StructuredEmitter",
]


@dataclass
class InstructionNode:
    """Represents straight-line Lua emitted for a single instruction."""

    instruction_index: int
    lines: List[str]


@dataclass
class IfNode:
    """Structured conditional node."""

    instruction_index: int
    condition: str
    then_branch: List["Statement"] = field(default_factory=list)
    else_branch: List["Statement"] = field(default_factory=list)
    guard_index: Optional[int] = None


@dataclass
class WhileNode:
    """Structured natural loop node."""

    instruction_index: int
    condition: str
    body: List["Statement"] = field(default_factory=list)
    loop: Optional[LoopInfo] = None


Statement = InstructionNode | IfNode | WhileNode


class StructuredEmitter:
    """Emit structured Lua constructs from a CFG annotated with metadata."""

    def __init__(
        self,
        cfg: CFG,
        translations: Sequence[Mapping[str, object] | object],
    ) -> None:
        self._cfg = cfg
        self._translations = translations
        self._ast: List[Statement] = []
        self._visited_blocks: set[int] = set()
        self._emitted_loops: set[int] = set()
        self._instruction_snippets: Dict[int, List[str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def ast(self) -> List[Statement]:
        return self._ast

    def emit(self) -> tuple[List[str], Dict[int, str]]:
        self._ast = self._build_block(self._cfg.entry, exit_block=None)
        lines = self._render(self._ast)
        instruction_lua = {
            index: "\n".join(snippets)
            for index, snippets in self._instruction_snippets.items()
            if snippets
        }
        return lines, instruction_lua

    # ------------------------------------------------------------------
    # AST construction
    # ------------------------------------------------------------------

    def _build_block(
        self,
        start_block: Optional[int],
        *,
        exit_block: Optional[int],
        allowed_blocks: Optional[Iterable[int]] = None,
    ) -> List[Statement]:
        statements: List[Statement] = []
        if start_block is None:
            return statements
        allowed = set(allowed_blocks) if allowed_blocks is not None else None
        block_id = start_block
        while block_id is not None and block_id != exit_block:
            block = self._cfg.block(block_id)
            loop_info = self._cfg.loops.get(block_id)
            if (
                loop_info
                and loop_info.reducible
                and block_id not in self._emitted_loops
                and (allowed is None or block_id in allowed)
            ):
                loop_stmt, next_block = self._build_loop(loop_info, exit_block, allowed)
                if loop_stmt is not None:
                    statements.append(loop_stmt)
                block_id = next_block
                continue

            if block_id in self._visited_blocks:
                break
            if allowed is not None and block_id not in allowed:
                break

            self._visited_blocks.add(block_id)
            statements.extend(self._instruction_nodes(block, include_terminator=False))
            terminator = block.terminator
            if terminator is None:
                block_id = block.linear_successor
                continue
            if terminator.kind == "cond":
                if_node = self._build_conditional(block, terminator, exit_block, allowed)
                statements.append(if_node)
                block_id = (
                    terminator.join
                    if terminator.join is not None
                    else block.linear_successor
                )
                continue
            if terminator.kind == "jump":
                target = terminator.target
                if target is None or target == block_id:
                    break
                block_id = target
                continue
            if terminator.kind == "return":
                statements.extend(self._instruction_nodes(block, include_only={terminator.instruction_index}))
                break
            if terminator.kind == "fallthrough":
                statements.extend(self._instruction_nodes(block, include_only={terminator.instruction_index}))
                block_id = block.linear_successor
        return statements

    def _build_loop(
        self,
        loop: LoopInfo,
        exit_block: Optional[int],
        allowed: Optional[Set[int]],
    ) -> tuple[Optional[WhileNode], Optional[int]]:
        header_block = self._cfg.block(loop.header)
        self._emitted_loops.add(loop.header)
        if header_block.id in self._visited_blocks:
            return None, exit_block
        self._visited_blocks.add(header_block.id)
        header_statements = self._instruction_nodes(header_block, include_terminator=False)
        terminator = header_block.terminator
        condition = self._condition_text(terminator)
        true_target = terminator.true_target if terminator else None
        false_target = terminator.false_target if terminator else None
        body_entry = None
        exit_target: Optional[int] = None
        negate = False
        if terminator and terminator.kind == "cond":
            true_in = true_target in loop.body if true_target is not None else False
            false_in = false_target in loop.body if false_target is not None else False
            if true_in and not false_in:
                body_entry = true_target
                exit_target = false_target
            elif false_in and not true_in:
                body_entry = false_target
                exit_target = true_target
                negate = True
            elif true_in:
                body_entry = true_target
                exit_target = false_target
            elif false_in:
                body_entry = false_target
                exit_target = true_target
        if condition is None:
            condition = "true"
        if negate:
            condition = self._negate_condition(condition)
        loop_body: List[Statement] = []
        loop_body.extend(header_statements)
        if body_entry is not None:
            inner_allowed = loop.body if allowed is None else (set(loop.body) & allowed)
            loop_body.extend(
                self._build_block(
                    body_entry,
                    exit_block=loop.header,
                    allowed_blocks=inner_allowed,
                )
            )
        for node in loop.body:
            self._visited_blocks.add(node)
        while_node = WhileNode(
            instruction_index=terminator.instruction_index if terminator else header_block.end,
            condition=condition,
            body=loop_body,
            loop=loop,
        )
        return while_node, exit_target or exit_block

    def _build_conditional(
        self,
        block: BasicBlock,
        terminator: Terminator,
        exit_block: Optional[int],
        allowed: Optional[Set[int]],
    ) -> IfNode:
        condition = self._condition_text(terminator) or "cond"
        then_branch: List[Statement] = []
        else_branch: List[Statement] = []
        if terminator.true_target is not None:
            then_branch = self._build_block(
                terminator.true_target,
                exit_block=terminator.join,
                allowed_blocks=allowed,
            )
        if terminator.false_target is not None:
            else_branch = self._build_block(
                terminator.false_target,
                exit_block=terminator.join,
                allowed_blocks=allowed,
            )
        return IfNode(
            instruction_index=terminator.instruction_index,
            condition=condition,
            then_branch=then_branch,
            else_branch=else_branch,
            guard_index=terminator.guard_index,
        )

    def _instruction_nodes(
        self,
        block: BasicBlock,
        *,
        include_terminator: bool = False,
        include_only: Optional[Set[int]] = None,
    ) -> List[InstructionNode]:
        statements: List[InstructionNode] = []
        for instr_index in block.instructions:
            if include_only is not None and instr_index not in include_only:
                continue
            terminator = block.terminator
            if (
                not include_terminator
                and terminator
                and terminator.kind in {"cond", "jump"}
                and instr_index == terminator.instruction_index
            ):
                continue
            node = self._instruction_node(instr_index)
            if node.lines:
                statements.append(node)
        return statements

    def _instruction_node(self, instruction_index: int) -> InstructionNode:
        translation = self._translation_at(instruction_index)
        fragments: List[str] = []
        lines = getattr(translation, "lines", None)
        if isinstance(lines, Sequence):
            fragments.extend(str(line) for line in lines)
        elif isinstance(translation, Mapping):
            raw_lines = translation.get("lines")
            if isinstance(raw_lines, Sequence):
                fragments.extend(str(line) for line in raw_lines)
        return InstructionNode(instruction_index=instruction_index, lines=fragments)

    def _translation_at(self, index: int) -> Mapping[str, object] | object:
        if index < 0 or index >= len(self._translations):
            return {}
        return self._translations[index]

    def _condition_text(self, terminator: Optional[Terminator]) -> Optional[str]:
        if not terminator:
            return None
        if terminator.condition:
            return terminator.condition
        translation = self._translation_at(terminator.instruction_index)
        metadata = {}
        if isinstance(translation, Mapping):
            metadata = translation
        else:
            meta_attr = getattr(translation, "metadata", None)
            if isinstance(meta_attr, Mapping):
                metadata = meta_attr
        control = metadata.get("control") if isinstance(metadata, Mapping) else None
        if isinstance(control, Mapping):
            condition = control.get("condition")
            if isinstance(condition, str):
                return condition
        return None

    # ------------------------------------------------------------------
    # Rendering helpers
    # ------------------------------------------------------------------

    def _render(self, statements: List[Statement]) -> List[str]:
        lines: List[str] = []
        self._instruction_snippets.clear()
        self._render_statements(statements, indent=0, lines=lines)
        return lines

    def _render_statements(
        self, statements: List[Statement], *, indent: int, lines: List[str]
    ) -> None:
        for statement in statements:
            if isinstance(statement, InstructionNode):
                indent = self._render_instruction(statement, indent, lines)
            elif isinstance(statement, IfNode):
                self._render_if(statement, indent, lines)
            elif isinstance(statement, WhileNode):
                self._render_while(statement, indent, lines)

    def _render_instruction(
        self, node: InstructionNode, indent: int, lines: List[str]
    ) -> int:
        current_indent = indent
        for fragment in node.lines:
            if fragment == "{INDENT}":
                current_indent += 1
                continue
            if fragment == "{DEDENT}":
                current_indent = max(current_indent - 1, 0)
                continue
            text = str(fragment)
            rendered = ("  " * current_indent + text) if text else ""
            lines.append(rendered)
            self._instruction_snippets.setdefault(node.instruction_index, []).append(rendered)
        return indent

    def _render_if(self, node: IfNode, indent: int, lines: List[str]) -> None:
        line = f"if {node.condition} then"
        self._append_control_line(node.instruction_index, line, indent, lines)
        self._render_statements(node.then_branch, indent=indent + 1, lines=lines)
        if node.else_branch:
            self._append_control_line(node.instruction_index, "else", indent, lines)
            self._render_statements(node.else_branch, indent=indent + 1, lines=lines)
        self._append_control_line(node.instruction_index, "end", indent, lines)

    def _render_while(self, node: WhileNode, indent: int, lines: List[str]) -> None:
        line = f"while {node.condition} do"
        self._append_control_line(node.instruction_index, line, indent, lines)
        self._render_statements(node.body, indent=indent + 1, lines=lines)
        self._append_control_line(node.instruction_index, "end", indent, lines)

    def _append_control_line(
        self, instruction_index: int, text: str, indent: int, lines: List[str]
    ) -> None:
        rendered = "  " * indent + text
        lines.append(rendered)
        self._instruction_snippets.setdefault(instruction_index, []).append(rendered)

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _negate_condition(condition: str) -> str:
        stripped = condition.strip()
        if stripped.startswith("not "):
            return stripped[4:].strip()
        if stripped.startswith("(") and stripped.endswith(")"):
            return f"not {stripped}"
        return f"not ({stripped})"
