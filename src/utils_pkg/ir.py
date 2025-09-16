"""IR node definitions shared across VM lifting and devirtualisation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class IRInstruction:
    """Single SSA-like instruction emitted by the VM lifter."""

    pc: int
    opcode: str
    args: Dict[str, Any] = field(default_factory=dict)
    dest: int | None = None
    sources: List[int] = field(default_factory=list)


@dataclass
class IRBasicBlock:
    """Straight-line sequence of IR instructions with successor metadata."""

    label: str
    start_pc: int
    instructions: List[IRInstruction] = field(default_factory=list)
    successors: List[str] = field(default_factory=list)


@dataclass
class IRModule:
    """Container returned by :class:`VMLifter` describing a VM program."""

    blocks: Dict[str, IRBasicBlock]
    order: List[str]
    entry: str
    register_types: Dict[int, str] = field(default_factory=dict)
    constants: List[Any] = field(default_factory=list)
    instructions: List[IRInstruction] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    bytecode_size: int = 0

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    @property
    def max_register(self) -> int:
        if not self.register_types:
            return -1
        return max(self.register_types)


__all__ = ["IRInstruction", "IRBasicBlock", "IRModule"]
