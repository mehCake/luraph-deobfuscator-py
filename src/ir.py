from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class IRInstruction:
    """Minimal intermediate representation node."""

    index: int
    opcode: str
    args: List[str] = field(default_factory=list)


@dataclass
class BasicBlock:
    """Container for a straight-line sequence of IR instructions."""

    label: str
    instructions: List[IRInstruction] = field(default_factory=list)


__all__ = ["IRInstruction", "BasicBlock"]
