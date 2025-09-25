from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


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


@dataclass
class VMInstruction:
    """Canonical representation of a lifted VM opcode."""

    opcode: str
    a: Optional[int] = None
    b: Optional[int] = None
    c: Optional[int] = None
    aux: Dict[str, Any] = field(default_factory=dict)
    pc: int = 0
    offset: Optional[int] = None
    ir: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VMFunction:
    """Register-based function used by the VM simulator and devirtualiser."""

    constants: List[Any]
    instructions: List[VMInstruction]
    prototypes: List["VMFunction"] = field(default_factory=list)
    num_params: int = 0
    is_vararg: bool = False
    register_count: int = 0
    upvalue_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


__all__ = [
    "IRInstruction",
    "BasicBlock",
    "VMInstruction",
    "VMFunction",
]
