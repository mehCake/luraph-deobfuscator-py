from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Union

from src.analysis.symbolic import SymbolicExpression


@dataclass
class VMState:
    """Runtime state for :class:`LuraphVM`.

    The state tracks the constants table, bytecode, stack, environment and
    program counter.  ``symbolic`` is a placeholder flag for future symbolic
    execution support.
    """

    constants: List[Any]
    bytecode: List[List[Any]]
    env: Dict[str, Any] = field(default_factory=dict)
    stack: List[Any] = field(default_factory=list)
    registers: Dict[int, Union[int, str, SymbolicExpression]] = field(default_factory=dict)
    pc: int = 0
    symbolic: bool = False
    upvalues: Dict[int, Any] = field(default_factory=dict)
    varargs: List[Any] = field(default_factory=list)

__all__ = ["VMState"]
