"""Register and stack emulation helpers for the VM lifter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence


@dataclass
class FrameSnapshot:
    """Represents a captured frame state during emulation."""

    base: Optional[int]
    returns: Any
    call: Optional[str]


class VMEmulator:
    """Minimal interpreter that tracks register and frame state."""

    def __init__(
        self,
        constants: Sequence[Any] | None = None,
        prototypes: Sequence[Any] | None = None,
    ) -> None:
        self._constants = list(constants or [])
        self._prototypes = list(prototypes or [])
        self._register_state: Dict[int, str] = {}
        self._reg_names: Dict[int, str] = {}
        self._call_stack: List[str] = []
        self._frames: List[FrameSnapshot] = []
        self._state_trace: List[Dict[str, Any]] = []
        self._stack_depth = 0
        self._frame_depth = 0
        self._max_call_depth = 0
        self._upvalues: Dict[int, str] = {}

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def register_name(self, index: int) -> str:
        name = self._reg_names.get(index)
        if name is None:
            name = f"local_{index}"
            self._reg_names[index] = name
        return name

    def reg(self, index: Optional[int]) -> str:
        if index is None:
            return "R[?]"
        return self.register_name(index)

    def rk(self, value: Optional[int]) -> str:
        RK_MASK = 0xFF
        RK_FLAG = 0x100
        if value is None:
            return "nil"
        if value & RK_FLAG:
            return self.format_constant(value & RK_MASK)
        return self.reg(value)

    def format_constant(self, index: Optional[int]) -> str:
        if index is None:
            return "nil"
        candidates: List[int] = []
        if isinstance(index, int):
            if 0 <= index < len(self._constants):
                candidates.append(index)
            if index > 0 and index - 1 < len(self._constants):
                candidates.append(index - 1)
        for candidate in candidates:
            literal = self.lua_literal(self._constants[candidate])
            if literal is not None:
                return literal
        return f"K[{index}]"

    def call_args(self, base: int, count: Optional[int]) -> List[str]:
        if not isinstance(count, int) or count <= 1:
            return []
        return [self.reg(base + offset) for offset in range(1, count)]

    def lua_literal(self, value: Any) -> str:
        if isinstance(value, str):
            escaped = (
                value.replace("\\", "\\\\")
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace('"', '\\"')
            )
            return f'"{escaped}"'
        if value is True:
            return "true"
        if value is False:
            return "false"
        if value is None:
            return "nil"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, (list, tuple)):
            inner = ", ".join(self.lua_literal(v) for v in value)
            return "{" + inner + "}"
        if isinstance(value, Mapping):
            parts = []
            for key, val in value.items():
                if isinstance(key, str) and key.isidentifier():
                    parts.append(f"{key} = {self.lua_literal(val)}")
                else:
                    parts.append(f"[{self.lua_literal(key)}] = {self.lua_literal(val)}")
            return "{" + ", ".join(parts) + "}"
        return repr(value)

    def snapshot(
        self,
        index: int,
        pc: Optional[int],
        opcode: Any,
        comment: str | None,
    ) -> Dict[str, Any]:
        registers = {
            self.register_name(reg): value
            for reg, value in sorted(self._register_state.items())
        }
        frames = [
            {
                "base": frame.base,
                "returns": frame.returns,
                "call": frame.call,
            }
            for frame in self._frames
        ]
        snapshot = {
            "index": index,
            "pc": pc,
            "opcode": opcode,
            "comment": comment,
            "registers": registers,
            "call_stack": list(self._call_stack),
            "frames": frames,
            "call_depth": len(self._call_stack),
            "max_call_depth": self._max_call_depth,
            "upvalues": dict(self._upvalues),
        }
        self._state_trace.append(snapshot)
        return snapshot

    # ------------------------------------------------------------------
    # Stack/frame bookkeeping
    # ------------------------------------------------------------------

    def push_frame(self, base: Optional[int], returns: Any, call: str | None) -> None:
        frame = FrameSnapshot(base=base, returns=returns, call=call)
        self._frames.append(frame)
        if call:
            self._call_stack.append(call)
        self._max_call_depth = max(self._max_call_depth, len(self._call_stack))
        self._stack_depth = max(self._stack_depth, len(self._call_stack))

    def pop_frame(self) -> None:
        if self._frames:
            self._frames.pop()
        if self._call_stack:
            self._call_stack.pop()

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def register_state(self) -> Dict[int, str]:
        return self._register_state

    @property
    def state_trace(self) -> List[Dict[str, Any]]:
        return self._state_trace

    @property
    def constants(self) -> Sequence[Any]:
        return self._constants

    @property
    def prototypes(self) -> Sequence[Any]:
        return self._prototypes


__all__ = ["VMEmulator", "FrameSnapshot"]
