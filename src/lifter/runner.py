"""Safety wrapper for executing the accurate lifter with resource limits."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence

from ..utils import OperationTimeout, run_with_timeout
from .lifter import LiftOutput, lift_program

DEFAULT_INSTRUCTION_BUDGET = 1_000_000
DEFAULT_TIME_LIMIT = 20.0
DEFAULT_RECURSION_LIMIT = 32


@dataclass
class LifterLimits:
    """Runtime limits enforced while the lifter executes."""

    instruction_budget: Optional[int] = DEFAULT_INSTRUCTION_BUDGET
    time_limit: Optional[float] = DEFAULT_TIME_LIMIT
    recursion_limit: Optional[int] = DEFAULT_RECURSION_LIMIT
    start_time: float = field(default_factory=time.perf_counter)
    instructions: int = 0
    recursion_depth: int = 0
    partial: bool = False
    partial_reason: Optional[str] = None
    partial_kind: Optional[str] = None

    def __post_init__(self) -> None:  # pragma: no cover - trivial
        if self.time_limit is None or self.time_limit <= 0:
            self.deadline: Optional[float] = None
        else:
            self.deadline = self.start_time + self.time_limit

    # ------------------------------------------------------------------
    # Limit helpers
    # ------------------------------------------------------------------

    def mark_partial(self, kind: str, reason: str) -> None:
        if not self.partial:
            self.partial = True
            self.partial_kind = kind
            self.partial_reason = reason

    def consume(self, amount: int = 1) -> bool:
        if self.partial:
            return False
        increment = amount if amount > 0 else 0
        candidate = self.instructions + increment
        if self.instruction_budget is not None and self.instruction_budget >= 0:
            if candidate > self.instruction_budget:
                overflow = candidate - self.instruction_budget
                self.instructions = self.instruction_budget
                reason = "instruction budget exceeded"
                if overflow > 0:
                    reason += f" (+{overflow})"
                self.mark_partial("instruction_budget", reason)
                return False
        if increment:
            self.instructions = candidate
        return self.check_time()

    def check_time(self) -> bool:
        if self.partial:
            return False
        if self.deadline is not None and time.perf_counter() >= self.deadline:
            self.mark_partial("time_budget", "time limit exceeded")
            return False
        return True

    def allow_recursion(self) -> bool:
        if self.partial:
            return False
        if self.recursion_limit is not None and self.recursion_limit >= 0:
            if self.recursion_depth >= self.recursion_limit:
                self.mark_partial("recursion_limit", "recursion depth limit exceeded")
                return False
        self.recursion_depth += 1
        return True

    def release_recursion(self) -> None:
        if self.recursion_depth > 0:
            self.recursion_depth -= 1


def _apply_partial_metadata(metadata: Dict[str, Any], limits: LifterLimits) -> None:
    if not limits.partial:
        return
    metadata.setdefault("partial", True)
    if limits.partial_kind:
        metadata.setdefault("partial_kind", limits.partial_kind)
    if limits.partial_reason:
        metadata.setdefault("partial_reason", limits.partial_reason)
    metadata.setdefault("instructions_processed", limits.instructions)


def _partial_output_from_limits(limits: LifterLimits, *, root: bool) -> LiftOutput:
    reason = limits.partial_reason or "analysis limits reached"
    lines = []
    if root:
        lines.append("-- lift_ir.lua (partial output)")
    lines.append(f"-- lifter aborted early: {reason}")
    lua_source = "\n".join(lines).rstrip() + "\n"
    metadata = {
        "partial": True,
        "instructions_processed": limits.instructions,
        "opcode_coverage": {"seen": []},
        "function_count": 0,
    }
    if limits.partial_kind:
        metadata["partial_kind"] = limits.partial_kind
    if limits.partial_reason:
        metadata["partial_reason"] = limits.partial_reason
    return LiftOutput(lua_source=lua_source, ir_entries=[], stack_trace=[], metadata=metadata)


def run_lifter_safe(
    instructions: Sequence[Mapping[str, Any]] | Sequence[Any],
    constants: Sequence[Any] | None,
    opcode_map: Optional[Mapping[int, str]] = None,
    *,
    prototypes: Sequence[Any] | None = None,
    script_key: Optional[str | bytes] = None,
    rehydration_state: Optional[Mapping[str, Any]] = None,
    vm_metadata: Optional[Mapping[str, Any]] = None,
    instruction_budget: Optional[int] = DEFAULT_INSTRUCTION_BUDGET,
    time_limit: Optional[float] = DEFAULT_TIME_LIMIT,
    recursion_limit: Optional[int] = DEFAULT_RECURSION_LIMIT,
    root: bool = True,
    debug_logger: Optional[logging.Logger] = None,
) -> LiftOutput:
    """Execute :func:`lift_program` with defensive limits.

    The helper enforces an instruction budget, wall-clock timeout, and recursion
    depth cap.  When a limit is exceeded the returned metadata includes a
    ``partial`` flag so callers can surface the truncated output.
    """

    limits = LifterLimits(
        instruction_budget=instruction_budget,
        time_limit=time_limit,
        recursion_limit=recursion_limit,
    )

    if debug_logger is not None:
        count = len(instructions) if hasattr(instructions, "__len__") else None
        if count is not None:
            debug_logger.debug(
                "Starting lifter (instructions=%d, budget=%s, time_limit=%s, recursion_limit=%s)",
                count,
                instruction_budget,
                time_limit,
                recursion_limit,
            )
        else:
            debug_logger.debug(
                "Starting lifter (budget=%s, time_limit=%s, recursion_limit=%s)",
                instruction_budget,
                time_limit,
                recursion_limit,
            )

    def _invoke() -> LiftOutput:
        return lift_program(
            instructions,
            constants,
            opcode_map,
            prototypes=prototypes or [],
            root=root,
            script_key=script_key,
            rehydration_state=rehydration_state,
            vm_metadata=vm_metadata,
            limits=limits,
            debug_logger=debug_logger,
        )

    timeout: Optional[float]
    if time_limit is None or time_limit <= 0:
        timeout = None
    else:
        timeout = max(time_limit * 1.25, time_limit + 2.0)

    try:
        output = run_with_timeout(_invoke, timeout)
    except OperationTimeout:
        limits.mark_partial("time_budget", "time limit exceeded")
        if debug_logger is not None:
            debug_logger.debug("Lifter timed out after %.2fs", time_limit or 0.0)
        return _partial_output_from_limits(limits, root=root)

    if limits.partial:
        _apply_partial_metadata(output.metadata, limits)
        if debug_logger is not None:
            debug_logger.debug(
                "Lifter completed with partial output (kind=%s, reason=%s)",
                limits.partial_kind,
                limits.partial_reason,
            )
    else:
        output.metadata.setdefault("instructions_processed", limits.instructions)
        if debug_logger is not None:
            debug_logger.debug(
                "Lifter completed successfully (instructions_processed=%d)",
                limits.instructions,
            )

    return output


__all__ = ["LifterLimits", "run_lifter_safe"]
