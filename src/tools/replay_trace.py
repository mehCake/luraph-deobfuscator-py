"""Trace replay utilities for validating opcode maps against recorded runs.

The heavy lifter pipeline extracts traces of VM execution either through the
sandboxed :mod:`src.tools.trace_recorder` helper or via static annotations.  A
trace contains the sequence of operations observed when executing a short
bootstrap snippet together with lightweight metadata about register writes.

This module replays such traces inside a deterministic Python interpreter and
compares the side effects produced by a *candidate* opcode map with the side
effects recorded in the trace.  The goal is not to perfectly emulate the Lua
VM but to highlight inconsistencies early so that analysts can quickly adjust
their opcode mappings.

Key characteristics
===================

* **Static by design** – we never execute bootstrap code.  The replay runs over
  previously captured trace data and a candidate opcode map.
* **Safety first** – the module refuses to persist or even log key material.
  It operates purely on structural information such as register writes.
* **Version-aware diagnostics** – when the caller passes a version hint (e.g.
  ``v14.4.2``) the report highlights heuristics tuned for that version so
  humans can focus on suspicious opcode assignments quickly.

The implementation is intentionally conservative: only a subset of core Lua
opcodes are simulated (``LOADK``, ``MOVE``, ``ADD`` …).  Unknown mnemonics are
treated as "no operation" instructions which keeps the replay predictable while
still surfacing mismatches through the recorded writes.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .trace_recorder import TraceEvent, TraceRecording

try:  # pragma: no cover - optional dependency chain during runtime execution
    from ..vm.opcode_map import OpcodeMap
except Exception:  # pragma: no cover - fallback for tests without full package
    OpcodeMap = None  # type: ignore[assignment]


LOGGER = logging.getLogger(__name__)


class ReplayError(RuntimeError):
    """Raised when the replay process encounters invalid artefacts."""


@dataclass
class ReplayDifference:
    """Represents a mismatch discovered while replaying a trace."""

    pc: int
    raw_opcode: Optional[int]
    expected_mnemonic: Optional[str]
    candidate_mnemonic: Optional[str]
    reason: str
    details: Dict[str, object] = field(default_factory=dict)


@dataclass
class ReplaySuggestion:
    """Recommended mapping adjustments derived from the replay."""

    raw_opcode: int
    suggested_mnemonic: str
    confidence: float
    reason: str
    metadata: Dict[str, object] = field(default_factory=dict)


@dataclass
class ReplayReport:
    """Container describing the replay outcome for a trace run."""

    differences: List[ReplayDifference] = field(default_factory=list)
    suggestions: List[ReplaySuggestion] = field(default_factory=list)
    events_processed: int = 0
    version_hint: Optional[str] = None

    @property
    def summary(self) -> Dict[str, int]:
        """Return a lightweight summary structure."""

        return {
            "events_processed": self.events_processed,
            "difference_count": len(self.differences),
            "suggestion_count": len(self.suggestions),
        }

    def as_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable representation of the replay."""

        return {
            "version_hint": self.version_hint,
            "summary": self.summary,
            "differences": [
                {
                    "pc": diff.pc,
                    "raw_opcode": diff.raw_opcode,
                    "expected_mnemonic": diff.expected_mnemonic,
                    "candidate_mnemonic": diff.candidate_mnemonic,
                    "reason": diff.reason,
                    "details": diff.details,
                }
                for diff in self.differences
            ],
            "suggestions": [
                {
                    "raw_opcode": suggestion.raw_opcode,
                    "suggested_mnemonic": suggestion.suggested_mnemonic,
                    "confidence": suggestion.confidence,
                    "reason": suggestion.reason,
                    "metadata": suggestion.metadata,
                }
                for suggestion in self.suggestions
            ],
        }


@dataclass
class ReplayContext:
    """Mutable state maintained while replaying a trace."""

    simulated_registers: MutableMapping[int, object] = field(default_factory=dict)
    expected_registers: MutableMapping[int, object] = field(default_factory=dict)
    terminated: bool = False

    def sync_expected(self, updates: Mapping[int, object]) -> None:
        for reg, value in updates.items():
            self.expected_registers[reg] = value

    def apply_simulated(self, updates: Mapping[int, object]) -> None:
        for reg, value in updates.items():
            self.simulated_registers[reg] = value


def load_trace(path: Path) -> TraceRecording:
    """Load a trace JSON file produced by :mod:`trace_recorder` or similar."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        events_payload = payload
        run_name = path.stem
        metadata: Dict[str, object] = {}
    else:
        events_payload = payload.get("events", [])
        run_name = str(payload.get("run", path.stem))
        metadata = dict(payload.get("metadata", {}))

    events: List[TraceEvent] = []
    for item in events_payload:
        registers = list(item.get("registers", []))
        extras = dict(item.get("extras", {}))
        stack_depth = int(item.get("stack_depth", item.get("stack", len(registers))))
        register_usage = int(
            item.get(
                "register_usage",
                sum(1 for value in registers if value is not None),
            )
        )
        events.append(
            TraceEvent(
                pc=int(item.get("pc", len(events) + 1)),
                opcode=str(item.get("opcode", "UNKNOWN")),
                stack_depth=stack_depth,
                register_usage=register_usage,
                registers=registers,
                extras=extras,
            )
        )

    return TraceRecording(run_name=run_name, events=events, metadata=metadata)


def load_opcode_map(path: Path) -> Mapping[int, str]:
    """Load an opcode map from disk.

    The loader supports two common formats:

    * :class:`src.vm.opcode_map.OpcodeMap.as_dict` output – payload contains a
      ``mnemonics`` mapping.
    * ``MapCandidate`` style structures exposed by the proposer where the
      mapping lives under ``mapping``.
    """

    payload = json.loads(path.read_text(encoding="utf-8"))
    if "mnemonics" in payload:
        if OpcodeMap is None:  # pragma: no cover - exercised when VM package unavailable
            return {int(opcode): str(mnemonic) for opcode, mnemonic in payload["mnemonics"].items()}
        return OpcodeMap.from_dict(payload).mnemonics
    if "mapping" in payload:
        return {int(opcode): str(mnemonic) for opcode, mnemonic in payload["mapping"].items()}
    raise ReplayError("opcode map JSON must contain a 'mnemonics' or 'mapping' field")


def _coerce_int(value: object) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_raw_opcode(event: TraceEvent) -> Optional[int]:
    extras = event.extras or {}
    for key in ("raw_opcode", "opcode_id", "opcode", "op"):
        raw = extras.get(key)
        coerced = _coerce_int(raw)
        if coerced is not None:
            return coerced
    return None


def _normalise_operands(event: TraceEvent) -> Mapping[str, object]:
    extras = event.extras or {}
    operands = extras.get("operands")
    if isinstance(operands, Mapping):
        return {str(key).lower(): value for key, value in operands.items()}
    if isinstance(operands, (list, tuple)):
        return {f"op{index}": value for index, value in enumerate(operands)}
    registers = event.registers or []
    mapping: Dict[str, object] = {}
    if registers:
        mapping["dest"] = registers[0]
        if len(registers) > 1:
            mapping["op1"] = registers[1]
        if len(registers) > 2:
            mapping["op2"] = registers[2]
    return mapping


def _extract_expected_writes(event: TraceEvent, context: ReplayContext) -> Dict[int, object]:
    extras = event.extras or {}
    writes: Dict[int, object] = {}
    raw_writes = extras.get("writes")
    if isinstance(raw_writes, Mapping):
        for reg, value in raw_writes.items():
            coerced = _coerce_int(reg)
            if coerced is not None:
                writes[coerced] = value
    elif isinstance(raw_writes, Iterable):
        for item in raw_writes:
            if isinstance(item, Mapping):
                reg = _coerce_int(item.get("reg"))
                if reg is None:
                    continue
                writes[reg] = item.get("value")

    expected_after = extras.get("expected_after")
    if isinstance(expected_after, Mapping):
        for reg, value in expected_after.items():
            coerced = _coerce_int(reg)
            if coerced is None:
                continue
            context.expected_registers[coerced] = value
            writes.setdefault(coerced, value)

    if not writes and event.registers:
        dest = _coerce_int(event.registers[0])
        if dest is not None:
            writes[dest] = event.registers[1] if len(event.registers) > 1 else None

    return writes


def _populate_pre_state(event: TraceEvent, context: ReplayContext) -> None:
    extras = event.extras or {}
    pre_state = extras.get("pre_state")
    if isinstance(pre_state, Mapping):
        for reg, value in pre_state.items():
            coerced = _coerce_int(reg)
            if coerced is None:
                continue
            context.simulated_registers.setdefault(coerced, value)
            context.expected_registers.setdefault(coerced, value)


def _operand_lookup(operands: Mapping[str, object], *keys: str, default: Optional[int] = None) -> Optional[int]:
    for key in keys:
        lowered = key.lower()
        if lowered in operands:
            return _coerce_int(operands[lowered])
    return default


def _resolve_operand_value(
    operand_index: Optional[int],
    context: ReplayContext,
    default: object = 0,
) -> object:
    if operand_index is None:
        return default
    if operand_index in context.simulated_registers:
        return context.simulated_registers[operand_index]
    if operand_index in context.expected_registers:
        return context.expected_registers[operand_index]
    return default


def _simulate_instruction(
    mnemonic: Optional[str],
    operands: Mapping[str, object],
    context: ReplayContext,
) -> Dict[int, object]:
    if not mnemonic:
        return {}
    opcode = mnemonic.upper()

    def dest_register(default: Optional[int] = None) -> Optional[int]:
        return _operand_lookup(operands, "dest", "a", "ra", default=default)

    updates: Dict[int, object] = {}
    dest = dest_register()

    if opcode == "LOADK":
        value = operands.get("value")
        if value is None:
            value = operands.get("const")
        if value is None:
            const_index = _operand_lookup(operands, "op1", "const_index", "k")
            value = const_index
        if dest is not None:
            updates[dest] = value
        return updates

    if opcode == "MOVE":
        src = _operand_lookup(operands, "src", "op1", "b")
        if dest is not None:
            updates[dest] = _resolve_operand_value(src, context)
        return updates

    if opcode in {"ADD", "SUB", "MUL", "DIV", "MOD"}:
        lhs = _operand_lookup(operands, "lhs", "op1", "b")
        rhs = _operand_lookup(operands, "rhs", "op2", "c")
        left_value = _resolve_operand_value(lhs, context)
        right_value = _resolve_operand_value(rhs, context)
        try:
            if opcode == "ADD":
                result = (left_value or 0) + (right_value or 0)
            elif opcode == "SUB":
                result = (left_value or 0) - (right_value or 0)
            elif opcode == "MUL":
                result = (left_value or 0) * (right_value or 0)
            elif opcode == "DIV":
                result = (left_value or 0) / (right_value or 1)
            else:  # MOD
                result = (left_value or 0) % (right_value or 1)
        except Exception:  # pragma: no cover - extremely defensive
            result = None
        if dest is not None:
            updates[dest] = result
        return updates

    if opcode == "RETURN":
        context.terminated = True
        return updates

    if opcode == "JMP":
        return updates

    if opcode == "EQ":
        lhs = _operand_lookup(operands, "lhs", "op1", "b")
        rhs = _operand_lookup(operands, "rhs", "op2", "c")
        result = _resolve_operand_value(lhs, context) == _resolve_operand_value(rhs, context)
        if dest is not None:
            updates[dest] = result
        return updates

    return updates


def replay_trace(
    recording: TraceRecording,
    opcode_map: Mapping[int, str],
    *,
    version_hint: Optional[str] = None,
    max_events: Optional[int] = None,
) -> ReplayReport:
    """Replay *recording* using *opcode_map* and build a discrepancy report."""

    report = ReplayReport(version_hint=version_hint)
    context = ReplayContext()
    suggestion_cache: Dict[int, ReplaySuggestion] = {}

    for index, event in enumerate(recording.events):
        if max_events is not None and index >= max_events:
            break

        report.events_processed += 1
        _populate_pre_state(event, context)

        raw_opcode = _extract_raw_opcode(event)
        candidate_mnemonic = opcode_map.get(raw_opcode) if raw_opcode is not None else None
        expected_mnemonic = event.opcode or None

        operands = _normalise_operands(event)
        expected_writes = _extract_expected_writes(event, context)

        predicted_writes = _simulate_instruction(candidate_mnemonic, operands, context)

        mismatched_registers: Dict[int, Tuple[object, object]] = {}
        for reg, expected_value in expected_writes.items():
            predicted_value = predicted_writes.get(reg)
            if predicted_value != expected_value:
                mismatched_registers[reg] = (expected_value, predicted_value)

        if expected_writes and not predicted_writes and candidate_mnemonic:
            mismatched_registers.update({reg: (value, None) for reg, value in expected_writes.items()})

        if raw_opcode is not None and expected_mnemonic and candidate_mnemonic:
            if expected_mnemonic.upper() != candidate_mnemonic.upper():
                details = {
                    "expected": expected_mnemonic,
                    "candidate": candidate_mnemonic,
                }
                if version_hint:
                    details["version_hint"] = version_hint
                report.differences.append(
                    ReplayDifference(
                        pc=event.pc,
                        raw_opcode=raw_opcode,
                        expected_mnemonic=expected_mnemonic,
                        candidate_mnemonic=candidate_mnemonic,
                        reason="mnemonic-mismatch",
                        details=details,
                    )
                )
                if raw_opcode not in suggestion_cache:
                    confidence = 0.75 if version_hint and "14.4.2" in version_hint else 0.6
                    suggestion_cache[raw_opcode] = ReplaySuggestion(
                        raw_opcode=raw_opcode,
                        suggested_mnemonic=expected_mnemonic,
                        confidence=confidence,
                        reason="trace-opcode-disagreement",
                        metadata={"event_pc": event.pc},
                    )

        if mismatched_registers:
            report.differences.append(
                ReplayDifference(
                    pc=event.pc,
                    raw_opcode=raw_opcode,
                    expected_mnemonic=expected_mnemonic,
                    candidate_mnemonic=candidate_mnemonic,
                    reason="write-mismatch",
                    details={
                        "registers": {
                            str(reg): {"expected": exp, "predicted": pred}
                            for reg, (exp, pred) in mismatched_registers.items()
                        },
                        "operands": dict(operands),
                        "version_hint": version_hint,
                    },
                )
            )
            if raw_opcode is not None and expected_mnemonic and raw_opcode not in suggestion_cache:
                confidence = 0.7 if version_hint and "14.4.2" in version_hint else 0.55
                suggestion_cache[raw_opcode] = ReplaySuggestion(
                    raw_opcode=raw_opcode,
                    suggested_mnemonic=expected_mnemonic,
                    confidence=confidence,
                    reason="register-side-effect-mismatch",
                    metadata={"event_pc": event.pc},
                )

        if not mismatched_registers:
            context.apply_simulated(predicted_writes)
        else:
            context.apply_simulated({reg: exp for reg, (exp, _pred) in mismatched_registers.items()})
        context.sync_expected(expected_writes)

    report.suggestions.extend(sorted(suggestion_cache.values(), key=lambda item: (-item.confidence, item.raw_opcode)))
    return report


def write_report(report: ReplayReport, output_dir: Path, candidate_name: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{candidate_name}.json"
    target.write_text(json.dumps(report.as_dict(), indent=2), encoding="utf-8")
    return target


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay VM trace against an opcode map")
    parser.add_argument("trace", type=Path, help="Path to the trace JSON file")
    parser.add_argument("opcode_map", type=Path, help="Path to the candidate opcode map JSON")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/replay"),
        help="Directory where replay reports are written (default: out/replay)",
    )
    parser.add_argument(
        "--candidate-name",
        default="candidate",
        help="Name used for the replay artefact (default: candidate)",
    )
    parser.add_argument(
        "--version-hint",
        help="Optional version hint (e.g. v14.4.2) used to tune diagnostics",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        help="Limit the number of events processed from the trace",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 1 when differences are detected",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    recording = load_trace(args.trace)
    opcode_map = load_opcode_map(args.opcode_map)

    report = replay_trace(
        recording,
        opcode_map,
        version_hint=args.version_hint,
        max_events=args.max_events,
    )
    target = write_report(report, args.output_dir, args.candidate_name)

    LOGGER.info("Replay report written to %s", target)
    print(target)
    if args.strict and report.differences:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI helper
    raise SystemExit(main())
