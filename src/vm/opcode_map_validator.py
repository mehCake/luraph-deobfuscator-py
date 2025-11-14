"""Opcode map validation utilities.

This module provides a static validator that inspects a disassembled
instruction stream together with a proposed opcode→mnemonic mapping.  The
validator does *not* execute any payload code.  Instead it performs a light
weight simulation over synthetic register values and analyses control-flow
patterns to highlight contradictions such as two different opcodes both being
labelled ``RETURN`` yet frequently appearing in the middle of a basic block.

The checks are intentionally heuristic – they aim to catch glaring mistakes in
candidate maps while remaining safe to run against untrusted input.  Analysts
can adjust the strictness profile to tune the thresholds used when comparing
opcode behaviour.  The validator emits a human readable Markdown report so that
manual review notes can be captured alongside the automated findings.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .disassembler import Instruction
from .opcode_map import load_map, apply_map_to_disasm
from .opcode_proposer import load_disassembly_instructions

if TYPE_CHECKING:  # pragma: no cover - type checking only
    from .opcode_map import OpcodeMap

LOGGER = logging.getLogger(__name__)

OUTPUT_DIR = Path("out/validate")
_TERMINAL_MNEMONICS = {"RETURN", "JMP"}


@dataclass(frozen=True)
class ValidationIssue:
    """Represents a single contradiction uncovered during validation."""

    opcode: int
    mnemonic: str
    message: str
    severity: str = "warning"
    example_index: Optional[int] = None

    def headline(self) -> str:
        prefix = self.severity.upper()
        target = f"0x{self.opcode:02X} ({self.mnemonic})"
        return f"{prefix}: {target} – {self.message}"


@dataclass
class OpcodeContext:
    """Aggregated behavioural information for a specific opcode."""

    opcode: int
    mnemonic: str
    total: int = 0
    terminal_count: int = 0
    followup_opcodes: MutableMapping[int, int] = field(default_factory=dict)
    registers_written: set[int] = field(default_factory=set)
    registers_read: set[int] = field(default_factory=set)
    const_indices: set[int] = field(default_factory=set)
    operand_signatures: set[Tuple[int, int, int]] = field(default_factory=set)
    return_signatures: set[Tuple[Optional[str], Optional[str]]] = field(default_factory=set)
    example_index: Optional[int] = None

    @property
    def terminal_ratio(self) -> float:
        if not self.total:
            return 0.0
        return self.terminal_count / self.total

    def record_followup(self, opcode: int) -> None:
        self.followup_opcodes[opcode] = self.followup_opcodes.get(opcode, 0) + 1


@dataclass(frozen=True)
class StrictnessProfile:
    """Configuration describing how aggressively to flag inconsistencies."""

    name: str
    terminal_variance: float
    operand_variance: float
    allow_duplicate_returns: int
    escalate_warnings: bool

    @classmethod
    def from_name(cls, name: str) -> "StrictnessProfile":
        mapping = {
            "lenient": cls("lenient", terminal_variance=0.5, operand_variance=0.75, allow_duplicate_returns=3, escalate_warnings=False),
            "balanced": cls("balanced", terminal_variance=0.35, operand_variance=0.6, allow_duplicate_returns=3, escalate_warnings=False),
            "strict": cls("strict", terminal_variance=0.2, operand_variance=0.45, allow_duplicate_returns=2, escalate_warnings=True),
        }
        try:
            return mapping[name]
        except KeyError:  # pragma: no cover - defensive
            raise ValueError(f"Unsupported strictness level: {name}")


@dataclass
class ValidationSummary:
    """Container holding the results of a validation run."""

    candidate: str
    strictness: StrictnessProfile
    total_instructions: int
    unique_opcodes: int
    contexts: Mapping[int, OpcodeContext]
    issues: List[ValidationIssue] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        if not self.issues:
            return True
        return all(issue.severity.lower() != "error" for issue in self.issues)

    def to_markdown(self) -> str:
        lines = [
            f"# Opcode Map Validation – {self.candidate}",
            "",
            f"*Strictness:* {self.strictness.name}",
            f"*Instructions analysed:* {self.total_instructions}",
            f"*Unique opcodes observed:* {self.unique_opcodes}",
            "",
        ]
        if self.issues:
            lines.append("## Detected issues")
            lines.append("")
            for issue in self.issues:
                head = issue.headline()
                if issue.example_index is not None:
                    head += f" (example index {issue.example_index})"
                lines.append(f"- {head}")
            lines.append("")
        else:
            lines.append("No contradictions detected under the selected profile.")
            lines.append("")
        if self.notes:
            lines.append("## Notes")
            lines.append("")
            for note in self.notes:
                lines.append(f"- {note}")
            lines.append("")
        lines.append("## Opcode statistics")
        lines.append("")
        for opcode in sorted(self.contexts):
            ctx = self.contexts[opcode]
            lines.append(f"- 0x{opcode:02X} {ctx.mnemonic} – total {ctx.total}, terminal ratio {ctx.terminal_ratio:.2f}")
            if ctx.const_indices:
                consts = ", ".join(str(idx) for idx in sorted(ctx.const_indices)[:6])
                lines.append(f"  - constant indices: {consts}")
            if ctx.followup_opcodes:
                follow = ", ".join(f"0x{code:02X}:{count}" for code, count in sorted(ctx.followup_opcodes.items()))
                lines.append(f"  - next opcodes: {follow}")
        lines.append("")
        return "\n".join(lines)


@dataclass
class SimulationState:
    """Minimal state used while analysing instruction effects."""

    registers: Dict[int, str] = field(default_factory=dict)

    def read(self, register: int) -> Optional[str]:
        return self.registers.get(register)

    def write(self, register: int, value: str) -> None:
        self.registers[register] = value


def _normalise_mapping(mapping: Mapping[int, str] | "OpcodeMap") -> Mapping[int, str]:
    if hasattr(mapping, "mnemonics"):
        return dict(mapping.mnemonics)  # type: ignore[return-value]
    return {int(op): str(mnemonic) for op, mnemonic in mapping.items()}


def _iter_mapped_instructions(
    instructions: Sequence[Instruction],
    mapping: Mapping[int, str],
) -> Iterator[Tuple[int, Instruction, str]]:
    for index, instruction in enumerate(instructions):
        mnemonic = mapping.get(instruction.opcode)
        if mnemonic is None:
            mnemonic = f"OP_{instruction.opcode:02X}"
        yield index, instruction, mnemonic.upper()


def _update_context(
    ctx: OpcodeContext,
    index: int,
    instr: Instruction,
    mnemonic: str,
    state: SimulationState,
) -> None:
    ctx.total += 1
    ctx.operand_signatures.add((instr.a, instr.b, instr.c))
    if ctx.example_index is None:
        ctx.example_index = index

    if mnemonic in _TERMINAL_MNEMONICS:
        ctx.terminal_count += 1

    if mnemonic == "LOADK":
        ctx.registers_written.add(instr.a)
        ctx.const_indices.add(instr.b)
        state.write(instr.a, f"K{instr.b}")
    elif mnemonic == "MOVE":
        ctx.registers_written.add(instr.a)
        ctx.registers_read.add(instr.b)
        value = state.read(instr.b) or f"R{instr.b}"
        state.write(instr.a, value)
    elif mnemonic == "RETURN":
        ctx.registers_read.add(instr.a)
        ctx.registers_read.add(instr.b)
        ctx.return_signatures.add((state.read(instr.a), state.read(instr.a + 1)))
    elif mnemonic == "CALL":
        ctx.registers_read.add(instr.a)
        ctx.registers_read.add(instr.b)
    elif mnemonic == "JMP":
        ctx.registers_read.add(instr.a)
    elif mnemonic == "EQ":
        ctx.registers_read.update({instr.a, instr.b, instr.c})


def _collect_contexts(
    instructions: Sequence[Instruction],
    mapping: Mapping[int, str],
) -> Dict[int, OpcodeContext]:
    contexts: Dict[int, OpcodeContext] = {}
    state = SimulationState()
    previous: Optional[Tuple[OpcodeContext, int]] = None
    for index, instr, mnemonic in _iter_mapped_instructions(instructions, mapping):
        ctx = contexts.setdefault(instr.opcode, OpcodeContext(opcode=instr.opcode, mnemonic=mnemonic))
        _update_context(ctx, index, instr, mnemonic, state)
        if previous is not None:
            prev_ctx, prev_opcode = previous
            if prev_ctx.mnemonic in _TERMINAL_MNEMONICS:
                prev_ctx.record_followup(instr.opcode)
        previous = (ctx, instr.opcode)
        if mnemonic in _TERMINAL_MNEMONICS:
            state = SimulationState()
    return contexts


def _compare_operand_patterns(a: OpcodeContext, b: OpcodeContext) -> float:
    if not a.operand_signatures or not b.operand_signatures:
        return 0.0
    overlap = len(a.operand_signatures & b.operand_signatures)
    total = len(a.operand_signatures | b.operand_signatures)
    if not total:
        return 0.0
    return 1.0 - (overlap / total)


def _analyse_duplicates(
    grouped: Mapping[str, List[OpcodeContext]],
    profile: StrictnessProfile,
) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    for mnemonic, contexts in grouped.items():
        if len(contexts) <= 1:
            continue
        base = contexts[0]
        for other in contexts[1:]:
            terminal_diff = abs(base.terminal_ratio - other.terminal_ratio)
            if mnemonic in _TERMINAL_MNEMONICS and terminal_diff > profile.terminal_variance:
                issues.append(
                    ValidationIssue(
                        opcode=other.opcode,
                        mnemonic=mnemonic,
                        message=(
                            f"terminal behaviour differs from opcode 0x{base.opcode:02X} by {terminal_diff:.2f}"
                        ),
                        severity="error",
                        example_index=other.example_index,
                    )
                )
            operand_distance = _compare_operand_patterns(base, other)
            if operand_distance > profile.operand_variance:
                issues.append(
                    ValidationIssue(
                        opcode=other.opcode,
                        mnemonic=mnemonic,
                        message=(
                            f"operand usage diverges significantly from opcode 0x{base.opcode:02X} (distance {operand_distance:.2f})"
                        ),
                        severity="warning",
                        example_index=other.example_index,
                    )
                )
        if mnemonic == "RETURN" and len(contexts) > profile.allow_duplicate_returns:
            issues.append(
                ValidationIssue(
                    opcode=contexts[-1].opcode,
                    mnemonic=mnemonic,
                    message=(
                        f"more than {profile.allow_duplicate_returns} opcodes mapped to RETURN – consider tightening the map"
                    ),
                    severity="warning",
                    example_index=contexts[-1].example_index,
                )
            )
    return issues


def _analyse_terminal_followups(contexts: Mapping[int, OpcodeContext]) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []
    for ctx in contexts.values():
        if ctx.mnemonic not in _TERMINAL_MNEMONICS:
            continue
        if ctx.followup_opcodes:
            follow = ", ".join(f"0x{op:02X}" for op in sorted(ctx.followup_opcodes))
            issues.append(
                ValidationIssue(
                    opcode=ctx.opcode,
                    mnemonic=ctx.mnemonic,
                    message=f"terminal opcode followed by additional instructions ({follow})",
                    severity="warning",
                    example_index=ctx.example_index,
                )
            )
    return issues


def _version_specific_checks(
    contexts: Mapping[int, OpcodeContext],
    version_hint: Optional[str],
) -> List[ValidationIssue]:
    if not version_hint:
        return []
    lowered = version_hint.lower()
    issues: List[ValidationIssue] = []
    if "14.4.2" in lowered:
        for ctx in contexts.values():
            if ctx.mnemonic == "RETURN":
                unusual = [sig for sig in ctx.operand_signatures if sig[1] not in {0, 1, 2}]
                if unusual:
                    issues.append(
                        ValidationIssue(
                            opcode=ctx.opcode,
                            mnemonic="RETURN",
                            message="unexpected RETURN operand patterns for v14.4.2 (check B operand)",
                            severity="warning",
                            example_index=ctx.example_index,
                        )
                    )
            if ctx.mnemonic == "CALL":
                # CALL in v14.4.2 typically has small argument counts encoded in C
                unusual = [sig for sig in ctx.operand_signatures if sig[2] > 4]
                if unusual:
                    issues.append(
                        ValidationIssue(
                            opcode=ctx.opcode,
                            mnemonic="CALL",
                            message="CALL operand C frequently exceeds expected small-arity range",
                            severity="warning",
                            example_index=ctx.example_index,
                        )
                    )
    return issues


def validate_opcode_map(
    instructions: Sequence[Instruction],
    mapping: Mapping[int, str] | "OpcodeMap",
    *,
    candidate: str = "candidate",
    strictness: str = "balanced",
    version_hint: Optional[str] = None,
) -> ValidationSummary:
    """Validate *mapping* against *instructions* and return a summary."""

    profile = StrictnessProfile.from_name(strictness)
    normalised = _normalise_mapping(mapping)
    contexts = _collect_contexts(instructions, normalised)

    grouped: Dict[str, List[OpcodeContext]] = {}
    for ctx in contexts.values():
        grouped.setdefault(ctx.mnemonic, []).append(ctx)

    issues: List[ValidationIssue] = []
    issues.extend(_analyse_duplicates(grouped, profile))
    issues.extend(_analyse_terminal_followups(contexts))
    issues.extend(_version_specific_checks(contexts, version_hint))

    if profile.escalate_warnings:
        escalated: List[ValidationIssue] = []
        for issue in issues:
            if issue.severity == "warning":
                escalated.append(
                    ValidationIssue(
                        opcode=issue.opcode,
                        mnemonic=issue.mnemonic,
                        message=issue.message,
                        severity="error",
                        example_index=issue.example_index,
                    )
                )
            else:
                escalated.append(issue)
        issues = escalated

    notes = [
        f"Observed {len(grouped)} distinct mnemonics across the instruction stream.",
    ]

    return ValidationSummary(
        candidate=candidate,
        strictness=profile,
        total_instructions=len(instructions),
        unique_opcodes=len(contexts),
        contexts=contexts,
        issues=issues,
        notes=notes,
    )


def write_validation_report(
    summary: ValidationSummary,
    *,
    output_dir: Path = OUTPUT_DIR,
    filename: Optional[str] = None,
) -> Path:
    """Persist ``summary`` as a Markdown report and return the path."""

    output_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"{summary.candidate}.md"
    path = output_dir / name
    path.write_text(summary.to_markdown(), encoding="utf-8")
    LOGGER.info("wrote validation report to %s", path)
    return path


def _load_mapping(path: Path) -> Mapping[int, str]:
    try:
        opcode_map = load_map(path)
        return _normalise_mapping(opcode_map)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Invalid opcode map JSON in {path}: {exc}") from exc
    except OSError as exc:  # pragma: no cover - filesystem
        raise ValueError(f"Unable to read opcode map {path}: {exc}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate opcode map candidates against disassembly traces")
    parser.add_argument("--map", type=Path, required=True, help="Path to opcode map JSON")
    parser.add_argument("--disasm", type=Path, nargs="+", help="Disassembly JSON files", required=True)
    parser.add_argument("--candidate-name", type=str, default=None, help="Name for the candidate in reports")
    parser.add_argument("--strictness", choices=["lenient", "balanced", "strict"], default="balanced")
    parser.add_argument("--version-hint", type=str, default="v14.4.2", help="Version string used for heuristic checks")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="Directory for validation reports")
    parser.add_argument("--report-name", type=str, default=None, help="Override the Markdown report filename")
    parser.add_argument("--dump-applied", action="store_true", help="Write applied disassembly JSON alongside the report")
    return parser


def run_cli(args: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    namespace = parser.parse_args(args=args)

    mapping = _load_mapping(namespace.map)
    instructions = load_disassembly_instructions(namespace.disasm)
    if not instructions:
        LOGGER.error("no instructions loaded from provided disassembly files")
        return 1

    candidate_name = namespace.candidate_name or namespace.map.stem
    summary = validate_opcode_map(
        instructions,
        mapping,
        candidate=candidate_name,
        strictness=namespace.strictness,
        version_hint=namespace.version_hint,
    )
    write_validation_report(summary, output_dir=namespace.output_dir, filename=namespace.report_name)

    if namespace.dump_applied:
        applied = apply_map_to_disasm(mapping, instructions)
        dump_path = namespace.output_dir / f"{candidate_name}_applied.json"
        dump_path.write_text(json.dumps(applied, indent=2), encoding="utf-8")
        LOGGER.info("wrote applied disassembly to %s", dump_path)

    if summary.is_valid:
        LOGGER.info("validation completed without blocking issues")
        return 0
    LOGGER.warning("validation detected issues – review the generated report")
    return 2


def main() -> None:  # pragma: no cover - thin wrapper for python -m execution
    raise SystemExit(run_cli())


__all__ = [
    "ValidationIssue",
    "ValidationSummary",
    "StrictnessProfile",
    "validate_opcode_map",
    "write_validation_report",
    "run_cli",
]
