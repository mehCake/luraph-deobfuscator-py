"""Produce a non-technical summary of the current analysis state.

The helper consolidates the structured artefacts emitted by the static
detection pipeline (pipeline candidates, mapping reports, parity summaries,
etc.) into a short Markdown digest aimed at stakeholders who do not require
implementation details.  No payload code is executed and the function
intentionally ignores any fields that might contain session keys.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "UserSummary",
    "build_user_summary",
    "write_user_summary",
    "main",
]


def _load_json(path: Optional[Path]) -> Mapping[str, object]:
    """Load *path* as JSON, returning an empty mapping on failure."""

    if path is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.debug("Report artefact %s not found", path)
        return {}
    except OSError as exc:  # pragma: no cover - defensive
        LOGGER.warning("Failed to read %s: %s", path, exc)
        return {}

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Failed to parse JSON from %s: %s", path, exc)
        return {}

    if isinstance(payload, Mapping):
        return payload
    LOGGER.warning("Expected JSON object in %s but received %s", path, type(payload).__name__)
    return {}


def _stringify_sequence(values: Sequence[object], separator: str = " → ") -> str:
    tokens = [str(value) for value in values if value]
    return separator.join(tokens) if tokens else "<not yet determined>"


def _ensure_percentage(value: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, numeric))


def _collect_notes(candidate: Mapping[str, object]) -> Tuple[str, ...]:
    hypothesis = candidate.get("hypothesis_score")
    if isinstance(hypothesis, Mapping):
        notes = hypothesis.get("notes")
        if isinstance(notes, Iterable) and not isinstance(notes, (str, bytes)):
            return tuple(str(note) for note in notes if note)
    return ()


@dataclass(frozen=True)
class UserSummary:
    """A lightweight summary tailored for non-technical readers."""

    target: str
    version_hint: str
    confidence: float
    key_findings: Tuple[str, ...]
    next_steps: Tuple[str, ...]
    outstanding_items: Tuple[str, ...]
    references: Tuple[str, ...]

    def render_markdown(self) -> str:
        lines = ["# Luraph Analysis Overview", ""]
        lines.append(f"**Target:** {self.target}")
        lines.append(f"**Version focus:** {self.version_hint}")
        lines.append(f"**Overall confidence:** {self.confidence:.0%}")
        lines.append("")

        lines.append("## What We Found")
        if self.key_findings:
            for entry in self.key_findings:
                lines.append(f"* {entry}")
        else:
            lines.append("* No automated findings available; manual review required.")
        lines.append("")

        lines.append("## Next Steps (prioritised)")
        if self.next_steps:
            for index, step in enumerate(self.next_steps, start=1):
                lines.append(f"{index}. {step}")
        else:
            lines.append("1. Review the pipeline artefacts and confirm findings with the analysis team.")
        lines.append("")

        lines.append("## Outstanding Questions")
        if self.outstanding_items:
            for item in self.outstanding_items:
                lines.append(f"* {item}")
        else:
            lines.append("* No unresolved items recorded by the tooling.")
        lines.append("")

        if self.references:
            lines.append("## Reference Artefacts")
            for ref in self.references:
                lines.append(f"* {ref}")
            lines.append("")

        lines.append("_This summary highlights Luraph v14.4.2 behaviours; adjust actions if the target payload deviates from that version._")
        lines.append("")
        return "\n".join(lines)


def _select_primary_candidate(report: Mapping[str, object]) -> Mapping[str, object]:
    pipelines = report.get("pipelines")
    if isinstance(pipelines, Sequence):
        candidates = [entry for entry in pipelines if isinstance(entry, Mapping)]
        if candidates:
            return max(
                candidates,
                key=lambda item: float(item.get("confidence", report.get("pipeline_confidence", 0.0)) or 0.0),
            )
    return report


def build_user_summary(
    *,
    target: str,
    pipeline_report: Mapping[str, object],
    mapping_report: Optional[Mapping[str, object]] = None,
    parity_report_path: Optional[Path] = None,
    transform_profile_path: Optional[Path] = None,
    detection_report_path: Optional[Path] = None,
    default_version: str = "v14.4.2",
) -> UserSummary:
    """Construct a :class:`UserSummary` from pipeline artefacts."""

    candidate = _select_primary_candidate(pipeline_report)
    sequence = candidate.get("sequence")
    confidence = _ensure_percentage(candidate.get("confidence", pipeline_report.get("pipeline_confidence", 0.0)))
    version_hint = (
        candidate.get("version_hint")
        or pipeline_report.get("version_hint")
        or pipeline_report.get("version")
        or default_version
    )
    if not isinstance(version_hint, str):
        version_hint = default_version

    key_findings: list[str] = []
    formatted_sequence = _stringify_sequence(sequence if isinstance(sequence, Sequence) else [])
    key_findings.append(
        "Primary transform chain identified" if formatted_sequence != "<not yet determined>" else "Primary transform chain requires manual confirmation"
    )
    key_findings[-1] += f": {formatted_sequence} (confidence {confidence:.0%})."

    pipelines = pipeline_report.get("pipelines")
    if isinstance(pipelines, Sequence) and len(pipelines) > 1:
        key_findings.append(f"{len(pipelines)} pipeline candidates evaluated; tooling favours the v14.4.2-tuned option.")

    vm_style = pipeline_report.get("vm_style")
    if isinstance(vm_style, Mapping) and vm_style.get("style"):
        key_findings.append(
            f"VM style heuristic suggests a {vm_style['style']} virtual machine (confidence {float(vm_style.get('confidence', 0.0)):.0%})."
        )

    if isinstance(mapping_report, Mapping):
        mapping_files = mapping_report.get("mapping_files")
        total_tables = mapping_report.get("total_tables")
        if isinstance(mapping_files, Sequence) and mapping_files:
            key_findings.append(f"Opcode mapping produced {len(mapping_files)} candidate table(s) for inspection.")
        elif isinstance(total_tables, (int, float)) and total_tables > 0:
            key_findings.append("Permutation tables detected but no canonical opcode map saved yet.")

    parity_available = parity_report_path is not None and parity_report_path.exists()
    if parity_available:
        key_findings.append("Parity diagnostics are available for v14.4.2 PRGA presets (see parity report).")
    else:
        key_findings.append("Parity diagnostics have not been captured for this run.")

    if transform_profile_path is not None and transform_profile_path.exists():
        key_findings.append("A transform_profile.json snapshot was generated for reproducibility.")

    next_steps: list[str] = []
    if confidence < 0.75:
        next_steps.append(
            "Review the proposed transform chain against a known-good v14.4.2 sample; automated confidence is below 75%."
        )

    if not parity_available:
        next_steps.append(
            "Run the parity harness with the session key to confirm the PRGA stage matches the v14.4.2 reference implementation."
        )

    mapping_files = mapping_report.get("mapping_files") if isinstance(mapping_report, Mapping) else None
    if not mapping_files:
        next_steps.append(
            "Collect additional handler traces and update opcode mapping proposals for the v14.4.2 VM."  # emphasise manual action
        )

    unresolved_ops: Sequence[object] | None = None
    if isinstance(mapping_report, Mapping):
        unresolved_ops = mapping_report.get("unresolved_opcodes")  # type: ignore[assignment]
    if isinstance(unresolved_ops, Sequence) and unresolved_ops:
        formatted = ", ".join(f"0x{int(op):02X}" for op in unresolved_ops if isinstance(op, (int, float)))
        if formatted:
            next_steps.append(f"Assign mnemonics for unresolved opcodes ({formatted}) using the interactive mapping tools.")

    if transform_profile_path is None or not transform_profile_path.exists():
        next_steps.append("Export a transform profile once the pipeline is confirmed so future runs can skip rediscovery.")

    if not next_steps:
        next_steps.append("Share this summary with stakeholders and schedule final validation using decoded output.")

    outstanding: list[str] = []
    outstanding.extend(_collect_notes(candidate))
    if not outstanding and confidence < 0.9:
        outstanding.append("Confidence remains below 90%; keep monitoring pipeline heuristics.")

    references: list[str] = []
    if detection_report_path is not None:
        references.append(f"Detailed analysis: {detection_report_path}")
    if transform_profile_path is not None and transform_profile_path.exists():
        references.append(f"Transform profile: {transform_profile_path}")
    if isinstance(mapping_files, Sequence):
        for path in mapping_files[:3]:
            references.append(f"Opcode map candidate: {path}")
    if parity_available:
        references.append(f"Parity report: {parity_report_path}")

    return UserSummary(
        target=target,
        version_hint=version_hint,
        confidence=confidence,
        key_findings=tuple(key_findings),
        next_steps=tuple(next_steps),
        outstanding_items=tuple(outstanding),
        references=tuple(references),
    )


def write_user_summary(path: Path, summary: UserSummary) -> None:
    """Persist *summary* as Markdown to *path*."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(summary.render_markdown(), encoding="utf-8")
    LOGGER.info("Wrote user summary to %s", path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a non-technical summary for Luraph analysis outputs.",
    )
    parser.add_argument("--pipeline", type=Path, required=True, help="Path to pipeline_candidates.json")
    parser.add_argument("--mapping", type=Path, help="Optional mapping_candidates.json path")
    parser.add_argument("--parity-report", type=Path, help="Optional parity report (Markdown)")
    parser.add_argument("--transform-profile", type=Path, help="Optional transform_profile.json path")
    parser.add_argument("--detection-report", type=Path, help="Optional detailed detection report")
    parser.add_argument("--target", default="unknown payload", help="Friendly target name")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "user_report.md",
        help="Destination Markdown file (default: out/user_report.md)",
    )

    args = parser.parse_args(argv)

    pipeline = _load_json(args.pipeline)
    mapping = _load_json(args.mapping)
    summary = build_user_summary(
        target=str(args.target),
        pipeline_report=pipeline,
        mapping_report=mapping or None,
        parity_report_path=args.parity_report,
        transform_profile_path=args.transform_profile,
        detection_report_path=args.detection_report,
    )
    write_user_summary(args.output, summary)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
