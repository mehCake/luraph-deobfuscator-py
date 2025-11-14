"""Aggregate pipeline artefacts into a human-readable final report.

The helpers in this module operate on the static JSON artefacts produced by
the detection pipeline (loader, bootstrap extractor, opcode proposer, …).
They never execute payload code and avoid persisting sensitive material such as
session keys.  Analysts can use the generated Markdown summary to understand
the current decoding progress and identify the remaining manual work.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "PipelineProfile",
    "OpcodeSummary",
    "FinalReport",
    "build_final_report",
    "write_final_report",
    "main",
]


def _load_json(path: Path) -> Mapping[str, object]:
    """Safely load *path* and return an empty mapping on failure."""

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.debug("JSON artefact %s not found", path)
        return {}
    except OSError as exc:  # pragma: no cover - filesystem edge case
        LOGGER.warning("Failed to read %s: %s", path, exc)
        return {}

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Failed to parse JSON from %s: %s", path, exc)
        return {}

    if isinstance(payload, Mapping):
        return payload
    LOGGER.warning("Expected a JSON object in %s; got %s", path, type(payload).__name__)
    return {}
@dataclass(frozen=True)
class PipelineProfile:
    """Snapshot of a pipeline candidate sequence."""

    sequence: Tuple[str, ...]
    confidence: float
    version_hint: Optional[str]
    hints: Tuple[str, ...]
    preferred_presets: Tuple[str, ...]
    confidence_breakdown: Mapping[str, float]

    def formatted_sequence(self, separator: str = " → ") -> str:
        return separator.join(self.sequence) if self.sequence else "<unknown>"


@dataclass(frozen=True)
class OpcodeSummary:
    """Description of the best opcode map candidate."""

    confidence: float
    mapping: Mapping[int, str]
    unresolved: Tuple[int, ...]
    preview: Tuple[str, ...]


@dataclass(frozen=True)
class FinalReport:
    """Aggregated view over pipeline, opcode, and reproduction data."""

    pipeline: PipelineProfile
    prga_presets: Tuple[str, ...]
    opcode_summary: Optional[OpcodeSummary]
    reproduction_steps: Tuple[str, ...]
    risk_flags: Tuple[str, ...]
    recommendations: Tuple[str, ...]
    ambiguous_notes: Tuple[str, ...] = ()

    def render_markdown(self) -> str:
        lines = ["# Final Analysis Report", ""]

        lines.append("## Pipeline Profile")
        lines.append(f"* **Sequence:** `{self.pipeline.formatted_sequence()}`")
        lines.append(f"* **Confidence:** {self.pipeline.confidence:.2f}")
        version_hint = self.pipeline.version_hint or "unknown"
        lines.append(f"* **Version hint:** {version_hint}")
        if self.pipeline.hints:
            lines.append("* **Pipeline hints:** " + ", ".join(self.pipeline.hints))
        if self.pipeline.preferred_presets:
            lines.append("* **Preferred presets:** " + ", ".join(self.pipeline.preferred_presets))
        if self.pipeline.confidence_breakdown:
            breakdown = ", ".join(
                f"{key}={value:.2f}" for key, value in self.pipeline.confidence_breakdown.items()
            )
            lines.append(f"* **Confidence breakdown:** {breakdown}")
        lines.append("")

        lines.append("## PRGA Parameters Evaluated")
        if self.prga_presets:
            for preset in self.prga_presets:
                lines.append(f"* {preset}")
        else:
            lines.append("* No PRGA presets recorded in pipeline artefacts.")
        lines.append("")

        lines.append("## Opcode Mapping Summary")
        if self.opcode_summary is None:
            lines.append("No opcode map candidates available; collect handler data for mapping analysis.")
        else:
            lines.append(f"* **Best candidate confidence:** {self.opcode_summary.confidence:.2f}")
            if self.opcode_summary.preview:
                lines.append("* **Preview:** " + ", ".join(self.opcode_summary.preview))
            if self.opcode_summary.unresolved:
                formatted = ", ".join(f"0x{opcode:02X}" for opcode in self.opcode_summary.unresolved)
                lines.append(f"* **Unresolved opcodes:** {formatted}")
            else:
                lines.append("* **Unresolved opcodes:** none detected")
        lines.append("")

        lines.append("## Steps to Reproduce Transformation")
        for index, step in enumerate(self.reproduction_steps, start=1):
            lines.append(f"{index}. {step}")
        lines.append("")

        lines.append("## Risk Flags")
        if self.risk_flags:
            for flag in self.risk_flags:
                lines.append(f"* {flag}")
        else:
            lines.append("* No outstanding risk flags detected.")
        lines.append("")

        lines.append("## Luraph v14.4.2 Recommendations")
        if self.recommendations:
            for recommendation in self.recommendations:
                lines.append(f"* {recommendation}")
        else:
            lines.append("* No additional recommendations beyond standard pipeline execution.")
        lines.append("")

        lines.append("## Ambiguous Analysis Items")
        if self.ambiguous_notes:
            for note in self.ambiguous_notes:
                lines.append(f"* {note}")
        else:
            lines.append("* No ambiguous opcodes or IR regions detected.")
        lines.append("")

        return "\n".join(lines)


def _select_pipeline_profile(report: Mapping[str, object]) -> PipelineProfile:
    pipelines = report.get("pipelines")
    candidate_entries: Sequence[Mapping[str, object]]
    if isinstance(pipelines, Sequence):
        candidate_entries = [entry for entry in pipelines if isinstance(entry, Mapping)]
    else:
        candidate_entries = []

    selected: Mapping[str, object] | None = None
    if candidate_entries:
        selected = max(
            candidate_entries,
            key=lambda item: float(item.get("confidence", report.get("pipeline_confidence", 0.0))),
        )

    if selected is None:
        sequence = tuple(str(step) for step in report.get("pipeline", []) if step)
        confidence = float(report.get("pipeline_confidence", 0.0))
        version_hint = report.get("version_hint")
        hints = tuple(str(item) for item in report.get("pipeline_hints", []) if item)
        preferred = ()
        breakdown: Mapping[str, float] = {}
    else:
        sequence = tuple(str(step) for step in selected.get("sequence", []) if step)
        confidence = float(selected.get("confidence", report.get("pipeline_confidence", 0.0)))
        version_hint = selected.get("version_hint") or report.get("version_hint")
        hints = tuple(str(item) for item in report.get("pipeline_hints", []) if item)
        preferred = tuple(str(item) for item in selected.get("preferred_presets", []) if item)
        breakdown_raw = selected.get("confidence_breakdown")
        if isinstance(breakdown_raw, Mapping):
            breakdown = {str(key): float(value) for key, value in breakdown_raw.items()}
        else:
            breakdown = {}

    return PipelineProfile(
        sequence=sequence,
        confidence=confidence,
        version_hint=str(version_hint) if version_hint else None,
        hints=hints,
        preferred_presets=preferred,
        confidence_breakdown=breakdown,
    )


def _extract_prga_presets(profile: PipelineProfile) -> Tuple[str, ...]:
    presets = list(profile.preferred_presets)
    if not presets and profile.version_hint and profile.version_hint.startswith("v14.4.2"):
        presets.append("v14.4.2-default (inferred)")
    seen = set()
    ordered: list[str] = []
    for preset in presets:
        if preset not in seen:
            ordered.append(preset)
            seen.add(preset)
    return tuple(ordered)


def _normalise_mapping(mapping: Mapping[str, object] | Mapping[int, object]) -> Dict[int, str]:
    normalised: Dict[int, str] = {}
    for key, value in mapping.items():
        mnemonic = str(value)
        try:
            opcode = int(key)
        except (TypeError, ValueError):
            try:
                opcode = int(str(key), 0)
            except ValueError:
                continue
        normalised[opcode] = mnemonic
    return normalised


def _summarise_opcode_candidates(
    report: Mapping[str, object], proposals: Mapping[str, object]
) -> Tuple[Optional[OpcodeSummary], Tuple[str, ...]]:
    """Return opcode summary and associated risk flags."""

    candidate_payloads: Sequence[Mapping[str, object]] = ()
    raw_candidates = report.get("opcode_map_candidates")
    if isinstance(raw_candidates, Sequence):
        candidate_payloads = [entry for entry in raw_candidates if isinstance(entry, Mapping)]
    if not candidate_payloads:
        alt_candidates = proposals.get("candidates")
        if isinstance(alt_candidates, Sequence):
            candidate_payloads = [entry for entry in alt_candidates if isinstance(entry, Mapping)]

    if not candidate_payloads:
        return None, ("No opcode map candidates available; rerun handler analysis for opcode mapping.",)

    best = max(candidate_payloads, key=lambda item: float(item.get("confidence", 0.0)))
    confidence = float(best.get("confidence", 0.0))
    mapping_raw = best.get("mapping")
    mapping = _normalise_mapping(mapping_raw) if isinstance(mapping_raw, Mapping) else {}

    selections = best.get("selections")
    preview: list[str] = []
    if isinstance(selections, Mapping):
        try:
            sorted_keys = sorted(mapping.keys())
        except TypeError:  # pragma: no cover - numeric sort failure
            sorted_keys = list(mapping.keys())
        for opcode in sorted_keys[: min(len(sorted_keys), 6)]:
            mnemonic = mapping[opcode]
            preview.append(f"0x{opcode:02X}→{mnemonic}")

    handler_keys: set[int] = set()
    handler_payload = report.get("opcode_handlers")
    if isinstance(handler_payload, Mapping):
        for key in handler_payload.keys():
            try:
                handler_keys.add(int(key))
            except (TypeError, ValueError):
                try:
                    handler_keys.add(int(str(key), 0))
                except ValueError:
                    continue

    unresolved = tuple(sorted(handler_keys - set(mapping.keys())))
    risks: list[str] = []
    if unresolved:
        formatted = ", ".join(f"0x{opcode:02X}" for opcode in unresolved)
        risks.append(f"Opcode map incomplete; unresolved opcodes: {formatted}")
    if confidence < 0.6:
        risks.append("Top opcode candidate confidence below 0.60; expect manual verification.")

    summary = OpcodeSummary(
        confidence=confidence,
        mapping=mapping,
        unresolved=unresolved,
        preview=tuple(preview),
    )
    return summary, tuple(risks)


def _build_reproduction_steps(output_dir: Path, target: Optional[Path]) -> Tuple[str, ...]:
    base = output_dir.resolve()
    placeholder = str(target.resolve()) if target else "<path/to/Obfuscated.lua>"
    steps = [
        f"python -m src.io.loader {placeholder} --out-dir {base}",
        f"python -m src.bootstrap.extract_bootstrap --manifest {base / 'raw_manifest.json'} --output {base / 'bootstrap_candidates.json'}",
        f"python -m src.tools.byte_extractor --candidates {base / 'bootstrap_candidates.json'} --output-dir {base / 'bytes'}",
        f"python -m src.tools.collector --chunks {base / 'bootstrap_candidates.json'} --manifest {base / 'raw_manifest.json'} --bytes-meta {base / 'bytes' / 'meta.json'} --output {base / 'pipeline_candidates.json'}",
        f"python -m src.vm.opcode_proposer --handlers {base / 'handler_suggestions.json'} --disasm {base / 'disasm.json'} --output {base / 'opcode_proposals.json'}",
        f"python -m src.tools.run_all_detection --file {placeholder} --output-dir {base}",
    ]
    return tuple(steps)


def _collect_risks(
    profile: PipelineProfile,
    opcode_summary: Optional[OpcodeSummary],
    opcode_risks: Sequence[str],
) -> Tuple[str, ...]:
    risks: list[str] = list(opcode_risks)
    if profile.confidence < 0.65:
        risks.append(
            "Pipeline confidence below 0.65; confirm extraction heuristics before proceeding."
        )
    if profile.version_hint and profile.version_hint.startswith("v14.4.2"):
        if "prga" not in {step.lower() for step in profile.sequence}:
            risks.append("Pipeline sequence lacks PRGA stage despite v14.4.2 hint.")
        if opcode_summary is None:
            risks.append("No opcode mapping candidate available for v14.4.2 analysis.")
    return tuple(dict.fromkeys(risks))


def _build_recommendations(
    profile: PipelineProfile,
    prga_presets: Sequence[str],
    opcode_summary: Optional[OpcodeSummary],
) -> Tuple[str, ...]:
    recommendations: list[str] = []

    if profile.version_hint and profile.version_hint.startswith("v14.4.2"):
        if not any("v14.4.2" in preset for preset in prga_presets):
            recommendations.append(
                "Prioritise testing the v14.4.2-default PRGA preset; it matches observed payloads."
            )
        else:
            recommendations.append(
                "Retain v14.4.2-default PRGA parameters for regression tracking."
            )
        if opcode_summary and opcode_summary.unresolved:
            recommendations.append(
                "Cross-reference unresolved opcodes with handler traces before lifting VM bytecode."
            )
    if not recommendations and opcode_summary and opcode_summary.unresolved:
        recommendations.append(
            "Review handler suggestions for unresolved opcodes to improve decompilation fidelity."
        )
    return tuple(dict.fromkeys(recommendations))


def _load_ambiguous_summary(
    explicit_path: Optional[Path], output_dir: Optional[Path]
) -> Tuple[str, ...]:
    candidate_paths: Tuple[Path, ...] = ()
    if explicit_path:
        candidate_paths += (explicit_path,)
    if output_dir:
        candidate_paths += (
            output_dir / "ambiguous.json",
            output_dir / "ambiguous_summary.json",
        )

    for path in candidate_paths:
        if path is None or not path.exists():
            continue
        payload = _load_json(path)
        if not payload:
            continue
        summary = payload.get("summary")
        if isinstance(summary, Sequence):
            notes = [str(item) for item in summary if item]
            if notes:
                return tuple(notes)
    return ()


def build_final_report(
    pipeline_path: Path,
    *,
    proposals_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    target: Optional[Path] = None,
    ambiguous_path: Optional[Path] = None,
) -> FinalReport:
    """Load artefacts and create a :class:`FinalReport` instance."""

    report_payload = _load_json(pipeline_path)
    if not report_payload:
        raise FileNotFoundError(f"Pipeline report not found or empty: {pipeline_path}")

    proposals_payload: Mapping[str, object] = {}
    if proposals_path is not None:
        proposals_payload = _load_json(proposals_path)

    profile = _select_pipeline_profile(report_payload)
    prga_presets = _extract_prga_presets(profile)
    opcode_summary, opcode_risks = _summarise_opcode_candidates(report_payload, proposals_payload)
    base_dir = output_dir or pipeline_path.parent
    reproduction_steps = _build_reproduction_steps(base_dir, target)
    risk_flags = _collect_risks(profile, opcode_summary, opcode_risks)
    recommendations = _build_recommendations(profile, prga_presets, opcode_summary)
    ambiguous_notes = _load_ambiguous_summary(ambiguous_path, output_dir)

    return FinalReport(
        pipeline=profile,
        prga_presets=prga_presets,
        opcode_summary=opcode_summary,
        reproduction_steps=reproduction_steps,
        risk_flags=risk_flags,
        recommendations=recommendations,
        ambiguous_notes=ambiguous_notes,
    )


def write_final_report(report: FinalReport, destination: Path) -> Path:
    """Write *report* to *destination* as Markdown."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report.render_markdown(), encoding="utf-8")
    LOGGER.info("Wrote final report to %s", destination)
    return destination


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate consolidated analysis report")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out"),
        help="Directory containing pipeline artefacts",
    )
    parser.add_argument(
        "--pipeline",
        type=Path,
        default=None,
        help="Pipeline candidates JSON (defaults to <output-dir>/pipeline_candidates.json)",
    )
    parser.add_argument(
        "--proposals",
        type=Path,
        default=None,
        help="Opcode proposals JSON (optional)",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=None,
        help="Optional original Lua payload path for reproduction notes",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Destination Markdown file (defaults to <output-dir>/final_report.md)",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    pipeline_path = args.pipeline or args.output_dir / "pipeline_candidates.json"
    proposals_path = args.proposals or args.output_dir / "opcode_proposals.json"
    output_path = args.output or args.output_dir / "final_report.md"

    try:
        report = build_final_report(
            pipeline_path,
            proposals_path=proposals_path,
            output_dir=args.output_dir,
            target=args.target,
        )
    except FileNotFoundError as exc:
        LOGGER.error(str(exc))
        return 1

    write_final_report(report, output_path)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
