"""Generate manual review checklists from pipeline artefacts.

The checklist highlights follow-up actions for analysts after the automated
pipeline has produced structured artefacts.  No payload code is executed and the
module purposefully ignores any fields that may contain session keys.  The
output is a concise Markdown checklist aimed at human reviewers.
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
    "RecommendationChecklist",
    "build_recommendation_checklist",
    "write_recommendation_markdown",
    "main",
]


def _load_json(path: Optional[Path]) -> Mapping[str, object]:
    """Return a JSON mapping from *path* or an empty mapping when missing."""

    if path is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.debug("Recommendation input %s missing", path)
        return {}
    except OSError as exc:  # pragma: no cover - defensive
        LOGGER.warning("Failed to read %s: %s", path, exc)
        return {}

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Failed to decode JSON from %s: %s", path, exc)
        return {}

    if isinstance(payload, Mapping):
        return payload
    LOGGER.warning("Expected JSON object in %s, received %s", path, type(payload).__name__)
    return {}


def _select_candidate(report: Mapping[str, object]) -> Mapping[str, object]:
    pipelines = report.get("pipelines")
    if isinstance(pipelines, Sequence):
        candidates = [entry for entry in pipelines if isinstance(entry, Mapping)]
        if candidates:
            return max(
                candidates,
                key=lambda item: float(item.get("confidence", 0.0) or 0.0),
            )
    return report


def _dedupe_preserve(items: Iterable[str]) -> Tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if not item:
            continue
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return tuple(ordered)


def _format_opcode_list(opcodes: Sequence[int]) -> str:
    tokens = [f"0x{value:02X}" for value in opcodes]
    return ", ".join(tokens)


def _collect_chunk_hints(report: Mapping[str, object]) -> Tuple[Tuple[str, ...], bool]:
    hints: list[str] = []
    trap_detected = False
    chunks = report.get("chunks")
    if isinstance(chunks, Sequence):
        for chunk in chunks:
            if not isinstance(chunk, Mapping):
                continue
            chunk_hints = chunk.get("hints")
            if isinstance(chunk_hints, Sequence):
                for hint in chunk_hints:
                    if not isinstance(hint, str):
                        continue
                    lowered = hint.lower()
                    hints.append(lowered)
                    if "trap" in lowered:
                        trap_detected = True
            handler_map = chunk.get("handler_map")
            if isinstance(handler_map, Sequence):
                for handler in handler_map:
                    if not isinstance(handler, Mapping):
                        continue
                    body = handler.get("body")
                    if isinstance(body, str) and "trap" in body.lower():
                        trap_detected = True
    return tuple(hints), trap_detected


@dataclass(frozen=True)
class RecommendationChecklist:
    """Checklist rendered for analysts overseeing the pipeline."""

    target: str
    version_hint: str
    items: Tuple[str, ...]
    context_notes: Tuple[str, ...]

    def render_markdown(self) -> str:
        lines = ["# Manual Review Checklist", ""]
        lines.append(f"**Target:** {self.target}")
        lines.append(f"**Version focus:** {self.version_hint or 'unknown'}")
        lines.append("")
        lines.append("## Checklist")
        if self.items:
            lines.extend(f"- [ ] {item}" for item in self.items)
        else:
            lines.append("- [ ] Review pipeline artefacts; no automated hints available.")
        if self.context_notes:
            lines.append("")
            lines.append("## Context Notes")
            lines.extend(f"* {note}" for note in self.context_notes)
        lines.append("")
        lines.append(
            "_Checklist generated without storing session keys; remove this file after review if it contains sensitive data._"
        )
        lines.append("")
        return "\n".join(lines)


def build_recommendation_checklist(
    *,
    target: str,
    pipeline_report: Mapping[str, object],
    mapping_report: Optional[Mapping[str, object]] = None,
    parity_summary: Optional[Mapping[str, object]] = None,
    default_version: str = "v14.4.2",
) -> RecommendationChecklist:
    """Derive actionable review steps from pipeline artefacts."""

    candidate = _select_candidate(pipeline_report)
    sequence = [str(step) for step in candidate.get("sequence", []) if step]
    version_hint = str(candidate.get("version_hint") or pipeline_report.get("version_hint") or default_version)

    checklist: list[str] = []
    notes: list[str] = []

    if sequence:
        checklist.append(
            f"Confirm pipeline sequence {' → '.join(sequence)} against manual expectations."
        )

    chunk_hints, trap_detected = _collect_chunk_hints(pipeline_report)
    hint_set = set(chunk_hints)

    if any(step in {"string-escape", "string.char"} for step in sequence) or "string.char" in hint_set:
        checklist.append("Inspect extracted strings to ensure no encrypted payloads remain.")

    if "perm-array" in hint_set or (mapping_report and int(mapping_report.get("total_tables", 0) or 0) > 0):
        checklist.append("Validate permutation tables and confirm they match expected VM ordering.")

    if "xor-loop" in hint_set or "xor" in sequence:
        checklist.append("Review XOR/PRGA stages for leftover obfuscation or incorrect rotate amounts.")

    if trap_detected:
        checklist.append("Review trap/opaque handler blocks and ensure they are isolated before lifting.")

    checksum_summary = pipeline_report.get("checksum_summary")
    if isinstance(checksum_summary, Mapping):
        invalid = int(checksum_summary.get("invalid", 0) or 0)
        if invalid > 0:
            checklist.append("Recalculate checksum fields for extracted payloads; tooling flagged mismatches.")

    byte_candidates = pipeline_report.get("byte_candidates")
    if isinstance(byte_candidates, Sequence) and any(
        isinstance(entry, Mapping) and entry.get("endianness_hint") not in {None, "unknown"}
        for entry in byte_candidates
    ):
        checklist.append("Double-check decoded byte payload endianness against bootstrap expectations.")

    opcode_handlers = pipeline_report.get("opcode_handlers")
    if isinstance(opcode_handlers, Mapping) and opcode_handlers:
        try:
            opcode_ids = sorted({int(key) for key in opcode_handlers.keys()})
        except Exception:  # pragma: no cover - defensive
            opcode_ids = []
        if opcode_ids:
            formatted = _format_opcode_list(opcode_ids[:8])
            checklist.append(
                f"Verify opcode mapping for opcodes [{formatted}] using handler traces and lifter output."
            )
        else:
            checklist.append("Review opcode handler assignments to ensure mnemonic mapping is accurate.")

    if mapping_report:
        mapping_files = mapping_report.get("mapping_files")
        if isinstance(mapping_files, Sequence) and mapping_files:
            notes.append(
                "Mapping artefacts available: "
                + ", ".join(str(Path(path)) for path in mapping_files[:5])
            )

    hypothesis = candidate.get("hypothesis_score")
    if isinstance(hypothesis, Mapping):
        hypothesis_notes = hypothesis.get("notes")
        if isinstance(hypothesis_notes, Iterable) and not isinstance(hypothesis_notes, (str, bytes)):
            for entry in hypothesis_notes:
                if entry:
                    notes.append(str(entry))

    if parity_summary and isinstance(parity_summary, Mapping):
        status = str(parity_summary.get("status") or "unknown")
        if status.lower() != "match":
            checklist.append("Investigate PRGA parity mismatches and apply suggested parameter tweaks.")
        recommendations = parity_summary.get("recommendations")
        if isinstance(recommendations, Sequence):
            for rec in recommendations:
                if rec:
                    notes.append(str(rec))

    if version_hint.startswith("v14.4.2"):
        if "prga" in sequence:
            checklist.append("Confirm v14.4.2 PRGA rotate amounts (11/13-bit) and XOR seeds match expectations.")
        if any(step in {"vm_unpack", "vm_dispatch"} for step in sequence) or "dispatcher-cfg" in hint_set:
            checklist.append("Cross-check dispatcher CFG against known v14.4.2 handler ordering.")
        if "permute" in sequence or "perm-array" in hint_set:
            checklist.append("Ensure permutation tables cover 0x100/0x200 entries typical of v14.4.2.")

    return RecommendationChecklist(
        target=target,
        version_hint=version_hint,
        items=_dedupe_preserve(checklist),
        context_notes=_dedupe_preserve(notes),
    )


def write_recommendation_markdown(destination: Path, checklist: RecommendationChecklist) -> Path:
    """Persist *checklist* to *destination* as Markdown."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(checklist.render_markdown(), encoding="utf-8")
    LOGGER.info("Wrote recommendation checklist to %s", destination)
    return destination


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a manual-review checklist from pipeline artefacts",
    )
    parser.add_argument(
        "--pipeline",
        type=Path,
        default=Path("out") / "pipeline_candidates.json",
        help="Pipeline candidates JSON file",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path("out") / "mapping_candidates.json",
        help="Mapping candidate report (optional)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "recommendations.md",
        help="Destination Markdown file",
    )
    parser.add_argument(
        "--target",
        type=str,
        default="unknown",
        help="Name of the analysed payload",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="v14.4.2",
        help="Fallback version hint when the pipeline report omits one",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    pipeline_payload = _load_json(args.pipeline)
    mapping_payload = _load_json(args.mapping)
    parity_summary = pipeline_payload.get("parity_summary")
    if not isinstance(parity_summary, Mapping):
        parity_summary = None

    checklist = build_recommendation_checklist(
        target=args.target,
        pipeline_report=pipeline_payload,
        mapping_report=mapping_payload,
        parity_summary=parity_summary,
        default_version=args.version,
    )
    write_recommendation_markdown(args.output, checklist)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

