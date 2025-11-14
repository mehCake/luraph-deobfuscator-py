"""Generate short run notes for sharing in chat tools.

The helper consumes artefacts produced by the detection pipeline and distils
them into a concise bullet list alongside three prioritised action items.  The
notes are designed for quick Slack or email updates and intentionally avoid any
session-key material.  The optional ``--copy`` flag performs a best-effort
clipboard copy for local use only.
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, MutableSequence, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "AutomatedNotes",
    "build_automated_notes",
    "write_notes",
    "main",
]


def _load_json(path: Optional[Path]) -> Mapping[str, object]:
    """Load *path* as JSON, returning an empty mapping when not available."""

    if path is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.debug("Automated notes input %s missing", path)
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
    LOGGER.warning(
        "Expected JSON object in %s but received %s", path, type(payload).__name__
    )
    return {}


def _load_text(path: Optional[Path]) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.debug("Text artefact %s missing", path)
        return ""
    except OSError as exc:  # pragma: no cover - defensive
        LOGGER.warning("Failed to read %s: %s", path, exc)
        return ""


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


def _stringify_sequence(sequence: Sequence[object]) -> str:
    tokens = [str(token) for token in sequence if token]
    return " → ".join(tokens) if tokens else "<no pipeline sequence>"


def _ensure_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _extract_recommendation_items(source: Mapping[str, object]) -> Tuple[str, ...]:
    ordered: list[str] = []
    for key in ("action_items", "items", "next_steps", "recommendations"):
        value = source.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            for item in value:
                text = str(item).strip()
                if text:
                    ordered.append(text)
    return tuple(ordered)


def _parse_markdown_actions(text: str) -> Tuple[str, ...]:
    capture = False
    items: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if lowered.startswith("## next steps"):
            capture = True
            continue
        if capture and lowered.startswith("## "):
            break
        if capture:
            if line.startswith("- ") or line.startswith("* "):
                items.append(line[2:].strip())
            elif line[:2].isdigit():  # handles "1. Do X"
                items.append(line.lstrip("0123456789. ").strip())
    if not items:
        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("- ["):
                items.append(stripped[stripped.find("]") + 1 :].strip())
    return tuple(item for item in items if item)


def _load_recommendation_items(path: Optional[Path]) -> Tuple[str, ...]:
    if path is None:
        return ()
    if path.suffix.lower() in {".json", ".js"}:
        data = _load_json(path)
        return _extract_recommendation_items(data)
    text = _load_text(path)
    return _parse_markdown_actions(text)


def _collect_hypothesis_notes(candidate: Mapping[str, object]) -> Tuple[str, ...]:
    hypothesis = candidate.get("hypothesis_score")
    if isinstance(hypothesis, Mapping):
        notes = hypothesis.get("notes")
        if isinstance(notes, Iterable) and not isinstance(notes, (str, bytes)):
            return tuple(str(note).strip() for note in notes if note)
    return ()


def _dedupe_preserve(items: Iterable[str]) -> Tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        token = item.strip()
        if not token:
            continue
        lowered = token.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(token)
    return tuple(ordered)


def _extract_summary_bullets(
    target: str,
    pipeline_report: Mapping[str, object],
    candidate: Mapping[str, object],
    parity_summary: Mapping[str, object],
    mapping_report: Mapping[str, object],
) -> Tuple[str, ...]:
    bullets: list[str] = []
    confidence = _ensure_float(
        candidate.get("confidence", pipeline_report.get("pipeline_confidence"))
    )
    sequence = candidate.get("sequence")
    if isinstance(sequence, Sequence):
        bullets.append(
            f"Pipeline confidence {confidence:.0%} for {target}: {_stringify_sequence(sequence)}"
        )
    else:
        bullets.append(f"Pipeline confidence {confidence:.0%} for {target}")

    version_hint = candidate.get("version_hint") or pipeline_report.get("version_hint")
    if isinstance(version_hint, str) and version_hint:
        bullets.append(f"Version hint: {version_hint}")

    chunk_count = len(pipeline_report.get("chunks", []) or [])
    if chunk_count:
        bullets.append(f"Analysed {chunk_count} bootstrap chunk(s)")

    parity_status = parity_summary.get("status") if parity_summary else None
    if isinstance(parity_status, str) and parity_status:
        bullets.append(f"Parity outcome: {parity_status}")

    mapping_files = mapping_report.get("mapping_files") if mapping_report else None
    if isinstance(mapping_files, Sequence) and mapping_files:
        bullets.append(f"Opcode maps reviewed: {len(mapping_files)} candidate(s)")

    return tuple(bullets[:4])  # keep the run summary concise


def _collect_action_items(
    candidate: Mapping[str, object],
    pipeline_report: Mapping[str, object],
    recommendation_items: Sequence[str],
    final_report_steps: Sequence[str],
) -> Tuple[str, ...]:
    actions: MutableSequence[str] = []
    actions.extend(str(step) for step in final_report_steps if step)
    actions.extend(_collect_hypothesis_notes(candidate))

    parity_summary = pipeline_report.get("parity_summary")
    if isinstance(parity_summary, Mapping):
        recommendations = parity_summary.get("recommendations")
        if isinstance(recommendations, Sequence) and not isinstance(
            recommendations, (str, bytes)
        ):
            actions.extend(str(item) for item in recommendations if item)
        status = parity_summary.get("status")
        if isinstance(status, str) and status.lower() == "mismatch":
            actions.append("Re-run parity harness with alternate rotate or XOR presets")

    ambiguous = pipeline_report.get("ambiguous_handlers")
    if isinstance(ambiguous, Sequence) and ambiguous:
        actions.append(
            f"Investigate {len(list(ambiguous))} ambiguous opcode handler(s) via sandbox tests"
        )

    actions.extend(recommendation_items)
    actions.extend(final_report_steps)

    deduped = list(_dedupe_preserve(actions))
    fallbacks = [
        "Confirm transform order against bootstrap expectations",
        "Validate opcode mappings with recorded traces",
        "Review suspicious I/O or trap handlers highlighted in reports",
    ]
    for item in fallbacks:
        if len(deduped) >= 3:
            break
        if item.lower() not in {entry.lower() for entry in deduped}:
            deduped.append(item)

    return tuple(deduped[:3])


def _copy_to_clipboard(text: str) -> bool:
    try:
        import pyperclip  # type: ignore
    except ImportError:  # pragma: no cover - optional dependency
        pyperclip = None
    if pyperclip is not None:
        try:
            pyperclip.copy(text)
            return True
        except Exception as exc:  # pragma: no cover - clipboard failure
            LOGGER.debug("pyperclip copy failed: %s", exc)

    commands = [
        ["pbcopy"],
        ["xclip", "-selection", "clipboard"],
        ["clip"],
    ]
    for command in commands:
        try:
            subprocess.run(command, input=text.encode("utf-8"), check=True)
        except FileNotFoundError:
            continue
        except subprocess.CalledProcessError as exc:  # pragma: no cover - defensive
            LOGGER.debug("Clipboard command %s failed: %s", command[0], exc)
            continue
        else:
            return True
    return False


@dataclass(frozen=True)
class AutomatedNotes:
    """Lightweight summary for quick status updates."""

    target: str
    summary_bullets: Tuple[str, ...]
    action_items: Tuple[str, ...]

    def render_text(self) -> str:
        lines = [f"Run summary for {self.target}:"]
        for bullet in self.summary_bullets:
            lines.append(f"• {bullet}")
        if not self.summary_bullets:
            lines.append("• No automated summary available")
        lines.append("")
        lines.append("Top action items:")
        if self.action_items:
            for index, item in enumerate(self.action_items, start=1):
                lines.append(f"{index}. {item}")
        else:
            lines.append("1. Review pipeline artefacts and plan follow-up analysis")
        return "\n".join(lines)


def build_automated_notes(
    *,
    target: str,
    pipeline_report: Mapping[str, object],
    mapping_report: Optional[Mapping[str, object]] = None,
    parity_summary: Optional[Mapping[str, object]] = None,
    recommendations: Sequence[str] = (),
    final_report_steps: Sequence[str] = (),
) -> AutomatedNotes:
    """Generate :class:`AutomatedNotes` from collected artefacts."""

    candidate = _select_candidate(pipeline_report)
    summary_bullets = _extract_summary_bullets(
        target,
        pipeline_report,
        candidate,
        parity_summary or {},
        mapping_report or {},
    )
    action_items = _collect_action_items(
        candidate,
        pipeline_report,
        recommendations,
        final_report_steps,
    )
    return AutomatedNotes(target=target, summary_bullets=summary_bullets, action_items=action_items)


def write_notes(destination: Path, notes: AutomatedNotes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(notes.render_text() + "\n", encoding="utf-8")


def _extract_next_steps_from_report(text: str) -> Tuple[str, ...]:
    if not text:
        return ()
    return _parse_markdown_actions(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pipeline", type=Path, required=True, help="Path to pipeline_candidates.json")
    parser.add_argument("--target", default="unknown target", help="Name of the analysed payload")
    parser.add_argument("--mapping", type=Path, help="Optional opcode mapping summary JSON")
    parser.add_argument("--parity", type=Path, help="Optional parity summary JSON")
    parser.add_argument("--recommendations", type=Path, help="Recommendation checklist (JSON or Markdown)")
    parser.add_argument("--final-report", type=Path, help="Final report Markdown for extracting next steps")
    parser.add_argument("--output", type=Path, help="Destination file for the generated notes")
    parser.add_argument("--copy", action="store_true", help="Copy the generated notes to the clipboard (best effort)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    pipeline_report = _load_json(args.pipeline)
    if not pipeline_report:
        LOGGER.error("Pipeline report %s is empty or missing", args.pipeline)
        return 1

    mapping_report = _load_json(args.mapping) if args.mapping else None
    parity_summary = _load_json(args.parity) if args.parity else None
    recommendations = _load_recommendation_items(args.recommendations)
    final_steps = _extract_next_steps_from_report(_load_text(args.final_report))

    notes = build_automated_notes(
        target=args.target,
        pipeline_report=pipeline_report,
        mapping_report=mapping_report,
        parity_summary=parity_summary,
        recommendations=recommendations,
        final_report_steps=final_steps,
    )

    rendered = notes.render_text()
    if args.output:
        write_notes(args.output, notes)
    else:
        print(rendered)

    if args.copy and rendered:
        if not _copy_to_clipboard(rendered):
            LOGGER.warning("Clipboard copy unavailable on this system")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
