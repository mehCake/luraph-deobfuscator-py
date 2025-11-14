"""Graphviz exporter for pipeline candidate summaries.

This module renders Graphviz diagrams (and SVG fallbacks) for pipeline
sequences discovered by :mod:`src.tools.collector`.  It preserves the
original lightweight DOT renderer but now understands richer pipeline
metadata, version hints, and candidate parameter summaries.  A CLI is
provided to turn ``pipeline_candidates.json`` files into annotated SVG
artefacts stored beneath ``out/graphs``.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List, Mapping, MutableSequence, Optional, Sequence, Tuple

from .hypothesis_scoring import score_pipeline_hypothesis

LOGGER = logging.getLogger(__name__)

__all__ = [
    "classify_operation",
    "render_pipeline_graph",
    "generate_pipeline_graphs",
    "load_pipeline_report",
]

_STEP_STYLES: Mapping[str, Tuple[str, str]] = {
    "bootstrap": ("#ff7f0e", "white"),
    "PRGA": ("#1f77b4", "white"),
    "permute": ("#2ca02c", "white"),
    "xor": ("#d62728", "white"),
    "vm_unpack": ("#9467bd", "white"),
    "dispatcher": ("#17becf", "white"),
    "handlers": ("#bcbd22", "black"),
    "endianness": ("#8c564b", "white"),
    "other": ("#7f7f7f", "white"),
}


def classify_operation(operation: str) -> str:
    """Map a raw operation string to a canonical pipeline step."""

    lower = operation.lower()
    if any(token in lower for token in ("loadstring", "load", "string-escape", "string.char", "numeric-array")):
        return "bootstrap"
    if "prga" in lower:
        return "PRGA"
    if "perm" in lower:
        return "permute"
    if "xor" in lower or "bxor" in lower:
        return "xor"
    if "vm" in lower and "unpack" in lower:
        return "vm_unpack"
    if "dispatch" in lower:
        return "dispatcher"
    if "handler" in lower:
        return "handlers"
    if lower.startswith("endianness:"):
        return "endianness"
    return "other"


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\"", "\\\"")


def _iter_steps(pipeline: Sequence[str]) -> Iterable[Tuple[str, str]]:
    for operation in pipeline:
        if not isinstance(operation, str):
            continue
        step = classify_operation(operation)
        yield step, operation


def render_pipeline_graph(
    pipeline: Sequence[str],
    *,
    title: Optional[str] = None,
    version_hint: Optional[str] = None,
    confidence: Optional[float] = None,
    preferred_presets: Optional[Sequence[str]] = None,
    annotations: Optional[Sequence[str]] = None,
) -> str:
    """Render a Graphviz DOT graph for the pipeline sequence.

    Additional metadata is rendered as a Graphviz label at the top of the
    diagram.  Sensitive information such as explicit keys is filtered from
    the annotation block.
    """

    lines: List[str] = [
        "digraph pipeline {",
        "  rankdir=LR;",
        "  node [shape=box, style=filled, fontname=Helvetica, fontsize=12];",
    ]

    label_lines: MutableSequence[str] = []
    if title:
        label_lines.append(str(title))
    if version_hint:
        label_lines.append(f"Version: {version_hint}")
    if confidence is not None:
        label_lines.append(f"Confidence: {confidence:.2f}")
    if preferred_presets:
        preset_preview = ", ".join(preferred_presets[:3])
        label_lines.append(f"Presets: {preset_preview}")
    if annotations:
        for note in annotations:
            if not isinstance(note, str):
                continue
            if "key" in note.lower():
                continue
            label_lines.append(note)

    if label_lines:
        escaped = "\\n".join(_escape(line) for line in label_lines)
        lines.append("  labelloc=\"t\";")
        lines.append("  fontsize=14;")
        lines.append(f"  label=\"{escaped}\";")

    steps = list(_iter_steps(pipeline))
    if not steps:
        lines.append("  // No pipeline steps available")
        lines.append("}")
        return "\n".join(lines) + "\n"

    for index, (step, operation) in enumerate(steps):
        fill, font_color = _STEP_STYLES.get(step, _STEP_STYLES["other"])
        node_id = f"step{index}"
        label = step
        tooltip = operation
        lines.append(
            f"  {node_id} [label=\"{_escape(label)}\", tooltip=\"{_escape(tooltip)}\", fillcolor=\"{fill}\", fontcolor=\"{font_color}\"];"
        )
        if index > 0:
            lines.append(f"  step{index - 1} -> {node_id};")

    lines.append("}")
    return "\n".join(lines) + "\n"


def _normalise_pipeline(payload: Mapping[str, object]) -> Sequence[str]:
    pipeline = payload.get("pipeline")
    if isinstance(pipeline, Sequence):
        return [str(step) for step in pipeline]
    chunks = payload.get("chunks")
    if isinstance(chunks, Sequence):
        operations: List[str] = []
        for chunk in chunks:
            if isinstance(chunk, Mapping):
                ops = chunk.get("operations")
                if isinstance(ops, Sequence):
                    operations.extend(str(op) for op in ops)
        return operations
    raise KeyError("Unable to locate pipeline sequence in payload")


def load_pipeline_report(path: Path) -> Mapping[str, object]:
    """Load a pipeline report from ``path`` and validate the payload."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("Pipeline file must contain a JSON object")
    return payload


def _slugify(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-")
    return cleaned or "candidate"


def _candidate_slug(index: int, candidate: Mapping[str, object]) -> str:
    for key in ("name", "version_hint"):
        value = candidate.get(key)
        if isinstance(value, str) and value.strip():
            return _slugify(value)
    presets = candidate.get("preferred_presets")
    if isinstance(presets, Sequence) and presets:
        first = str(presets[0])
        if first:
            return _slugify(first)
    return f"candidate-{index:02d}"


def _collect_annotations(candidate: Mapping[str, object]) -> List[str]:
    notes: List[str] = []
    confidence_breakdown = candidate.get("confidence_breakdown")
    if isinstance(confidence_breakdown, Mapping):
        for key, value in sorted(confidence_breakdown.items()):
            try:
                notes.append(f"{key}: {float(value):.3f}")
            except (TypeError, ValueError):
                notes.append(f"{key}: {value}")
    parameters = candidate.get("parameters")
    if isinstance(parameters, Mapping):
        for key, value in sorted(parameters.items()):
            if "key" in str(key).lower():
                continue
            notes.append(f"{key}={value}")
    hints = candidate.get("hints") or candidate.get("pipeline_hints")
    if isinstance(hints, Sequence):
        for hint in hints:
            if isinstance(hint, str):
                notes.append(hint)
    hypothesis = candidate.get("hypothesis_score")
    if isinstance(hypothesis, Mapping):
        components = hypothesis.get("components")
        if isinstance(components, Mapping) and components:
            parts: List[str] = []
            for key, value in sorted(components.items()):
                try:
                    parts.append(f"{key}:{float(value):.2f}")
                except (TypeError, ValueError):
                    parts.append(f"{key}:{value}")
            if parts:
                notes.append("Hypothesis components " + ", ".join(parts))
        hypothesis_notes = hypothesis.get("notes")
        if isinstance(hypothesis_notes, Sequence):
            for note in hypothesis_notes:
                if isinstance(note, str) and note:
                    notes.append(note)
    return notes


def _try_render_with_graphviz(dot: str, destination: Path) -> bool:
    try:
        from graphviz import Source  # type: ignore
    except Exception:  # pragma: no cover - optional dependency
        Source = None

    if Source is not None:
        try:
            svg_bytes = Source(dot).pipe(format="svg")
        except Exception as exc:  # pragma: no cover - runtime error
            LOGGER.debug("Graphviz.Source render failed: %s", exc)
        else:
            destination.write_bytes(svg_bytes)
            return True

    dot_exec = shutil.which("dot")
    if dot_exec:
        try:
            proc = subprocess.run(
                [dot_exec, "-Tsvg"],
                input=dot.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - environment specific
            LOGGER.debug("dot command failed: %s", exc)
        else:
            destination.write_bytes(proc.stdout)
            return True
    return False


def _fallback_svg(
    steps: Sequence[Tuple[str, str]],
    *,
    title: Optional[str],
    annotations: Sequence[str],
) -> str:
    width_per_step = 150
    height = 140
    padding = 20
    header_height = 0
    header_lines: List[str] = []
    if title:
        header_lines.append(title)
    for note in annotations:
        if "key" in note.lower():
            continue
        header_lines.append(note)
    if header_lines:
        header_height = 40 + 14 * (len(header_lines) - 1)
    total_width = max(200, padding * 2 + width_per_step * max(1, len(steps)))
    total_height = height + header_height

    elements: List[str] = [
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{total_width}' height='{total_height}' viewBox='0 0 {total_width} {total_height}'>",
    ]
    y_offset = 20
    if header_lines:
        for idx, line in enumerate(header_lines):
            elements.append(
                f"  <text x='{total_width/2:.1f}' y='{y_offset + idx * 16:.1f}' font-family='Helvetica' font-size='14' text-anchor='middle'>{_escape(line)}</text>"
            )
        y_offset += header_height - 20

    box_y = y_offset
    for index, (step, operation) in enumerate(steps):
        x = padding + index * width_per_step
        fill, font = _STEP_STYLES.get(step, _STEP_STYLES["other"])
        elements.append(
            f"  <rect x='{x}' y='{box_y}' width='{width_per_step - 20}' height='60' rx='8' ry='8' fill='{fill}' stroke='#333333'/>"
        )
        elements.append(
            f"  <text x='{x + (width_per_step - 20)/2:.1f}' y='{box_y + 28}' font-family='Helvetica' font-size='14' text-anchor='middle' fill='{font}'>{_escape(step)}</text>"
        )
        elements.append(
            f"  <text x='{x + (width_per_step - 20)/2:.1f}' y='{box_y + 46}' font-family='Helvetica' font-size='10' text-anchor='middle' fill='{font}'>{_escape(operation[:32])}</text>"
        )
        if index > 0:
            prev_x = padding + (index - 1) * width_per_step + (width_per_step - 20)
            elements.append(
                f"  <line x1='{prev_x}' y1='{box_y + 30}' x2='{x}' y2='{box_y + 30}' stroke='#333333' stroke-width='2' marker-end='url(#arrow)'/>"
            )

    elements.insert(1, "  <defs><marker id='arrow' markerWidth='10' markerHeight='7' refX='10' refY='3.5' orient='auto'><polygon points='0 0, 10 3.5, 0 7' fill='#333333'/></marker></defs>")
    elements.append("</svg>")
    return "\n".join(elements) + "\n"


def _write_svg(
    dot: str,
    steps: Sequence[Tuple[str, str]],
    destination: Path,
    *,
    title: Optional[str],
    annotations: Sequence[str],
) -> None:
    if _try_render_with_graphviz(dot, destination):
        return
    destination.write_text(_fallback_svg(steps, title=title, annotations=annotations), encoding="utf-8")


def generate_pipeline_graphs(
    report: Mapping[str, object],
    destination: Path,
    *,
    open_paths: bool = False,
) -> List[Path]:
    """Generate SVG graphs for each pipeline candidate.

    Parameters
    ----------
    report:
        Pipeline candidate payload.
    destination:
        Directory where SVG and DOT artefacts will be written.
    open_paths:
        When ``True`` the resolved SVG paths are printed to stdout (useful for
        ``--open`` CLI invocations).
    """

    destination.mkdir(parents=True, exist_ok=True)

    candidates = report.get("pipelines")
    pipeline_entries: List[Mapping[str, object]] = []
    if isinstance(candidates, Sequence) and candidates:
        pipeline_entries.extend(
            candidate
            for candidate in candidates
            if isinstance(candidate, Mapping) and candidate.get("sequence")
        )
    else:
        sequence = report.get("pipeline")
        if isinstance(sequence, Sequence):
            base_conf_raw = report.get("pipeline_confidence", 0.0)
            try:
                base_confidence = float(base_conf_raw)
            except (TypeError, ValueError):
                base_confidence = 0.0
            hypothesis = score_pipeline_hypothesis(pipeline_confidence=base_confidence)
            pipeline_entries.append(
                {
                    "sequence": [str(step) for step in sequence],
                    "confidence": round(hypothesis.overall, 4),
                    "version_hint": report.get("version_hint"),
                    "preferred_presets": report.get("preferred_presets"),
                    "hints": report.get("pipeline_hints"),
                    "hypothesis_score": {
                        "overall": round(hypothesis.overall, 4),
                        "components": {k: round(v, 4) for k, v in hypothesis.components.items()},
                        "notes": list(hypothesis.notes),
                    },
                    "scoring_context": {
                        "pipeline_confidence": base_confidence,
                        "english_scores": [],
                        "lua_scores": [],
                    },
                }
            )

    report_hints: List[str] = []
    hints_payload = report.get("pipeline_hints")
    if isinstance(hints_payload, Sequence):
        report_hints.extend(str(hint) for hint in hints_payload if isinstance(hint, str))

    generated: List[Path] = []
    for index, candidate in enumerate(pipeline_entries, start=1):
        sequence = candidate.get("sequence")
        if not isinstance(sequence, Sequence) or not sequence:
            continue
        sequence_str = [str(step) for step in sequence]
        slug = _candidate_slug(index, candidate)
        dot_path = destination / f"pipeline-{slug}.dot"
        svg_path = destination / f"pipeline-{slug}.svg"

        annotations = _collect_annotations(candidate)
        for hint in report_hints:
            if hint not in annotations:
                annotations.append(hint)
        preferred_presets = candidate.get("preferred_presets")
        presets: Optional[Sequence[str]] = None
        if isinstance(preferred_presets, Sequence):
            presets = [str(value) for value in preferred_presets[:3]]

        version_value: Optional[str]
        version_hint = candidate.get("version_hint")
        if isinstance(version_hint, str) and version_hint.strip():
            version_value = version_hint.strip()
        else:
            parent_hint = report.get("version_hint")
            version_value = parent_hint.strip() if isinstance(parent_hint, str) and parent_hint.strip() else None

        confidence_value = candidate.get("confidence")
        confidence_float = float(confidence_value) if isinstance(confidence_value, (int, float)) else None

        if version_value and f"Version: {version_value}" not in annotations:
            annotations.insert(0, f"Version: {version_value}")
        if confidence_float is not None:
            confidence_line = f"Confidence: {confidence_float:.2f}"
            if confidence_line not in annotations:
                annotations.insert(1 if version_value else 0, confidence_line)

        dot = render_pipeline_graph(
            sequence_str,
            title=candidate.get("name") or f"Pipeline {index}",
            version_hint=version_value,
            confidence=confidence_float,
            preferred_presets=presets,
            annotations=annotations,
        )
        dot_path.write_text(dot, encoding="utf-8")

        steps = list(_iter_steps(sequence_str))
        _write_svg(dot, steps, svg_path, title=candidate.get("name") or f"Pipeline {index}", annotations=annotations)
        generated.append(svg_path)
        if open_paths:
            print(svg_path)

    return generated


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Visualise pipeline candidates as Graphviz SVG")
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("out") / "pipeline_candidates.json",
        help="Pipeline candidate JSON file",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out") / "graphs",
        help="Directory where SVG graphs will be written",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Print the generated SVG paths (useful for quick inspection)",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not args.source.exists():
        LOGGER.error("Pipeline candidate file %s does not exist", args.source)
        return 1

    try:
        payload = load_pipeline_report(args.source)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        LOGGER.error("Failed to load pipeline report: %s", exc)
        return 1

    generated = generate_pipeline_graphs(payload, args.output_dir, open_paths=args.open)
    if not generated:
        LOGGER.warning("No pipeline sequences found in %s", args.source)
        return 1

    LOGGER.info("Wrote %d pipeline graph(s) to %s", len(generated), args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
