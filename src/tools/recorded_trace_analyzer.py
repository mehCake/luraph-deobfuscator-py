"""Post-processing helpers for recorded VM traces.

This module operates purely on trace JSON artefacts produced by
:mod:`src.tools.trace_recorder` (or compatible emitters).  It does **not** execute
untrusted code.  The analyser derives higher-level statistics such as register
lifetimes, "hot" handler frequency, and repeated opcode patterns.  Findings are
written to Markdown and CSV artefacts so that humans can quickly understand
recurring idioms (e.g. bootstrap prologue/epilogue blocks) without re-running
instrumentation.

Outputs are written under ``out/trace_analysis`` by default:

* ``<run>.md`` – Markdown summary for a trace.
* ``<run>_registers.csv`` – register lifetime visualisation.
* ``<run>_handlers.csv`` – handler heatmap data.
* ``<run>_patterns.csv`` – repeated opcode sequences.

The analyser is careful to avoid leaking sensitive information.  Metadata fields
containing words such as ``key``/``token``/``secret`` are ignored, and CSV/MD
files only contain structural insight.
"""

from __future__ import annotations

import argparse
import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .trace_recorder import TraceEvent, TraceRecording
from .replay_trace import load_trace as load_trace_file

LOGGER = logging.getLogger(__name__)

REGISTER_FALLBACK_PREFIX = "slot"
REGISTER_HINT_KEYS = {
    "ra",
    "rb",
    "rc",
    "rd",
    "rs",
    "rt",
    "dest",
    "src",
    "source",
    "target",
    "register",
    "registers",
    "reg",
    "result",
    "lhs",
    "rhs",
    "idx",
    "index",
}
SENSITIVE_SUBSTRINGS = ("key", "secret", "token")


@dataclass(frozen=True)
class RegisterLifetime:
    """Describes lifetime information for a register-like entity."""

    register: str
    first_pc: int
    last_pc: int
    occurrences: int

    @property
    def lifetime(self) -> int:
        """Return the span between first and last observation."""

        return self.last_pc - self.first_pc


@dataclass(frozen=True)
class HotHandlerStats:
    """Aggregated statistics for a handler/opcode."""

    handler: str
    count: int
    percentage: float
    average_registers: float
    average_stack_depth: float
    max_stack_depth: int


@dataclass(frozen=True)
class PatternInsight:
    """Represents a repeated opcode sequence discovered in a trace."""

    sequence: Tuple[str, ...]
    count: int


@dataclass(frozen=True)
class TraceAnalysisReport:
    """Container holding derived insight for a trace run."""

    run_name: str
    metadata: Mapping[str, object]
    total_events: int
    unique_handlers: int
    register_lifetimes: Tuple[RegisterLifetime, ...]
    hot_handlers: Tuple[HotHandlerStats, ...]
    pattern_insights: Tuple[PatternInsight, ...]
    prologue: Tuple[str, ...]
    epilogue: Tuple[str, ...]

    def as_markdown(self) -> str:
        """Render the analysis report as Markdown text."""

        lines: List[str] = []
        lines.append(f"# Trace analysis for {self.run_name}\n")
        lines.append("## Overview")
        lines.append("")
        lines.append(f"*Total instructions:* {self.total_events}")
        lines.append(f"*Unique handlers:* {self.unique_handlers}")
        if self.metadata:
            lines.append("*Metadata:*" )
            for key, value in self.metadata.items():
                lines.append(f"  * {key}: {value}")
        lines.append("")

        if self.prologue:
            prologue_seq = ", ".join(self.prologue)
            lines.append("## Common prologue")
            lines.append("")
            lines.append(f"First operations: {prologue_seq}")
            lines.append("")
        if self.epilogue:
            epilogue_seq = ", ".join(self.epilogue)
            lines.append("## Common epilogue")
            lines.append("")
            lines.append(f"Final operations: {epilogue_seq}")
            lines.append("")

        lines.append("## Register lifetimes")
        lines.append("")
        if self.register_lifetimes:
            lines.append("| Register | First PC | Last PC | Lifetime | Occurrences |")
            lines.append("| --- | ---: | ---: | ---: | ---: |")
            for lifetime in self.register_lifetimes:
                lines.append(
                    f"| {lifetime.register} | {lifetime.first_pc} | {lifetime.last_pc} | "
                    f"{lifetime.lifetime} | {lifetime.occurrences} |"
                )
        else:
            lines.append("No register usage information was recorded.")
        lines.append("")

        lines.append("## Hot handlers")
        lines.append("")
        if self.hot_handlers:
            lines.append("| Handler | Count | Share | Avg regs | Avg stack | Max stack |")
            lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
            for handler in self.hot_handlers:
                lines.append(
                    f"| {handler.handler} | {handler.count} | {handler.percentage:.1%} | "
                    f"{handler.average_registers:.2f} | {handler.average_stack_depth:.2f} | "
                    f"{handler.max_stack_depth} |"
                )
        else:
            lines.append("No handler statistics available.")
        lines.append("")

        lines.append("## Repeated opcode patterns")
        lines.append("")
        if self.pattern_insights:
            lines.append("| Sequence | Occurrences |")
            lines.append("| --- | ---: |")
            for insight in self.pattern_insights:
                lines.append(
                    f"| {' → '.join(insight.sequence)} | {insight.count} |"
                )
        else:
            lines.append("No repeated opcode patterns detected above the threshold.")
        lines.append("")

        return "\n".join(lines).strip() + "\n"


def _is_sensitive_field(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in SENSITIVE_SUBSTRINGS)


def _sanitize_metadata(metadata: Mapping[str, object]) -> Dict[str, object]:
    cleaned: Dict[str, object] = {}
    for key, value in metadata.items():
        if _is_sensitive_field(key):
            continue
        cleaned[key] = value
    return cleaned


def _coerce_register_names(value: object, fallback: Optional[str] = None) -> List[str]:
    names: List[str] = []

    def _handle(item: object) -> None:
        if item is None:
            return
        if isinstance(item, (list, tuple, set)):
            for sub in item:
                _handle(sub)
            return
        if isinstance(item, Mapping):
            for hint in REGISTER_HINT_KEYS:
                if hint in item:
                    _handle(item[hint])
            return
        if isinstance(item, (int, float)):
            try:
                numeric = int(item)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                pass
            else:
                names.append(f"R{numeric}")
                return
        text = str(item).strip()
        if not text:
            return
        lowered = text.lower()
        if lowered.startswith("r") and lowered[1:].isdigit():
            names.append(f"R{int(lowered[1:])}")
            return
        if text.isdigit():
            names.append(f"R{int(text)}")
            return
        if not _is_sensitive_field(text):
            names.append(text)

    _handle(value)
    if not names and fallback is not None:
        names.append(fallback)
    return list(dict.fromkeys(names))


def _extract_register_names(event: TraceEvent) -> List[str]:
    names: MutableMapping[str, None] = {}
    for index, register in enumerate(event.registers):
        fallback = f"{REGISTER_FALLBACK_PREFIX}{index}"
        for name in _coerce_register_names(register, fallback):
            names.setdefault(name, None)
    for key, value in event.extras.items():
        if _is_sensitive_field(key):
            continue
        lowered = key.lower()
        if lowered in REGISTER_HINT_KEYS or lowered.startswith("reg"):
            for name in _coerce_register_names(value):
                names.setdefault(name, None)
    return list(names.keys())


def _compute_register_lifetimes(events: Sequence[TraceEvent]) -> List[RegisterLifetime]:
    lifetimes: Dict[str, Dict[str, int]] = {}
    for event in events:
        registers = _extract_register_names(event)
        if not registers and event.register_usage:
            # fall back to synthetic slots to capture activity
            registers = [f"{REGISTER_FALLBACK_PREFIX}{idx}" for idx in range(event.register_usage)]
        for name in registers:
            stats = lifetimes.setdefault(name, {"first": event.pc, "last": event.pc, "count": 0})
            stats["first"] = min(stats["first"], event.pc)
            stats["last"] = max(stats["last"], event.pc)
            stats["count"] += 1
    results = [
        RegisterLifetime(register=name, first_pc=data["first"], last_pc=data["last"], occurrences=data["count"])
        for name, data in lifetimes.items()
    ]
    results.sort(key=lambda item: (item.first_pc, item.register))
    return results


def _resolve_handler_name(event: TraceEvent) -> str:
    for key in ("handler", "function", "dispatch", "name"):
        value = event.extras.get(key)
        if value:
            text = str(value)
            if not _is_sensitive_field(key) and text:
                return text
    return event.opcode


def _compute_hot_handlers(events: Sequence[TraceEvent]) -> List[HotHandlerStats]:
    totals: Dict[str, Dict[str, float]] = {}
    total_events = len(events)
    if not total_events:
        return []
    for event in events:
        handler = _resolve_handler_name(event)
        bucket = totals.setdefault(handler, {"count": 0, "regs": 0.0, "stack": 0.0, "max_stack": 0.0})
        bucket["count"] += 1
        bucket["regs"] += event.register_usage
        bucket["stack"] += event.stack_depth
        bucket["max_stack"] = max(bucket["max_stack"], float(event.stack_depth))
    stats = [
        HotHandlerStats(
            handler=handler,
            count=int(data["count"]),
            percentage=(data["count"] / total_events),
            average_registers=(data["regs"] / data["count"]) if data["count"] else 0.0,
            average_stack_depth=(data["stack"] / data["count"]) if data["count"] else 0.0,
            max_stack_depth=int(data["max_stack"]),
        )
        for handler, data in totals.items()
    ]
    stats.sort(key=lambda item: (-item.count, item.handler))
    return stats


def _compute_pattern_insights(events: Sequence[TraceEvent], max_length: int = 3) -> Tuple[List[PatternInsight], Tuple[str, ...], Tuple[str, ...]]:
    opcodes = [event.opcode for event in events]
    patterns: Dict[Tuple[str, ...], int] = {}
    length = len(opcodes)
    for window in range(2, max_length + 1):
        if window > length:
            break
        for index in range(length - window + 1):
            seq = tuple(opcodes[index : index + window])
            patterns[seq] = patterns.get(seq, 0) + 1
    insights = [
        PatternInsight(sequence=sequence, count=count)
        for sequence, count in patterns.items()
        if count > 1
    ]
    insights.sort(key=lambda item: (-item.count, -len(item.sequence), item.sequence))
    prologue = tuple(opcodes[: min(3, len(opcodes))]) if opcodes else tuple()
    epilogue = tuple(opcodes[-min(3, len(opcodes)) :]) if opcodes else tuple()
    return insights, prologue, epilogue


def analyze_trace(
    recording: TraceRecording,
    *,
    max_pattern_length: int = 3,
    top_handlers: Optional[int] = None,
) -> TraceAnalysisReport:
    """Derive a :class:`TraceAnalysisReport` from a recording."""

    register_lifetimes = _compute_register_lifetimes(recording.events)
    hot_handlers = _compute_hot_handlers(recording.events)
    if top_handlers is not None and top_handlers >= 0:
        hot_handlers = hot_handlers[:top_handlers]
    pattern_insights, prologue, epilogue = _compute_pattern_insights(
        recording.events, max_length=max_pattern_length
    )
    metadata = _sanitize_metadata(recording.metadata)
    report = TraceAnalysisReport(
        run_name=recording.run_name,
        metadata=metadata,
        total_events=len(recording.events),
        unique_handlers=len({item.handler for item in hot_handlers}) if hot_handlers else 0,
        register_lifetimes=tuple(register_lifetimes),
        hot_handlers=tuple(hot_handlers),
        pattern_insights=tuple(pattern_insights),
        prologue=prologue,
        epilogue=epilogue,
    )
    return report


def write_markdown(report: TraceAnalysisReport, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{report.run_name}.md"
    target.write_text(report.as_markdown(), encoding="utf-8")
    return target


def write_csvs(report: TraceAnalysisReport, output_dir: Path) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    registers_csv = output_dir / f"{report.run_name}_registers.csv"
    with registers_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["register", "first_pc", "last_pc", "lifetime", "occurrences"])
        for item in report.register_lifetimes:
            writer.writerow([item.register, item.first_pc, item.last_pc, item.lifetime, item.occurrences])
    written.append(registers_csv)

    handlers_csv = output_dir / f"{report.run_name}_handlers.csv"
    with handlers_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["handler", "count", "share", "avg_registers", "avg_stack", "max_stack"])
        for item in report.hot_handlers:
            writer.writerow(
                [
                    item.handler,
                    item.count,
                    f"{item.percentage:.6f}",
                    f"{item.average_registers:.6f}",
                    f"{item.average_stack_depth:.6f}",
                    item.max_stack_depth,
                ]
            )
    written.append(handlers_csv)

    patterns_csv = output_dir / f"{report.run_name}_patterns.csv"
    with patterns_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sequence", "length", "count"])
        for item in report.pattern_insights:
            writer.writerow([" ".join(item.sequence), len(item.sequence), item.count])
    written.append(patterns_csv)

    return written


def _iter_trace_files(paths: Sequence[Path]) -> List[Path]:
    collected: List[Path] = []
    for path in paths:
        if path.is_dir():
            collected.extend(sorted(p for p in path.glob("*.json") if p.is_file()))
        else:
            collected.append(path)
    return collected


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyse recorded VM traces")
    parser.add_argument("trace", nargs="+", type=Path, help="Trace JSON files or directories to analyse")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/trace_analysis"),
        help="Directory where analysis artefacts are written (default: out/trace_analysis)",
    )
    parser.add_argument(
        "--max-pattern-length",
        type=int,
        default=3,
        help="Maximum opcode sequence length considered for pattern detection (default: 3)",
    )
    parser.add_argument(
        "--top-handlers",
        type=int,
        default=10,
        help="Number of hot handlers to keep in the report (default: 10; negative to keep all)",
    )
    parser.add_argument(
        "--skip-csv",
        action="store_true",
        help="Skip writing CSV visualisations (Markdown summary is still produced)",
    )
    return parser


def analyse_path(path: Path, *, max_pattern_length: int, top_handlers: int, output_dir: Path, write_csv: bool) -> Optional[TraceAnalysisReport]:
    try:
        recording = load_trace_file(path)
    except Exception as exc:  # pragma: no cover - defensive logging path
        LOGGER.error("Failed to load trace %s: %s", path, exc)
        return None
    handler_limit = top_handlers if top_handlers >= 0 else None
    report = analyze_trace(
        recording,
        max_pattern_length=max_pattern_length,
        top_handlers=handler_limit,
    )
    write_markdown(report, output_dir)
    if write_csv:
        write_csvs(report, output_dir)
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    trace_files = _iter_trace_files(args.trace)
    if not trace_files:
        LOGGER.error("No trace files found for analysis")
        return 1
    args.output_dir.mkdir(parents=True, exist_ok=True)
    success = True
    for trace_path in trace_files:
        report = analyse_path(
            trace_path,
            max_pattern_length=args.max_pattern_length,
            top_handlers=args.top_handlers,
            output_dir=args.output_dir,
            write_csv=not args.skip_csv,
        )
        if report is None:
            success = False
        else:
            LOGGER.info("Analysed trace %s (%d instructions)", report.run_name, report.total_events)
    return 0 if success else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
