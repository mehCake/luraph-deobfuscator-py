"""Inject provenance headers into prettified Lua output.

The annotate helper adds (or removes) a multi-line comment at the top of
``out/deobfuscated_pretty.lua`` describing the pipeline steps that produced the
file alongside a run timestamp.  The header intentionally avoids recording any
session keys or other sensitive details – any token that looks like a key is
redacted before the header is written.

Usage examples::

    # Annotate the default output using the pipeline candidates report
    python -m src.tools.annotate_output \
        --output out/deobfuscated_pretty.lua \
        --pipeline-json out/pipeline_candidates.json

    # Remove a previously inserted header
    python -m src.tools.annotate_output --output out/deobfuscated_pretty.lua --disable
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

LOGGER = logging.getLogger(__name__)

DEFAULT_OUTPUT = Path("out/deobfuscated_pretty.lua")
DEFAULT_PIPELINE_JSON = Path("out/pipeline_candidates.json")

HEADER_PREFIX = "-- PROVENANCE (annotate_output):"


@dataclass(frozen=True)
class AnnotationContext:
    """Metadata used to build the provenance header."""

    steps: Sequence[str]
    version_hint: Optional[str]
    confidence: Optional[float]


@dataclass(frozen=True)
class AnnotationResult:
    """Details about an annotation attempt."""

    output_path: Path
    applied: bool
    header: Optional[str]


def _sanitize_token(token: str) -> str:
    """Redact obviously sensitive words such as ``key``."""

    lowered = token.lower()
    if "key" in lowered:
        return "[redacted]"
    return token


def _sanitize_steps(steps: Iterable[str]) -> list[str]:
    return [_sanitize_token(str(step)) for step in steps]


def _load_pipeline_context(path: Path | None) -> AnnotationContext:
    """Extract the best pipeline candidate from ``pipeline_candidates.json``."""

    if path is None or not path.exists():
        return AnnotationContext(steps=(), version_hint=None, confidence=None)

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
        LOGGER.debug("Failed to parse pipeline candidates at %s: %s", path, exc)
        return AnnotationContext(steps=(), version_hint=None, confidence=None)

    pipelines = payload.get("pipelines")
    if not isinstance(pipelines, Sequence):
        return AnnotationContext(steps=(), version_hint=None, confidence=None)

    best_entry: Optional[Mapping[str, object]] = None
    best_score = float("-inf")

    for entry in pipelines:
        if not isinstance(entry, Mapping):
            continue
        score: Optional[float]
        raw_score = entry.get("confidence")
        if raw_score is None:
            hypothesis = entry.get("hypothesis_score")
            if isinstance(hypothesis, Mapping):
                raw_score = hypothesis.get("overall")
        try:
            score = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            score = None
        score_value = score if score is not None else float("-inf")
        if score_value > best_score:
            best_score = score_value
            best_entry = entry

    if best_entry is None:
        return AnnotationContext(steps=(), version_hint=None, confidence=None)

    raw_steps = best_entry.get("sequence")
    steps: list[str]
    if isinstance(raw_steps, Sequence):
        steps = _sanitize_steps(step for step in raw_steps if isinstance(step, str))
    else:
        steps = []

    version_hint: Optional[str] = None
    raw_version = best_entry.get("version_hint") or payload.get("version_hint")
    if isinstance(raw_version, str):
        version_hint = _sanitize_token(raw_version)

    confidence: Optional[float] = None
    if best_score != float("-inf"):
        confidence = float(best_score)

    return AnnotationContext(steps=steps, version_hint=version_hint, confidence=confidence)


def _normalise_timestamp(timestamp: Optional[datetime]) -> datetime:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _build_header(context: AnnotationContext, timestamp: datetime) -> str:
    timestamp = _normalise_timestamp(timestamp)
    timestamp_text = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    steps = list(context.steps)
    pipeline_text = " -> ".join(steps) if steps else "unknown"

    lines = [
        "--[[",
        f"{HEADER_PREFIX} generated {timestamp_text}",
        f"-- PIPELINE: {pipeline_text}",
    ]

    if context.version_hint:
        lines.append(f"-- VERSION_HINT: {context.version_hint}")
    if context.confidence is not None:
        lines.append(f"-- CONFIDENCE: {context.confidence:.3f}")

    lines.append("-- Generated by src.tools.annotate_output (disable with --disable).")
    lines.append("--]]")

    return "\n".join(lines) + "\n\n"


def _strip_existing_header(text: str) -> tuple[str, bool]:
    if not text.startswith("--[["):
        return text, False
    end_index = text.find("--]]")
    if end_index == -1:
        return text, False
    header_body = text[:end_index]
    if HEADER_PREFIX not in header_body:
        return text, False
    remainder = text[end_index + len("--]]") :]
    # Remove at most one blank line that we previously inserted
    if remainder.startswith("\r\n"):
        remainder = remainder[2:]
    if remainder.startswith("\n"):
        remainder = remainder[1:]
    if remainder.startswith("\r\n"):
        remainder = remainder[2:]
    if remainder.startswith("\n"):
        remainder = remainder[1:]
    return remainder, True


def annotate_output(
    output_path: Path,
    *,
    pipeline_path: Path | None = None,
    steps: Optional[Sequence[str]] = None,
    timestamp: Optional[datetime] = None,
    version_hint: Optional[str] = None,
    confidence: Optional[float] = None,
    enabled: bool = True,
) -> AnnotationResult:
    """Insert (or remove) the provenance header for ``output_path``."""

    if not output_path.exists():
        raise FileNotFoundError(f"Beautified output not found at {output_path}")

    text = output_path.read_text(encoding="utf-8")
    remainder, removed = _strip_existing_header(text)

    if not enabled:
        if removed:
            output_path.write_text(remainder, encoding="utf-8")
            LOGGER.info("Removed provenance header from %s", output_path)
        else:
            LOGGER.info("No provenance header present on %s", output_path)
        return AnnotationResult(output_path=output_path, applied=False, header=None)

    if steps is not None:
        context = AnnotationContext(
            steps=_sanitize_steps(steps),
            version_hint=_sanitize_token(version_hint) if version_hint else None,
            confidence=confidence,
        )
    else:
        context = _load_pipeline_context(pipeline_path)
        if version_hint:
            context = AnnotationContext(
                steps=context.steps,
                version_hint=_sanitize_token(version_hint),
                confidence=context.confidence,
            )
        if confidence is not None:
            context = AnnotationContext(
                steps=context.steps,
                version_hint=context.version_hint,
                confidence=confidence,
            )

    header = _build_header(context, _normalise_timestamp(timestamp))
    new_text = header + remainder
    output_path.write_text(new_text, encoding="utf-8")
    LOGGER.info("Annotated %s with provenance header", output_path)
    return AnnotationResult(output_path=output_path, applied=True, header=header)


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Annotate prettified Lua output with provenance metadata")
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Path to the prettified Lua output (default: out/deobfuscated_pretty.lua)",
    )
    parser.add_argument(
        "--pipeline-json",
        type=Path,
        default=DEFAULT_PIPELINE_JSON,
        help="Pipeline candidates JSON used to derive step information",
    )
    parser.add_argument(
        "--disable",
        action="store_true",
        help="Remove an existing provenance header instead of inserting one",
    )
    parser.add_argument(
        "--timestamp",
        help="Explicit ISO8601 timestamp to record (defaults to current UTC time)",
    )
    parser.add_argument(
        "--step",
        dest="steps",
        action="append",
        help="Manually provide a pipeline step (overrides pipeline JSON)",
    )
    parser.add_argument(
        "--version-hint",
        help="Explicit version hint to include in the header",
    )
    parser.add_argument(
        "--confidence",
        type=float,
        help="Confidence value to record in the header",
    )
    return parser.parse_args(argv)


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SystemExit(f"Invalid timestamp '{value}': {exc}") from exc


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    timestamp = _parse_timestamp(args.timestamp)

    result = annotate_output(
        args.output,
        pipeline_path=args.pipeline_json,
        steps=args.steps,
        timestamp=timestamp,
        version_hint=args.version_hint,
        confidence=args.confidence,
        enabled=not args.disable,
    )

    if result.applied:
        LOGGER.info("Header inserted for %s", result.output_path)
    else:
        LOGGER.info("Annotation disabled for %s", result.output_path)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())


__all__ = [
    "AnnotationContext",
    "AnnotationResult",
    "annotate_output",
    "main",
]
