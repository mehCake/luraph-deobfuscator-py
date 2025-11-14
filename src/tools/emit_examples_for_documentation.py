"""Generate sanitized documentation examples from pipeline outputs.

This helper collects a handful of representative artefacts from a previous
analysis run (for instance ``pipeline_candidates.json`` and the prettified Lua
listing) and emits shortened, sanitised snippets under ``docs/examples/``.  The
snippets are intentionally small so that they can be embedded in documentation
without leaking sensitive information such as session keys.  Any JSON fields
whose name contains tokens like ``key`` or ``secret`` are removed entirely, and
text excerpts drop lines that mention those tokens.

The module provides both a Python API (``emit_documentation_examples``) and a
CLI entry point.  The CLI defaults to reading artefacts from ``out/`` and
writing examples to ``docs/examples`` but both locations are configurable.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ExampleArtefact",
    "ExampleGenerationError",
    "ExampleSummary",
    "emit_documentation_examples",
    "build_arg_parser",
    "main",
]

_FORBIDDEN_TOKENS = {"key", "secret", "token"}


class ExampleGenerationError(RuntimeError):
    """Raised when documentation examples cannot be generated."""


@dataclass(slots=True)
class ExampleArtefact:
    """Configuration for generating an example fragment."""

    source: Path
    destination_name: str
    extractor: Callable[[Path], Optional[str]]


@dataclass(slots=True)
class ExampleSummary:
    """Summary of example emission."""

    generated: List[Path]
    skipped: List[Tuple[Path, str]]


def _contains_forbidden_token(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in _FORBIDDEN_TOKENS)


def _sanitize_json(value):  # type: ignore[no-untyped-def]
    if isinstance(value, dict):
        clean = {}
        for key, child in value.items():
            if any(token in str(key).lower() for token in _FORBIDDEN_TOKENS):
                continue
            clean[key] = _sanitize_json(child)
        return clean
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    return value


def _json_excerpt(path: Path, *, max_entries: int = 1) -> Optional[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        LOGGER.warning("Failed to parse JSON from %s: %s", path, exc)
        return None

    sanitized = _sanitize_json(data)

    if isinstance(sanitized, list) and len(sanitized) > max_entries:
        sanitized = sanitized[:max_entries]
    if isinstance(sanitized, dict):
        # Keep only the first few items for brevity while preserving keys.
        limited = {}
        for index, (key, value) in enumerate(sanitized.items()):
            if index >= max_entries:
                break
            limited[key] = value
        sanitized = limited

    return json.dumps(sanitized, indent=2, ensure_ascii=False) + "\n"


def _text_excerpt(path: Path, *, max_lines: int = 40) -> Optional[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        LOGGER.warning("Failed to read text from %s: %s", path, exc)
        return None

    excerpt: List[str] = []
    for line in lines:
        if _contains_forbidden_token(line):
            continue
        excerpt.append(line)
        if len(excerpt) >= max_lines:
            break
    if not excerpt:
        return None
    return "\n".join(excerpt) + "\n"


def _default_artefacts(out_dir: Path) -> List[ExampleArtefact]:
    return [
        ExampleArtefact(
            source=out_dir / "pipeline_candidates.json",
            destination_name="pipeline_candidates_example.json",
            extractor=lambda path: _json_excerpt(path, max_entries=1),
        ),
        ExampleArtefact(
            source=out_dir / "final_report.md",
            destination_name="final_report_excerpt.md",
            extractor=lambda path: _text_excerpt(path, max_lines=30),
        ),
        ExampleArtefact(
            source=out_dir / "deobfuscated_pretty.lua",
            destination_name="prettified_snippet.lua",
            extractor=lambda path: _text_excerpt(path, max_lines=40),
        ),
        ExampleArtefact(
            source=out_dir / "opcode_proposals.json",
            destination_name="opcode_proposals_example.json",
            extractor=lambda path: _json_excerpt(path, max_entries=2),
        ),
    ]


def emit_documentation_examples(
    *,
    out_dir: Path,
    docs_dir: Path,
    artefacts: Optional[Sequence[ExampleArtefact]] = None,
) -> ExampleSummary:
    """Generate documentation examples from ``out_dir`` into ``docs_dir``."""

    if not out_dir.exists():
        raise ExampleGenerationError(f"Output directory {out_dir} does not exist")

    artefact_list = list(artefacts or _default_artefacts(out_dir))
    if not artefact_list:
        raise ExampleGenerationError("No artefacts specified for example generation")

    examples_dir = docs_dir / "examples"
    examples_dir.mkdir(parents=True, exist_ok=True)

    generated: List[Path] = []
    skipped: List[Tuple[Path, str]] = []

    for artefact in artefact_list:
        source = artefact.source
        if not source.exists():
            skipped.append((source, "missing"))
            LOGGER.debug("Skipping %s because it does not exist", source)
            continue
        snippet = artefact.extractor(source)
        if not snippet:
            skipped.append((source, "empty after sanitisation"))
            LOGGER.debug("Skipping %s because snippet was empty", source)
            continue
        destination = examples_dir / artefact.destination_name
        destination.write_text(snippet, encoding="utf-8")
        generated.append(destination)
        LOGGER.info("Example %s written", destination)

    if not generated:
        raise ExampleGenerationError("No documentation examples were generated")

    return ExampleSummary(generated, skipped)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Directory containing analysis artefacts",
    )
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=Path("docs"),
        help="Documentation root where examples will be written",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational logging",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if not args.quiet else logging.WARNING)

    try:
        summary = emit_documentation_examples(out_dir=args.out_dir, docs_dir=args.docs_dir)
    except ExampleGenerationError as exc:
        LOGGER.error("Failed to generate documentation examples: %s", exc)
        return 1

    LOGGER.info("Generated %d examples (skipped %d)", len(summary.generated), len(summary.skipped))
    return 0


if __name__ == "__main__":  # pragma: no cover - manual invocation guard
    raise SystemExit(main())
