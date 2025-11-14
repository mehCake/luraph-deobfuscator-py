"""Scan deobfuscated Lua text for potentially insecure constructs.

The helper inspects plain-text artefacts produced by the analysis pipeline
without executing any payload code.  When suspicious API calls are detected a
human-readable report is written to ``out/warnings.txt`` (or another path
specified at the CLI level).  The module never mutates the inspected files nor
stores session keys; any snippet containing a ``key=`` assignment is redacted in
the generated report.
"""

from __future__ import annotations

import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "SuspiciousPattern",
    "PatternMatch",
    "DEFAULT_PATTERNS",
    "scan_paths",
    "write_warning_report",
    "build_arg_parser",
    "main",
]


@dataclass(frozen=True)
class SuspiciousPattern:
    """Descriptor for a suspicious construct recognised by the scanner."""

    name: str
    expression: str
    description: str
    flags: int = re.IGNORECASE

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.expression, self.flags)


@dataclass(frozen=True)
class PatternMatch:
    """A single match encountered while scanning a source file."""

    path: Path
    line: int
    pattern: str
    description: str
    snippet: str


DEFAULT_PATTERNS: Tuple[SuspiciousPattern, ...] = (
    SuspiciousPattern("os.execute", r"\bos\.execute\b", "Direct operating system command execution"),
    SuspiciousPattern("io.popen", r"\bio\.popen\b", "Spawns a process and pipes output"),
    SuspiciousPattern("io.open", r"\bio\.open\b", "Direct file-system access"),
    SuspiciousPattern("loadstring", r"\bloadstring\b", "Dynamic code loading"),
    SuspiciousPattern("load", r"\bload\s*\(", "Dynamic chunk loading"),
    SuspiciousPattern("game.HttpGet", r"game\s*:\s*HttpGet", "Roblox HTTP fetch invocation"),
    SuspiciousPattern("syn.request", r"\bsyn\s*\.request\b", "Synapse X HTTP request"),
    SuspiciousPattern("http.request", r"\bhttp\s*\.request\b", "Generic HTTP request"),
    SuspiciousPattern("websocket", r"\bwebsocket\b", "WebSocket usage"),
    SuspiciousPattern("socket", r"require\s*\(?[\"']socket", "Socket library import"),
    SuspiciousPattern("getfenv", r"\bgetfenv\b", "Environment manipulation"),
    SuspiciousPattern("setfenv", r"\bsetfenv\b", "Environment manipulation"),
)

_KEY_ASSIGNMENT = re.compile(
    r"(?i)(key\s*=\s*)(?:['\"]([^'\"]*)['\"]|([^,;]+))"
)


def _scrub_snippet(snippet: str) -> str:
    """Redact session keys and trim whitespace within *snippet*."""

    snippet = snippet.strip()
    if not snippet:
        return snippet

    def _replacement(match: re.Match[str]) -> str:
        return f"{match.group(1)}<redacted>"

    return _KEY_ASSIGNMENT.sub(_replacement, snippet)


def _iter_candidate_files(paths: Iterable[Path]) -> Iterator[Path]:
    for raw in paths:
        path = raw
        if not path.exists():
            LOGGER.warning("Input %s does not exist", path)
            continue
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file():
                    yield child
            continue
        if path.is_file():
            yield path


def scan_paths(
    paths: Sequence[Path],
    *,
    patterns: Optional[Sequence[SuspiciousPattern]] = None,
    encoding: str = "utf-8",
) -> Tuple[PatternMatch, ...]:
    """Scan *paths* for suspicious constructs and return ordered matches."""

    compiled = [pattern.compile() for pattern in (patterns or DEFAULT_PATTERNS)]
    descriptors = list(patterns or DEFAULT_PATTERNS)

    results: list[PatternMatch] = []
    for path in _iter_candidate_files(Path(p) for p in paths):
        try:
            text = path.read_text(encoding=encoding)
        except (UnicodeDecodeError, OSError) as exc:
            LOGGER.warning("Failed to read %s: %s", path, exc)
            continue

        lines = text.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for descriptor, expression in zip(descriptors, compiled):
                if expression.search(line):
                    results.append(
                        PatternMatch(
                            path=path,
                            line=lineno,
                            pattern=descriptor.name,
                            description=descriptor.description,
                            snippet=_scrub_snippet(line),
                        )
                    )
    return tuple(results)


def write_warning_report(destination: Path, matches: Sequence[PatternMatch]) -> Path:
    """Write a warning report enumerating *matches* to *destination*."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    if matches:
        lines.append("# Suspicious Constructs Detected")
        lines.append("")
        for match in matches:
            lines.append(
                f"{match.path}:{match.line}: {match.description} (pattern: {match.pattern})"
            )
            if match.snippet:
                lines.append(f"    {match.snippet}")
            lines.append("")
        lines.append(
            "Review the flagged constructs manually and ensure no sensitive keys are stored in this report."
        )
    else:
        lines.append("No suspicious constructs detected.")
    destination.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    LOGGER.info("Wrote warning report to %s", destination)
    return destination


def _load_custom_patterns(path: Optional[Path]) -> Tuple[SuspiciousPattern, ...]:
    if path is None:
        return ()
    try:
        payload = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        LOGGER.warning("Pattern configuration %s not found", path)
        return ()
    except OSError as exc:
        LOGGER.warning("Failed to read pattern config %s: %s", path, exc)
        return ()

    entries = []
    for line in payload.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            name, expression, description = line.split("|", 2)
        except ValueError:
            LOGGER.warning("Invalid pattern specification: %s", line)
            continue
        entries.append(SuspiciousPattern(name.strip(), expression.strip(), description.strip()))
    return tuple(entries)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan deobfuscated files for suspicious constructs without modifying them.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Files or directories to scan")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "warnings.txt",
        help="Destination warnings report (default: out/warnings.txt)",
    )
    parser.add_argument(
        "--patterns",
        type=Path,
        default=None,
        help="Optional pattern definition file (pipe-separated name|regex|description)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    custom = _load_custom_patterns(args.patterns)
    patterns = DEFAULT_PATTERNS + custom

    matches = scan_paths(args.paths, patterns=patterns)
    write_warning_report(args.output, matches)

    if matches:
        LOGGER.warning("Detected %d suspicious constructs", len(matches))
        return 1
    LOGGER.info("No suspicious constructs detected")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
