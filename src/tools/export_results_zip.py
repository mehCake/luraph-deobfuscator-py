"""Package analysis artefacts into a sanitized ZIP archive.

The exporter collects files from an ``out/`` directory and writes them into a
timestamped archive under ``runs/``.  Any file whose name contains the word
``key`` (case insensitive) is automatically excluded, as are JSON documents that
expose a top-level field named ``key``.  A dry-run mode is provided so callers
can inspect which files would be written without creating an archive.
"""

from __future__ import annotations

import argparse
import json
import logging
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ExportResultsError",
    "ExportSummary",
    "export_results_zip",
    "build_arg_parser",
    "main",
]


class ExportResultsError(RuntimeError):
    """Raised when the exporter cannot package the requested artefacts."""


@dataclass(slots=True)
class ExportSummary:
    """Summary of an export attempt."""

    archive_path: Path
    included: List[Path]
    skipped: List[Tuple[Path, str]]
    dry_run: bool = False


def _iter_files(source_dir: Path) -> Iterable[Path]:
    for path in sorted(source_dir.rglob("*")):
        if path.is_file():
            yield path


def _contains_key_field(path: Path) -> bool:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError):
        return False

    stack = [data]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                if str(key).lower() == "key":
                    return True
                stack.append(value)
        elif isinstance(current, (list, tuple)):
            stack.extend(current)
    return False


def _should_exclude(path: Path) -> Optional[str]:
    if "key" in path.name.lower():
        return "name contains 'key'"
    if path.suffix.lower() == ".json" and _contains_key_field(path):
        return "JSON contains 'key' field"
    return None


def _unique_archive_path(runs_dir: Path, *, timestamp: Optional[datetime]) -> Path:
    stamp = (timestamp or datetime.utcnow()).strftime("%Y%m%d-%H%M%S")
    candidate = runs_dir / f"run-{stamp}.zip"
    counter = 2
    while candidate.exists():
        candidate = runs_dir / f"run-{stamp}-{counter}.zip"
        counter += 1
    return candidate


def export_results_zip(
    *,
    source_dir: Path,
    runs_dir: Path,
    timestamp: Optional[datetime] = None,
    dry_run: bool = False,
) -> ExportSummary:
    """Create a sanitized ZIP of ``source_dir`` under ``runs_dir``."""

    if not source_dir.exists():
        raise ExportResultsError(f"Source directory {source_dir} does not exist")

    runs_dir.mkdir(parents=True, exist_ok=True)
    archive_path = _unique_archive_path(runs_dir, timestamp=timestamp)

    included: List[Path] = []
    skipped: List[Tuple[Path, str]] = []

    for path in _iter_files(source_dir):
        reason = _should_exclude(path)
        if reason:
            skipped.append((path, reason))
            LOGGER.debug("Skipping %s: %s", path, reason)
            continue
        included.append(path)

    if dry_run:
        LOGGER.info("Dry run: %d files would be archived", len(included))
        return ExportSummary(archive_path, included, skipped, dry_run=True)

    if not included:
        raise ExportResultsError("No eligible files found to archive")

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in included:
            rel = file_path.relative_to(source_dir)
            zf.write(file_path, rel.as_posix())
            LOGGER.debug("Archived %s -> %s", file_path, rel)

    LOGGER.info("Export archive written to %s", archive_path)
    return ExportSummary(archive_path, included, skipped)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="out",
        type=Path,
        help="Directory containing analysis artefacts to package",
    )
    parser.add_argument(
        "--runs-dir",
        default="runs",
        type=Path,
        help="Destination directory for generated ZIP archives",
    )
    parser.add_argument(
        "--timestamp",
        help="Optional timestamp (UTC, YYYYMMDD-HHMMSS) to use for the archive name",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files that would be archived without creating a ZIP",
    )
    return parser


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y%m%d-%H%M%S")
    except ValueError as exc:  # pragma: no cover - defensive
        raise ExportResultsError(f"Invalid timestamp format: {value}") from exc


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        summary = export_results_zip(
            source_dir=args.out_dir,
            runs_dir=args.runs_dir,
            timestamp=_parse_timestamp(args.timestamp),
            dry_run=args.dry_run,
        )
    except ExportResultsError as exc:
        LOGGER.error("Export failed: %s", exc)
        return 1

    if summary.dry_run:
        for path in summary.included:
            print(path)
        for path, reason in summary.skipped:
            print(f"SKIP {path}: {reason}")
    else:
        print(f"Archive written to {summary.archive_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

