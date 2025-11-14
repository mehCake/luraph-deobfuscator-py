"""Build a compact reviewer export archive from analysis artefacts.

The exporter focuses on the high-level outputs that human reviewers typically
inspect: the prettified Lua listing, written reports, and intermediate artefacts
that explain how the pipeline arrived at its conclusions.  The archive excludes
large binary blobs by default (anything above five mebibytes) so that the result
remains lightweight for manual sharing.  Callers can opt into including those
large files via ``--include-blobs``.

Sensitive material such as session keys must never be written to the archive.
Any file whose name suggests that it might contain a key (``key``, ``secret``,
``token``) or JSON documents that expose such fields are automatically skipped.
"""

from __future__ import annotations

import argparse
import json
import logging
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ExportForReviewersError",
    "ReviewerExportSummary",
    "export_for_reviewers",
    "build_arg_parser",
    "main",
]

DEFAULT_MAX_BLOB_SIZE = 5 * 1024 * 1024  # 5 MiB
_FORBIDDEN_NAMES = {"key", "secret", "token"}


class ExportForReviewersError(RuntimeError):
    """Raised when reviewer export cannot be generated."""


@dataclass(slots=True)
class ReviewerExportSummary:
    """Summary of the reviewer export operation."""

    archive_path: Path
    included: List[Path]
    skipped: List[Tuple[Path, str]]
    dry_run: bool = False


def _validate_required_files(out_dir: Path, required: Sequence[str]) -> List[Path]:
    paths: List[Path] = []
    for name in required:
        path = out_dir / name
        if not path.exists():
            raise ExportForReviewersError(
                f"Required artefact {name!r} is missing from {out_dir}."
            )
        paths.append(path)
    return paths


def _iter_intermediate(out_dir: Path) -> Iterable[Path]:
    intermediate_dir = out_dir / "intermediate"
    if not intermediate_dir.exists():
        return []
    return (path for path in sorted(intermediate_dir.rglob("*")) if path.is_file())


def _contains_forbidden_field(path: Path) -> bool:
    if path.suffix.lower() not in {".json", ".jsonl"}:
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError):
        return False

    stack = [data]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower() in _FORBIDDEN_NAMES:
                    return True
                stack.append(child)
        elif isinstance(value, (list, tuple)):
            stack.extend(value)
    return False


def _should_skip(path: Path, *, include_blobs: bool, max_blob_size: int) -> Optional[str]:
    lower_name = path.name.lower()
    for token in _FORBIDDEN_NAMES:
        if token in lower_name:
            return f"name contains '{token}'"
    if path.suffix.lower() in {".json", ".jsonl"} and _contains_forbidden_field(path):
        return "JSON contains forbidden field"
    size = path.stat().st_size
    if not include_blobs and size > max_blob_size:
        return f"size {size} exceeds max blob size {max_blob_size}"
    return None


def _unique_archive_path(dest_dir: Path, *, timestamp: Optional[datetime]) -> Path:
    stamp = (timestamp or datetime.utcnow()).strftime("%Y%m%d-%H%M%S")
    candidate = dest_dir / f"review-{stamp}.zip"
    counter = 2
    while candidate.exists():
        candidate = dest_dir / f"review-{stamp}-{counter}.zip"
        counter += 1
    return candidate


def export_for_reviewers(
    *,
    out_dir: Path,
    dest_dir: Path,
    include_blobs: bool = False,
    max_blob_size: int = DEFAULT_MAX_BLOB_SIZE,
    timestamp: Optional[datetime] = None,
    dry_run: bool = False,
) -> ReviewerExportSummary:
    """Create a reviewer-friendly archive from ``out_dir`` artefacts."""

    if not out_dir.exists():
        raise ExportForReviewersError(f"Output directory {out_dir} does not exist")

    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_path = _unique_archive_path(dest_dir, timestamp=timestamp)

    required_paths = _validate_required_files(
        out_dir,
        [
            "deobfuscated_pretty.lua",
            "final_report.md",
            "review_opmap.md",
        ],
    )

    included: List[Path] = []
    skipped: List[Tuple[Path, str]] = []

    for path in required_paths:
        reason = _should_skip(path, include_blobs=include_blobs, max_blob_size=max_blob_size)
        if reason:
            skipped.append((path, reason))
            LOGGER.warning("Required artefact %s skipped: %s", path, reason)
        else:
            included.append(path)

    for path in _iter_intermediate(out_dir):
        reason = _should_skip(path, include_blobs=include_blobs, max_blob_size=max_blob_size)
        if reason:
            skipped.append((path, reason))
            LOGGER.debug("Skipping intermediate artefact %s: %s", path, reason)
            continue
        included.append(path)

    if not included:
        raise ExportForReviewersError("No artefacts eligible for reviewer export")

    if dry_run:
        LOGGER.info("Dry run: %d files would be archived", len(included))
        return ReviewerExportSummary(archive_path, included, skipped, dry_run=True)

    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in included:
            try:
                rel = file_path.relative_to(out_dir)
            except ValueError:
                # Should not happen, but fall back to name-only path.
                rel = file_path.name
            zf.write(file_path, Path(rel).as_posix())
            LOGGER.debug("Archived %s", file_path)

    LOGGER.info("Reviewer archive written to %s", archive_path)
    return ReviewerExportSummary(archive_path, included, skipped)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Directory containing analysis artefacts",
    )
    parser.add_argument(
        "--dest-dir",
        type=Path,
        default=Path("out") / "reviewer_exports",
        help="Destination directory for reviewer ZIP archives",
    )
    parser.add_argument(
        "--include-blobs",
        action="store_true",
        help="Include intermediate files larger than 5 MiB",
    )
    parser.add_argument(
        "--max-blob-size",
        type=int,
        default=DEFAULT_MAX_BLOB_SIZE,
        help="Maximum blob size in bytes when --include-blobs is not set",
    )
    parser.add_argument(
        "--timestamp",
        help="Optional timestamp (UTC, YYYYMMDD-HHMMSS) for deterministic naming",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List files that would be archived without writing a ZIP",
    )
    return parser


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.strptime(value, "%Y%m%d-%H%M%S")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        summary = export_for_reviewers(
            out_dir=args.out_dir,
            dest_dir=args.dest_dir,
            include_blobs=args.include_blobs,
            max_blob_size=args.max_blob_size,
            timestamp=_parse_timestamp(args.timestamp),
            dry_run=args.dry_run,
        )
    except ExportForReviewersError as exc:  # pragma: no cover - CLI surface
        LOGGER.error("%s", exc)
        return 1

    if summary.dry_run:
        LOGGER.info("Dry run complete: %d files would be included", len(summary.included))
    else:
        LOGGER.info("Archive created at %s", summary.archive_path)
    if summary.skipped:
        LOGGER.info(
            "%d artefacts skipped:",
            len(summary.skipped),
        )
        for path, reason in summary.skipped:
            LOGGER.info(" - %s (%s)", path, reason)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
