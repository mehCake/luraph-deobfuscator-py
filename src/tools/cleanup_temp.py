"""Utilities for cleaning intermediate analysis artefacts.

The detection pipeline produces sizeable temporary artefacts under
``out/intermediate``.  These are useful for debugging, but they can quickly
accumulate and consume disk space on long-running analysis sessions.  This
module implements a retention policy that keeps the most recent runs and any
artefacts that are newer than a configurable threshold, while offering a
``--dry-run`` mode so analysts can preview what would be deleted.

Backups stored under ``out/backups`` are intentionally ignored so the clean-up
routine never removes long-term recovery data.
"""

from __future__ import annotations

import argparse
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Sequence

LOGGER = logging.getLogger(__name__)

__all__ = ["CleanupPlan", "collect_cleanup_candidates", "cleanup_intermediate_artifacts", "main"]


@dataclass(slots=True)
class CleanupPlan:
    """Configuration for trimming intermediate artefacts."""

    out_dir: Path
    retention_days: int = 14
    keep_latest: int = 3
    dry_run: bool = False

    def intermediate_dir(self) -> Path:
        return self.out_dir / "intermediate"


@dataclass(slots=True)
class CleanupCandidate:
    """Represents an artefact that may be removed."""

    path: Path
    modified: datetime

    @property
    def key(self) -> tuple[datetime, str]:
        # Sort newest first (descending).  ``modified`` uses UTC to avoid TZ
        # differences when comparing values created on different systems.
        return (-self.modified.timestamp(), str(self.path))


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iter_entries(directory: Path) -> Iterable[CleanupCandidate]:
    for entry in directory.iterdir():
        try:
            stat_result = entry.stat()
        except OSError as exc:  # pragma: no cover - defensive logging only
            LOGGER.warning("Failed to stat %s: %s", entry, exc)
            continue
        modified = _to_utc(datetime.fromtimestamp(stat_result.st_mtime, timezone.utc))
        yield CleanupCandidate(path=entry, modified=modified)


def collect_cleanup_candidates(plan: CleanupPlan) -> List[CleanupCandidate]:
    """Return a sorted list of candidates from ``out/intermediate``."""

    intermediate_dir = plan.intermediate_dir()
    if not intermediate_dir.exists():
        LOGGER.info("No intermediate directory found at %s", intermediate_dir)
        return []

    candidates = list(_iter_entries(intermediate_dir))
    candidates.sort(key=lambda candidate: candidate.key)
    return candidates


def _should_preserve(candidate: CleanupCandidate, *, keep_latest: Sequence[CleanupCandidate], cutoff: datetime) -> bool:
    if candidate in keep_latest:
        return True
    return candidate.modified >= cutoff


def _delete_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def cleanup_intermediate_artifacts(plan: CleanupPlan) -> List[Path]:
    """Remove temporary artefacts according to the retention policy."""

    candidates = collect_cleanup_candidates(plan)
    if not candidates:
        return []

    cutoff = _to_utc(datetime.now(timezone.utc) - timedelta(days=max(plan.retention_days, 0)))
    keep_count = max(plan.keep_latest, 0)
    keep_latest: Sequence[CleanupCandidate] = candidates[:keep_count]
    removed: List[Path] = []

    LOGGER.info(
        "Evaluating %s intermediate artefacts (keeping %s newest, retention=%s days)",
        len(candidates),
        keep_count,
        plan.retention_days,
    )

    for candidate in candidates:
        if _should_preserve(candidate, keep_latest=keep_latest, cutoff=cutoff):
            LOGGER.debug("Preserving %s (modified %s)", candidate.path, candidate.modified.isoformat())
            continue

        LOGGER.info("Removing %s (modified %s)", candidate.path, candidate.modified.isoformat())
        removed.append(candidate.path)
        if not plan.dry_run:
            _delete_path(candidate.path)

    if plan.dry_run:
        LOGGER.info("Dry-run enabled; no files were deleted.")

    return removed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Clean temporary intermediate artefacts.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Path to the analysis output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=14,
        help="Remove artefacts older than this many days (default: %(default)s)",
    )
    parser.add_argument(
        "--keep-latest",
        type=int,
        default=3,
        help="Always preserve the most recent N artefacts regardless of age (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview removals without deleting any files",
    )
    return parser


def _resolve_out_dir(out_dir: Path) -> Path:
    try:
        resolved = out_dir.resolve(strict=False)
    except OSError:  # pragma: no cover - defensive
        return out_dir
    return resolved


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    plan = CleanupPlan(
        out_dir=_resolve_out_dir(args.out_dir),
        retention_days=max(args.retention_days, 0),
        keep_latest=max(args.keep_latest, 0),
        dry_run=args.dry_run,
    )

    removed = cleanup_intermediate_artifacts(plan)

    if removed:
        LOGGER.info("Removed %s artefacts", len(removed))
    else:
        LOGGER.info("No artefacts matched the clean-up criteria")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

