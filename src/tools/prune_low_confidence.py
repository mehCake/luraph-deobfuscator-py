"""Archive low-confidence pipeline candidates to keep reports focused."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .backup_manager import BackupPlan, snapshot_analysis_inputs
from .uid_generator import generate_run_id, reserve_artifact_path

LOGGER = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 0.45
DEFAULT_PIPELINE_JSON = Path("out") / "pipeline_candidates.json"
DEFAULT_ARCHIVE_DIR = Path("out") / "archive"

PRUNABLE_KEYS: Tuple[str, ...] = (
    "pipelines",
    "chunks",
    "byte_candidates",
    "mapping_candidates",
    "opcode_candidates",
)


@dataclass(slots=True)
class PruneResult:
    """Summary of a pruning run."""

    pipeline_path: Path
    threshold: float
    pruned_counts: Mapping[str, int]
    kept_counts: Mapping[str, int]
    archive_path: Optional[Path]
    archive_id: Optional[str]
    backup_dir: Optional[Path]

    @property
    def total_pruned(self) -> int:
        return sum(self.pruned_counts.values())


@dataclass(slots=True)
class RestoreResult:
    """Summary describing a restoration from an archive file."""

    pipeline_path: Path
    archive_path: Path
    restored_counts: Mapping[str, int]
    backup_dir: Optional[Path]

    @property
    def total_restored(self) -> int:
        return sum(self.restored_counts.values())


def _load_json(path: Path) -> MutableMapping[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:  # pragma: no cover - delegated to CLI handling
        raise FileNotFoundError(f"Pipeline report not found: {path}") from exc


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _split_low_confidence(entries: Sequence[object], threshold: float) -> Tuple[List[object], List[object]]:
    kept: List[object] = []
    pruned: List[object] = []

    for entry in entries:
        confidence = None
        if isinstance(entry, Mapping):
            raw = entry.get("confidence")
            if isinstance(raw, (int, float)):
                confidence = float(raw)
        if confidence is not None and confidence < threshold:
            pruned.append(entry)
        else:
            kept.append(entry)

    return kept, pruned


def _collect_prunable_keys(data: Mapping[str, object]) -> Iterable[str]:
    for key in PRUNABLE_KEYS:
        if isinstance(data.get(key), list):
            yield key


def _iso_timestamp(now: Optional[datetime] = None) -> str:
    stamp = now or datetime.now(timezone.utc)
    text = stamp.isoformat(timespec="seconds")
    if text.endswith("+00:00"):
        return text[:-6] + "Z"
    return text


def prune_low_confidence(
    pipeline_path: Path,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    archive_dir: Optional[Path] = None,
    backup: bool = True,
) -> PruneResult:
    """Remove low-confidence candidates from ``pipeline_path`` and archive them."""

    if threshold <= 0:
        LOGGER.debug("Threshold %.3f <= 0, nothing will be pruned", threshold)
    if threshold < 0 or threshold > 1:
        raise ValueError("threshold must be within [0, 1]")

    data = _load_json(pipeline_path)

    pruned_entries: Dict[str, List[object]] = {}
    kept_counts: Dict[str, int] = {}

    for key in _collect_prunable_keys(data):
        entries = data.get(key, [])
        if not isinstance(entries, list):  # pragma: no cover - defensive
            continue
        kept, pruned = _split_low_confidence(entries, threshold)
        if pruned:
            data[key] = kept
            pruned_entries[key] = pruned
            kept_counts[key] = len(kept)

    if not pruned_entries:
        LOGGER.info("No candidates below threshold %.2f found in %s", threshold, pipeline_path)
        return PruneResult(
            pipeline_path=pipeline_path,
            threshold=threshold,
            pruned_counts={},
            kept_counts={},
            archive_path=None,
            archive_id=None,
            backup_dir=None,
        )

    archive_dir = archive_dir or pipeline_path.parent / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)
    archive_id = generate_run_id(
        components=[pipeline_path.stem or "pipeline", f"lt{threshold:.2f}", timestamp.isoformat()],
    )
    archive_path, _ = reserve_artifact_path(
        archive_dir,
        run_id=archive_id,
        prefix="archive",
        suffix=".json",
    )

    pruned_counts = {key: len(items) for key, items in pruned_entries.items()}

    archive_payload = {
        "archive_id": archive_id,
        "created_at": _iso_timestamp(timestamp),
        "threshold": threshold,
        "source": str(pipeline_path),
        "pruned": pruned_entries,
    }

    backup_dir: Optional[Path] = None
    if backup:
        backup_dir = snapshot_analysis_inputs(
            output_dir=pipeline_path.parent,
            plan=BackupPlan(original_file=pipeline_path),
        )

    _write_json(archive_path, archive_payload)
    _write_json(pipeline_path, data)

    LOGGER.info(
        "Pruned %s low-confidence candidate(s) below %.2f into %s",
        pruned_counts,
        threshold,
        archive_path,
    )

    return PruneResult(
        pipeline_path=pipeline_path,
        threshold=threshold,
        pruned_counts=pruned_counts,
        kept_counts=kept_counts,
        archive_path=archive_path,
        archive_id=archive_id,
        backup_dir=backup_dir,
    )


def _resolve_archive_path(
    archive_identifier: str | Path,
    *,
    archive_dir: Path,
) -> Path:
    candidate = Path(archive_identifier)
    if candidate.exists():
        return candidate

    archive_dir.mkdir(parents=True, exist_ok=True)
    name = str(archive_identifier)
    if not name.endswith(".json"):
        name = f"{name}.json"
    path = archive_dir / name
    if not path.exists():
        raise FileNotFoundError(f"Archive file not found: {archive_identifier}")
    return path


def restore_from_archive(
    pipeline_path: Path,
    archive_identifier: str | Path,
    *,
    archive_dir: Optional[Path] = None,
    backup: bool = True,
) -> RestoreResult:
    """Reintroduce archived candidates into the active pipeline file."""

    archive_dir = archive_dir or pipeline_path.parent / "archive"
    archive_path = _resolve_archive_path(archive_identifier, archive_dir=archive_dir)

    data = _load_json(pipeline_path)
    archive_payload = _load_json(archive_path)

    pruned_section = archive_payload.get("pruned")
    if not isinstance(pruned_section, Mapping):
        raise ValueError(f"Archive payload {archive_path} is missing 'pruned' section")

    restored_counts: Dict[str, int] = {}
    for key, entries in pruned_section.items():
        if not isinstance(entries, list):
            continue
        target = data.get(key)
        if target is None:
            target = []
            data[key] = target
        if not isinstance(target, list):  # pragma: no cover - defensive
            LOGGER.warning("Cannot restore key %s; expected list but found %s", key, type(target).__name__)
            continue
        restored = 0
        for entry in entries:
            if entry not in target:
                target.append(entry)
                restored += 1
        if restored:
            restored_counts[key] = restored

    if not restored_counts:
        LOGGER.info("No new entries restored from %s", archive_path)
        return RestoreResult(
            pipeline_path=pipeline_path,
            archive_path=archive_path,
            restored_counts={},
            backup_dir=None,
        )

    backup_dir: Optional[Path] = None
    if backup:
        backup_dir = snapshot_analysis_inputs(
            output_dir=pipeline_path.parent,
            plan=BackupPlan(original_file=pipeline_path),
        )

    _write_json(pipeline_path, data)
    LOGGER.info(
        "Restored %s candidate(s) from archive %s into %s",
        restored_counts,
        archive_path,
        pipeline_path,
    )

    return RestoreResult(
        pipeline_path=pipeline_path,
        archive_path=archive_path,
        restored_counts=restored_counts,
        backup_dir=backup_dir,
    )


def _build_parser():  # pragma: no cover - exercised via CLI smoke tests
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pipeline",
        type=Path,
        default=DEFAULT_PIPELINE_JSON,
        help="Path to pipeline_candidates.json",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help="Confidence threshold for pruning (0-1)",
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        default=None,
        help="Destination directory for archived candidates (defaults to out/archive)",
    )
    parser.add_argument(
        "--restore",
        type=str,
        default=None,
        help="Archive identifier or path to restore instead of pruning",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating a backup snapshot before writing changes",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:  # pragma: no cover - CLI entrypoint
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.restore:
            restore_from_archive(
                args.pipeline,
                args.restore,
                archive_dir=args.archive_dir,
                backup=not args.no_backup,
            )
        else:
            prune_low_confidence(
                args.pipeline,
                threshold=args.threshold,
                archive_dir=args.archive_dir,
                backup=not args.no_backup,
            )
    except Exception as exc:  # pragma: no cover - user facing error
        parser.error(str(exc))
        return 2
    return 0


__all__ = [
    "DEFAULT_THRESHOLD",
    "PruneResult",
    "RestoreResult",
    "prune_low_confidence",
    "restore_from_archive",
    "main",
]
