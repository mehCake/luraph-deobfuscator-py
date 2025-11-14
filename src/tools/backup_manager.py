"""Timestamped backups for static analysis artefacts.

The backup manager copies key pipeline inputs into ``out/backups`` while
stripping any JSON fields named ``key`` so session keys are never written to
disk.  Existing backups are preserved by creating unique run directories based
on the current timestamp.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, Mapping, MutableMapping, Optional

LOGGER = logging.getLogger(__name__)

__all__ = ["BackupPlan", "snapshot_analysis_inputs"]


@dataclass(slots=True)
class BackupPlan:
    """Configuration describing artefacts that should be snapshotted."""

    original_file: Path
    manifest_path: Optional[Path] = None
    bootstrap_chunks: Optional[Path] = None
    transform_profile: Optional[Path] = None
    extra_files: Mapping[str, Path] | None = None


def _strip_key_fields(payload: object) -> object:
    """Recursively remove any mapping entries named ``key`` (case insensitive)."""

    if isinstance(payload, MutableMapping):
        return {k: _strip_key_fields(v) for k, v in payload.items() if k.lower() != "key"}
    if isinstance(payload, Mapping):  # pragma: no cover - ``Mapping`` without ``Mutable``
        return {k: _strip_key_fields(v) for k, v in payload.items() if str(k).lower() != "key"}
    if isinstance(payload, list):
        return [_strip_key_fields(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(_strip_key_fields(item) for item in payload)
    return payload


def _write_json_sanitised(source: Path, destination: Path) -> None:
    """Copy ``source`` JSON to ``destination`` while stripping key fields."""

    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
        LOGGER.debug("Failed to parse JSON from %s (%s); copying raw file", source, exc)
        shutil.copy2(source, destination)
        return

    sanitised = _strip_key_fields(data)
    destination.write_text(json.dumps(sanitised, indent=2) + "\n", encoding="utf-8")


def _copy_file(source: Path, destination: Path, *, sanitise_json: bool) -> Optional[Path]:
    """Copy ``source`` to ``destination`` and return the written path."""

    if not source.exists():
        LOGGER.debug("Skipping backup for missing artefact: %s", source)
        return None

    destination.parent.mkdir(parents=True, exist_ok=True)

    if sanitise_json and source.suffix.lower() == ".json":
        _write_json_sanitised(source, destination)
    else:
        shutil.copy2(source, destination)

    LOGGER.debug("Backed up %s -> %s", source, destination)
    return destination


def _unique_run_directory(base: Path, *, timestamp: Optional[datetime] = None) -> Path:
    stamp = (timestamp or datetime.utcnow()).strftime("%Y%m%d-%H%M%S")
    candidate = base / f"run-{stamp}"
    counter = 2
    while candidate.exists():
        candidate = base / f"run-{stamp}-{counter}"
        counter += 1
    return candidate


def _iter_named_files(plan: BackupPlan) -> Iterator[tuple[str, Path, bool]]:
    yield ("original", plan.original_file, False)
    if plan.manifest_path is not None:
        yield ("manifest", plan.manifest_path, True)
    if plan.bootstrap_chunks is not None:
        yield ("bootstrap_chunks", plan.bootstrap_chunks, True)
    if plan.transform_profile is not None:
        yield ("transform_profile", plan.transform_profile, True)
    if plan.extra_files:
        for name, path in plan.extra_files.items():
            yield (name, path, path.suffix.lower() == ".json")


def snapshot_analysis_inputs(
    *,
    output_dir: Path,
    plan: BackupPlan,
    timestamp: Optional[datetime] = None,
) -> Path:
    """Snapshot important inputs and return the backup directory path."""

    backups_root = output_dir / "backups"
    run_dir = _unique_run_directory(backups_root, timestamp=timestamp)
    run_dir.mkdir(parents=True, exist_ok=True)

    manifest: Dict[str, str] = {}
    for name, source, sanitise_json in _iter_named_files(plan):
        destination = run_dir / f"{name}{source.suffix if source.suffix else ''}"
        written = _copy_file(source, destination, sanitise_json=sanitise_json)
        if written is not None:
            manifest[name] = written.name

    manifest_path = run_dir / "backup_manifest.json"
    manifest_path.write_text(json.dumps({"files": manifest}, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Backup snapshot written to %s", run_dir)
    return run_dir

