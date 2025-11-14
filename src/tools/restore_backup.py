"""Restore backed-up pipeline artefacts into a temporary workspace.

This helper complements :mod:`src.tools.backup_manager` by providing a safe
way to materialise a snapshot for re-analysis.  Restored files are copied into
an ephemeral directory, their checksums are verified, and any accidental
session key leakage is detected before the files are exposed to analysts.

The module intentionally refuses to restore artefacts that still contain key
material.  Analysts are guided to sanitise the offending backup before
retrying, ensuring the repository never persists secrets across runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableMapping, Sequence

LOGGER = logging.getLogger(__name__)

__all__ = [
    "RestoredFile",
    "RestoredRun",
    "RestoreBackupError",
    "build_arg_parser",
    "main",
    "restore_backup",
]


class RestoreBackupError(RuntimeError):
    """Raised when a backup cannot be safely restored."""


@dataclass(slots=True)
class RestoredFile:
    """Metadata about an individual restored artefact."""

    name: str
    source: Path
    destination: Path
    checksum: str


@dataclass(slots=True)
class RestoredRun:
    """Container describing the restored backup workspace."""

    run_dir: Path
    restored_dir: Path
    files: List[RestoredFile]


def _load_manifest(run_dir: Path) -> Mapping[str, str]:
    manifest_path = run_dir / "backup_manifest.json"
    if not manifest_path.exists():
        raise RestoreBackupError(f"Missing backup manifest: {manifest_path}")

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RestoreBackupError(f"Invalid backup manifest at {manifest_path}: {exc}") from exc

    files = data.get("files")
    if not isinstance(files, Mapping):
        raise RestoreBackupError(
            "backup_manifest.json does not contain a 'files' mapping"
        )
    return files


def _has_key_field(payload: object) -> bool:
    """Return ``True`` if a mapping with a ``key`` entry is present."""

    if isinstance(payload, MutableMapping):
        if any(str(k).lower() == "key" for k in payload):
            return True
        return any(_has_key_field(value) for value in payload.values())

    if isinstance(payload, Mapping):  # pragma: no cover - defensive for Mapping subclasses
        if any(str(k).lower() == "key" for k in payload.keys()):
            return True
        return any(_has_key_field(value) for value in payload.values())

    if isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        return any(_has_key_field(item) for item in payload)

    return False


def _detect_key_material(path: Path) -> None:
    """Raise :class:`RestoreBackupError` if ``path`` appears to contain keys."""

    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "\"key\"" in text.lower():
                raise RestoreBackupError(
                    f"Refusing to restore {path.name}: contains a JSON 'key' field"
                )
            return

        if _has_key_field(payload):
            raise RestoreBackupError(
                "Refusing to restore backup because JSON file contains a 'key' field. "
                "Please remove session keys from backups before retrying."
            )
        return

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:  # binary payloads are fine
        return

    lowered = text.lower()
    patterns = ["\"key\"", "'key'", "key=", "key:", " key "]
    if any(pattern in lowered for pattern in patterns):
        raise RestoreBackupError(
            f"Refusing to restore {path.name}: potential key material detected"
        )


def _compute_checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_and_verify(source: Path, destination: Path) -> RestoredFile:
    if not source.exists():
        raise RestoreBackupError(f"Backed up file is missing: {source}")

    _detect_key_material(source)

    checksum_before = _compute_checksum(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    checksum_after = _compute_checksum(destination)

    if checksum_before != checksum_after:
        raise RestoreBackupError(
            f"Checksum mismatch when restoring {source.name}; copy may be corrupted"
        )

    return RestoredFile(
        name=source.name,
        source=source,
        destination=destination,
        checksum=checksum_after,
    )


def _create_workspace(destination_root: Path | None) -> Path:
    if destination_root is not None:
        destination_root.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="restore-", dir=str(destination_root)))
    return Path(tempfile.mkdtemp(prefix="restore-"))


def restore_backup(
    run_dir: Path,
    *,
    destination_root: Path | None = None,
) -> RestoredRun:
    """Restore ``run_dir`` into a temporary workspace and return metadata."""

    run_dir = run_dir.resolve()
    if not run_dir.exists():
        raise RestoreBackupError(f"Backup directory does not exist: {run_dir}")

    manifest = _load_manifest(run_dir)
    workspace = _create_workspace(destination_root)

    restored_files: List[RestoredFile] = []
    for logical_name, filename in manifest.items():
        source = (run_dir / filename).resolve()
        destination = workspace / filename
        LOGGER.debug("Restoring %s from %s", logical_name, source)
        restored = _copy_and_verify(source, destination)
        restored_files.append(restored)

    LOGGER.info("Restored %d files to %s", len(restored_files), workspace)
    return RestoredRun(run_dir=run_dir, restored_dir=workspace, files=restored_files)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Restore a backed-up analysis run into a temporary workspace",
    )
    parser.add_argument("backup_run", type=Path, help="Path to the backup run directory")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Optional directory in which the temporary workspace will be created",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List restored files after completion",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        result = restore_backup(args.backup_run, destination_root=args.output_dir)
    except RestoreBackupError as exc:
        LOGGER.error("Restore failed: %s", exc)
        return 1

    print(result.restored_dir)
    if args.list:
        for restored in result.files:
            print(f"- {restored.destination.name} (sha256={restored.checksum})")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
