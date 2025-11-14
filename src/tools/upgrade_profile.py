"""Upgrade transform profile JSON files to the latest schema safely.

This helper normalises stored transform profiles that may have been written by
older versions of the toolkit.  It performs the following tasks:

* removes any fields that look like session keys (``key``, ``secret``,
  ``token``) and warns the operator when doing so;
* rewrites the profile using the canonical schema emitted by
  :mod:`src.tools.transform_profile`;
* appends a JSON-lines migration log so analysts can audit profile changes;
* behaves idempotently so repeated executions do not duplicate work or log
  entries.

The module also exposes a small CLI that can be used from the command line::

    python -m src.tools.upgrade_profile path/to/profile.json

The CLI supports ``--dry-run`` to preview the changes without touching the
profile or log files.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, List, Mapping, MutableMapping, Sequence

from .transform_profile import TransformProfile

LOGGER = logging.getLogger(__name__)

SENSITIVE_FIELD_NAMES = {"key", "secret", "token"}
DEFAULT_LOG_SUFFIX = ".migrations.log"

__all__ = [
    "MigrationEntry",
    "UpgradeResult",
    "upgrade_profile",
    "main",
]


@dataclass(slots=True)
class MigrationEntry:
    """Recorded information about a profile migration."""

    timestamp: str
    source: str
    from_version: str | None
    to_version: str
    removed_sensitive_fields: List[str]
    changed: bool


@dataclass(slots=True)
class UpgradeResult:
    """Outcome of a profile upgrade operation."""

    profile_path: Path
    output_path: Path
    log_path: Path
    updated: bool
    would_update: bool
    wrote_log_entry: bool
    removed_sensitive_fields: Sequence[str]
    from_version: str | None
    to_version: str


def _strip_sensitive_fields(payload: Any, *, path: Sequence[str] | None = None) -> tuple[Any, List[str]]:
    """Return ``payload`` without sensitive fields and record removed paths."""

    path = tuple(path or ())
    removed: List[str] = []

    if isinstance(payload, MutableMapping):
        sanitized: dict[str, Any] = {}
        for key, value in payload.items():
            key_str = str(key)
            key_lower = key_str.lower()
            current_path = path + (key_str,)
            if key_lower in SENSITIVE_FIELD_NAMES:
                if value not in (None, "", [], {}):
                    removed.append("/" + "/".join(current_path))
                continue
            sanitized_value, nested_removed = _strip_sensitive_fields(value, path=current_path)
            sanitized[key_str] = sanitized_value
            removed.extend(nested_removed)
        return sanitized, removed

    if isinstance(payload, Mapping):  # pragma: no cover - defensive for non-mutable mapping
        return _strip_sensitive_fields(dict(payload), path=path)

    if isinstance(payload, list):
        sanitized_list: list[Any] = []
        for index, value in enumerate(payload):
            index_path = path + (f"[{index}]",)
            sanitized_value, nested_removed = _strip_sensitive_fields(value, path=index_path)
            sanitized_list.append(sanitized_value)
            removed.extend(nested_removed)
        return sanitized_list, removed

    if isinstance(payload, tuple):
        sanitized_items = []
        for index, value in enumerate(payload):
            index_path = path + (f"[{index}]",)
            sanitized_value, nested_removed = _strip_sensitive_fields(value, path=index_path)
            sanitized_items.append(sanitized_value)
            removed.extend(nested_removed)
        return tuple(sanitized_items), removed

    return payload, removed


def _append_migration_log(log_path: Path, entry: MigrationEntry) -> bool:
    """Append ``entry`` to ``log_path`` if it is not already present."""

    serialized = json.dumps(asdict(entry), sort_keys=True)
    if log_path.exists():
        existing = {line.strip() for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()}
        if serialized in existing:
            return False
    else:
        log_path.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(serialized + "\n")
    return True


def upgrade_profile(
    profile_path: Path | str,
    *,
    output_path: Path | str | None = None,
    log_path: Path | str | None = None,
    dry_run: bool = False,
) -> UpgradeResult:
    """Normalise ``profile_path`` into the latest schema and record migration."""

    profile_path = Path(profile_path)
    if output_path is None:
        output = profile_path
    else:
        output = Path(output_path)

    if log_path is None:
        log_file = output.with_suffix(output.suffix + DEFAULT_LOG_SUFFIX)
    else:
        log_file = Path(log_path)

    raw_text = profile_path.read_text(encoding="utf-8")
    data = json.loads(raw_text)
    if not isinstance(data, Mapping):
        raise ValueError("transform profile JSON must contain an object at the top level")

    from_version = str(data.get("version")) if "version" in data else None

    sanitized, removed_sensitive = _strip_sensitive_fields(data)
    if removed_sensitive:
        LOGGER.warning(
            "Removed sensitive fields from %s: %s",
            profile_path,
            ", ".join(sorted(removed_sensitive)),
        )

    profile = TransformProfile.from_dict(sanitized)
    target_version = TransformProfile().version
    profile.version = target_version
    upgraded_payload = profile.to_dict()

    current_normalised = TransformProfile.from_dict(sanitized).to_dict()
    needs_update = current_normalised != upgraded_payload or removed_sensitive or output != profile_path

    if dry_run:
        return UpgradeResult(
            profile_path=profile_path,
            output_path=output,
            log_path=log_file,
            updated=False,
            would_update=needs_update,
            wrote_log_entry=False,
            removed_sensitive_fields=removed_sensitive,
            from_version=from_version,
            to_version=target_version,
        )

    wrote_log = False
    if needs_update:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(upgraded_payload, indent=2) + "\n", encoding="utf-8")
        LOGGER.info("Transform profile upgraded: %s", output)

        entry = MigrationEntry(
            timestamp=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            source=str(profile_path),
            from_version=from_version,
            to_version=target_version,
            removed_sensitive_fields=list(sorted(removed_sensitive)),
            changed=True,
        )
        wrote_log = _append_migration_log(log_file, entry)
    else:
        LOGGER.info("Profile %s already matches the latest schema", profile_path)

    return UpgradeResult(
        profile_path=profile_path,
        output_path=output,
        log_path=log_file,
        updated=needs_update,
        would_update=needs_update,
        wrote_log_entry=wrote_log,
        removed_sensitive_fields=removed_sensitive,
        from_version=from_version,
        to_version=target_version,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Upgrade transform profile JSON files")
    parser.add_argument("profile", type=Path, help="Path to the transform profile JSON file")
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional destination file for the upgraded profile (defaults to in-place)",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help="Optional migration log file path (defaults to <profile>.migrations.log)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing files")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        result = upgrade_profile(
            args.profile,
            output_path=args.output,
            log_path=args.log,
            dry_run=args.dry_run,
        )
    except Exception as exc:  # pragma: no cover - CLI level defensive guard
        LOGGER.error("Failed to upgrade profile: %s", exc)
        return 1

    if args.dry_run:
        if result.would_update:
            print(f"Profile {result.profile_path} would be upgraded to version {result.to_version}")
            if result.removed_sensitive_fields:
                print("Sensitive fields removed:", ", ".join(result.removed_sensitive_fields))
            return 0
        print(f"Profile {result.profile_path} already matches the latest schema")
        return 0

    if result.updated:
        print(f"Profile upgraded and written to {result.output_path}")
        if result.wrote_log_entry:
            print(f"Migration log updated: {result.log_path}")
    else:
        print(f"Profile {result.profile_path} already matches the latest schema")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
