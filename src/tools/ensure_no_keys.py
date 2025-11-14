"""Detect leaked session keys in generated analysis artefacts.

The loader and detection tooling intentionally avoid persisting sensitive
session keys.  This helper provides a final safety net by walking JSON-like
artefacts beneath an output directory and failing fast if any field named
``key``, ``secret``, or ``token`` contains a non-empty value.  The scanner is
used by the CI pipeline and can also be invoked manually as an audit step.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Sequence

LOGGER = logging.getLogger(__name__)

DEFAULT_PATTERNS: Sequence[str] = ("*.json", "*.manifest", "*.profile")
FORBIDDEN_FIELDS = {"key", "secret", "token"}

__all__ = [
    "DEFAULT_PATTERNS",
    "FORBIDDEN_FIELDS",
    "KeyViolation",
    "KeyLeakError",
    "scan_for_leaked_keys",
    "ensure_no_keys",
    "main",
]


@dataclass(slots=True)
class KeyViolation:
    """A record describing a forbidden field discovered in an artefact."""

    file: Path
    field_path: str
    value_preview: str


class EnsureNoKeysError(RuntimeError):
    """Base error type raised when validation fails."""


class KeyLeakError(EnsureNoKeysError):
    """Raised when forbidden fields with non-empty values are discovered."""

    def __init__(self, violations: Sequence[KeyViolation]):
        message = "forbidden key material detected in analysis artefacts"
        super().__init__(message)
        self.violations = list(violations)


def _discover_files(base_dir: Path, patterns: Sequence[str]) -> List[Path]:
    """Return candidate artefact files that should be scanned."""

    discovered: set[Path] = set()
    for pattern in patterns:
        for path in base_dir.rglob(pattern):
            if path.is_file():
                discovered.add(path)
    return sorted(discovered)


def _is_non_empty(value: object) -> bool:
    """Return ``True`` if the JSON value should be considered non-empty."""

    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, set)):
        return bool(value)
    if isinstance(value, dict):
        return bool(value)
    # Numbers, booleans, and other JSON scalars are treated as meaningful.
    return True


def _value_preview(value: object, *, limit: int = 80) -> str:
    try:
        rendered = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - defensive fallback
        rendered = repr(value)
    if len(rendered) > limit:
        return rendered[: limit - 1] + "…"
    return rendered


def _scan_json(file_path: Path, payload: object) -> Iterator[KeyViolation]:
    stack: list[tuple[object, List[str]]] = [(payload, [])]

    while stack:
        current, path_parts = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                next_parts = path_parts + [str(key)]
                if isinstance(key, str):
                    if key.lower() in FORBIDDEN_FIELDS and _is_non_empty(value):
                        field_path = "/" + "/".join(next_parts)
                        preview = _value_preview(value)
                        yield KeyViolation(file=file_path, field_path=field_path, value_preview=preview)
                stack.append((value, next_parts))
        elif isinstance(current, list):
            for index, value in enumerate(current):
                stack.append((value, path_parts + [str(index)]))


def scan_for_leaked_keys(
    base_dir: Path,
    *,
    patterns: Sequence[str] = DEFAULT_PATTERNS,
) -> List[KeyViolation]:
    """Scan artefacts beneath ``base_dir`` and return any forbidden fields."""

    if not base_dir.exists():
        return []

    violations: List[KeyViolation] = []
    for candidate in _discover_files(base_dir, patterns):
        try:
            content = candidate.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - filesystem failure
            LOGGER.debug("Unable to read %s: %s", candidate, exc)
            continue

        try:
            payload = json.loads(content)
        except json.JSONDecodeError as exc:
            raise EnsureNoKeysError(f"failed to parse JSON in {candidate}: {exc}") from exc

        violations.extend(_scan_json(candidate, payload))
    return violations


def ensure_no_keys(
    base_dir: Path,
    *,
    patterns: Sequence[str] = DEFAULT_PATTERNS,
    raise_on_violation: bool = True,
) -> List[KeyViolation]:
    """Validate that generated artefacts do not contain leaked key material."""

    violations = scan_for_leaked_keys(base_dir, patterns=patterns)
    if violations and raise_on_violation:
        raise KeyLeakError(violations)
    return violations


def _format_violation(violation: KeyViolation) -> str:
    return f"{violation.file}: {violation.field_path} -> {violation.value_preview}"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan analysis outputs for leaked session keys or secrets.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=Path("out"),
        help="Root directory to scan (default: out)",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        dest="patterns",
        default=None,
        help=(
            "Additional glob pattern for candidate files (default patterns: "
            + ", ".join(DEFAULT_PATTERNS)
            + ")"
        ),
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    patterns = tuple(args.patterns) if args.patterns else DEFAULT_PATTERNS

    try:
        violations = ensure_no_keys(args.base_dir, patterns=patterns)
    except KeyLeakError as exc:
        for violation in exc.violations:
            LOGGER.error(_format_violation(violation))
        LOGGER.error("Sensitive material detected; refusing to continue.")
        return 1
    except EnsureNoKeysError as exc:
        LOGGER.error(str(exc))
        return 1

    if violations:
        for violation in violations:
            LOGGER.warning(_format_violation(violation))
    else:
        LOGGER.info("No forbidden key fields detected beneath %s", args.base_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
