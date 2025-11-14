"""Run identifier helpers for pipeline artefacts.

This module centralises run identifier generation so that every tool writes
artefacts using deterministic, sanitised names.  The identifiers are
constructed from caller-provided components and a short digest which keeps the
values stable across processes while avoiding collisions.  Callers can also
reserve artefact paths and detect when an identifier has already been used so
that existing results are not overwritten.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Iterable, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

_SANITISE_RE = re.compile(r"[^0-9A-Za-z._-]+")


def _coerce_component(component: object) -> str:
    if isinstance(component, bytes):
        return component.decode("utf-8", errors="ignore")
    return str(component)


def sanitise_token(token: str) -> str:
    """Return a safe representation that only contains [a-z0-9._-]."""

    collapsed = _SANITISE_RE.sub("-", token.strip())
    collapsed = collapsed.strip("-_.")
    if not collapsed:
        return "run"
    return collapsed.lower()


def _digest_components(components: Sequence[str], *, digest_length: int = 8) -> str:
    payload = json.dumps(list(components), separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()
    return digest[:digest_length]


def generate_run_id(
    *, components: Sequence[object], max_length: int = 48, digest_length: int = 8
) -> str:
    """Generate a deterministic run identifier from ``components``.

    Each component is coerced to a string, sanitised, and combined.  A short
    digest ensures that even if sanitisation removes distinctive characters the
    identifier remains unique.  The result is always lowercase and limited to
    ``max_length`` characters.  The function never returns an empty string.
    """

    raw_components = [_coerce_component(part) for part in components]
    safe_components = [sanitise_token(part) for part in raw_components if part.strip()]

    if not safe_components:
        base = "run"
    else:
        base = "-".join(safe_components)

    digest = _digest_components(raw_components, digest_length=digest_length)
    candidate = f"{base}-{digest}" if digest else base

    if len(candidate) <= max_length:
        return candidate

    # Reserve space for the digest and separator while trimming the base.
    overflow = len(candidate) - max_length
    if overflow >= len(base):
        # Base is completely trimmed; fall back to digest only.
        return digest or "run"

    trimmed_base = base[:-overflow]
    trimmed_base = trimmed_base.rstrip("-_.") or "run"
    return f"{trimmed_base}-{digest}" if digest else trimmed_base


def reserve_artifact_path(
    base_dir: Path,
    *,
    run_id: str,
    prefix: str | None = "run",
    suffix: str = "",
    create_directory: bool = False,
) -> Tuple[Path, bool]:
    """Return a path for ``run_id`` without overwriting existing artefacts.

    ``run_id`` is validated to ensure it only contains safe characters.  The
    function returns the resolved path and a boolean indicating whether the
    caller should write new data (``True``) or reuse an existing artefact
    (``False``).
    """

    sanitised = sanitise_token(run_id)
    if sanitised != run_id:
        raise ValueError("run_id contains unsafe characters; use generate_run_id")

    name_parts: Iterable[str] = ()
    if prefix:
        name_parts = (*name_parts, sanitise_token(prefix))
    name_parts = (*name_parts, run_id)

    filename = "-".join(filter(None, name_parts)) + suffix
    target = base_dir / filename

    if target.exists():
        LOGGER.info("Reusing existing artefact at %s", target)
        return target, False

    if create_directory:
        target.mkdir(parents=True, exist_ok=False)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)

    return target, True


__all__ = [
    "generate_run_id",
    "reserve_artifact_path",
    "sanitise_token",
]

