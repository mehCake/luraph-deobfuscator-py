"""Lightweight detection utilities for Luraph variants."""
from __future__ import annotations

import re
from typing import Optional

from version_detector import VersionDetector, VersionInfo

_DETECTOR = VersionDetector()


def legacy_detector(text: str, *, from_json: bool = False) -> VersionInfo:
    """Fallback to the repository heuristics for version detection."""

    info = _DETECTOR.detect_version(text, from_json=from_json)
    return info


def detect_version_from_text(text: str) -> Optional[str]:
    """Detect Luraph variants from banner text before running heuristics."""

    if re.search(r"lura\.ph|luraph", text, re.IGNORECASE):
        if re.search(r"v14\.4", text, re.IGNORECASE) or re.search(r"14\.4\.1", text, re.IGNORECASE):
            return "luraph_v14_4_initv4"
        return "luraph_v14_4_initv4"
    return None


def ask_confirm(ctx, message: str) -> bool:
    """Prompt the user to confirm an automatic detection unless suppressed."""

    if getattr(ctx, "yes", False):
        return True
    if getattr(ctx, "force", False):
        return True
    try:
        response = input(f"{message} (Y/N): ")
    except EOFError:  # pragma: no cover - treat EOF as acceptance
        return True
    answer = response.strip().lower()
    return answer in {"y", "yes", ""}


__all__ = [
    "ask_confirm",
    "detect_version_from_text",
    "legacy_detector",
]
