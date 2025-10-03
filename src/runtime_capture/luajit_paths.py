"""Helpers for locating LuaJIT executables across platforms."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[2]


def _candidate_paths() -> List[Path]:
    """Return candidate paths where a LuaJIT executable might live."""

    candidates: List[Path] = []
    bin_dir = REPO_ROOT / "bin"
    for name in ("luajit.exe", "luajit"):
        candidate = bin_dir / name
        candidates.append(candidate)

    env_candidate = shutil.which("luajit")
    if env_candidate:
        candidates.append(Path(env_candidate))

    return candidates


def find_luajit() -> list[str] | None:
    """Locate a LuaJIT executable and return the command to invoke it.

    The function searches the repository ``bin`` folder first and then falls
    back to ``shutil.which``.  It returns the command as a single-element list
    so callers can append script arguments without worrying about platform
    quoting.
    """

    for candidate in _candidate_paths():
        if candidate and candidate.exists():
            return [str(candidate)]
    return None


__all__ = ["find_luajit"]

