"""Helpers for locating LuaJIT executables across platforms."""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import List

import subprocess

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


def find_luajit() -> Path | None:
    """Locate a LuaJIT executable if one is available."""

    for candidate in _candidate_paths():
        if not candidate or not candidate.exists():
            continue
        if candidate.suffix.lower() == ".exe" and os.name != "nt":
            continue
        try:
            mode = candidate.stat().st_mode
            if not mode & stat.S_IXUSR:
                candidate.chmod(mode | stat.S_IXUSR)
        except OSError:
            pass
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def build_luajit_command(executable: Path, *args: str) -> List[str]:
    """Return a subprocess-ready command for invoking ``luajit``.

    The helper wraps paths using :func:`subprocess.list2cmdline` on Windows so
    that bundled binaries in directories with spaces are handled correctly.
    On POSIX systems the command is returned as ``[luajit, arg1, arg2, ...]``.
    """

    flattened: List[str] = [str(executable)]
    flattened.extend(str(part) for part in args)

    if os.name == "nt":
        command = subprocess.list2cmdline(flattened)
        shell = os.environ.get("COMSPEC", "cmd.exe")
        return [shell, "/c", command]
    return flattened


__all__ = ["find_luajit", "build_luajit_command"]

