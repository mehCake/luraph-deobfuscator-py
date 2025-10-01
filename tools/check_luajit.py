#!/usr/bin/env python3
"""Utility helpers for locating and validating a LuaJIT executable."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_CANDIDATES = [
    REPO_ROOT / "bin" / "luajit.exe",
    REPO_ROOT / "bin" / "luajit",
    REPO_ROOT / "luajit.exe",
    REPO_ROOT / "luajit",
]
PATH_CANDIDATES = ["luajit", "luajit.exe"]


def find_luajit() -> Path | None:
    """Return the preferred LuaJIT executable if one is available."""

    for candidate in BIN_CANDIDATES:
        if candidate.exists() and candidate.is_file():
            return candidate

    for name in PATH_CANDIDATES:
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved)
    return None


def validate_luajit(executable: Path) -> tuple[bool, str]:
    """Run ``luajit -v`` to confirm the binary is callable."""

    try:
        proc = subprocess.run(
            [str(executable), "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    except OSError as exc:  # pragma: no cover - rare failure path
        return False, f"failed to execute {executable}: {exc}"

    output = (proc.stdout or "").strip()
    if proc.returncode != 0:
        return False, f"luajit returned {proc.returncode}: {output}"

    return True, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify LuaJIT availability")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress normal output; only use exit code",
    )
    args = parser.parse_args(argv)

    executable = find_luajit()
    if not executable:
        if not args.quiet:
            print(
                "LuaJIT executable not found. Install luajit on PATH or use the bundled bin/luajit.exe",
                file=sys.stderr,
            )
        return 1

    ok, message = validate_luajit(executable)
    if not args.quiet:
        location = executable.relative_to(REPO_ROOT) if executable.is_relative_to(REPO_ROOT) else executable
        print(f"LuaJIT located at {location}")
        print(message)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
