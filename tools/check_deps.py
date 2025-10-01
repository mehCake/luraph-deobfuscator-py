#!/usr/bin/env python3
"""Simple dependency checker for the Luraph deobfuscation toolchain."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

from check_luajit import find_luajit, validate_luajit

REPO_ROOT = Path(__file__).resolve().parents[1]


def check_lupa() -> tuple[bool, str]:
    try:
        module = importlib.import_module("lupa")
    except ModuleNotFoundError as exc:
        return False, f"lupa not installed: {exc}"

    version = getattr(module, "__version__", "unknown")
    return True, f"lupa {version}"


def check_luajit_dependency() -> tuple[bool, str]:
    executable = find_luajit()
    if not executable:
        return False, "LuaJIT not found. Install system luajit or use bundled bin/luajit.exe"

    ok, message = validate_luajit(executable)
    if not ok:
        return False, message

    rel = executable.relative_to(REPO_ROOT) if executable.is_relative_to(REPO_ROOT) else executable
    return True, f"LuaJIT at {rel}: {message}"


CHECKS = {
    "lupa": check_lupa,
    "luajit": check_luajit_dependency,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify required runtime dependencies")
    parser.add_argument(
        "--check",
        choices=CHECKS.keys(),
        action="append",
        help="Run a specific check (default: run all)",
    )
    args = parser.parse_args(argv)

    names = args.check or list(CHECKS.keys())
    overall_ok = True
    for name in names:
        ok, message = CHECKS[name]()
        status = "OK" if ok else "MISSING"
        print(f"[{status:<8}] {name}: {message}")
        overall_ok &= ok

    if not overall_ok:
        print(
            "One or more dependencies are missing. Install via pip/apt or refer to bin/ for bundled LuaJIT.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
