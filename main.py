#!/usr/bin/env python3
"""Compat shim that forwards to :mod:`src.main`.

The historical repository exposed a top-level ``main.py`` script which newer
examples and tests continue to invoke (``python main.py ...``).  Over time the
real CLI implementation moved into :mod:`src.main`; however the thin wrapper was
never updated and drifted into a stub that produced placeholder artefacts.  The
current test-suite exercises the full deobfuscation pipeline – including
bootstrap extraction, payload decoding and Lua reconstruction – so we forward
all arguments directly to :func:`src.main.main`.

The indirection keeps backwards compatibility while ensuring a single code path
handles option parsing and artifact generation for both ``python -m src.main``
and ``python main.py`` entry points.
"""

from __future__ import annotations

import sys

from src import main as _cli


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python main.py``.

    Parameters
    ----------
    argv:
        Optional argument vector.  When ``None`` the wrapper forwards the
        current ``sys.argv[1:]`` to :func:`src.main.main`.
    """

    return _cli.main(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":  # pragma: no cover - thin CLI shim
    raise SystemExit(main())
