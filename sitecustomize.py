"""Ensure the project root takes precedence on ``sys.path`` for tests."""

from __future__ import annotations

import os
import sys


def _promote(path: str, *, position: int = 0) -> None:
    try:
        index = sys.path.index(path)
    except ValueError:
        sys.path.insert(position, path)
        return
    if index != position:
        entry = sys.path.pop(index)
        sys.path.insert(position, entry)


ROOT = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(ROOT, "tests")

_promote(ROOT, position=0)
if os.path.isdir(TESTS):
    _promote(TESTS, position=1)

