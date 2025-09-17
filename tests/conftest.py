"""Test configuration ensuring the project source tree is importable."""

from __future__ import annotations

import sys
from pathlib import Path
import importlib

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

root_str = str(ROOT)
if root_str not in sys.path:
    sys.path.insert(0, root_str)
else:
    idx = sys.path.index(root_str)
    if idx != 0:
        sys.path.insert(0, sys.path.pop(idx))

if str(TESTS) in sys.path:
    sys.path.pop(sys.path.index(str(TESTS)))
sys.path.insert(1, str(TESTS))

# Import the project package eagerly so subsequent imports reuse it
importlib.import_module("src")
