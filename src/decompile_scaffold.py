"""Placeholder for decompile scaffold generation."""
from __future__ import annotations

from pathlib import Path
from typing import Any


class DecompileNotImplementedError(RuntimeError):
    pass


def build_scaffold(ir_path: Path, opcode_map_path: Path, out_dir: Path) -> dict[str, Any]:
    raise DecompileNotImplementedError(
        "decompile_scaffold.build_scaffold is not implemented."
    )
