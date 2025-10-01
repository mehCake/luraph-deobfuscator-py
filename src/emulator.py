"""Placeholder opcode emulator."""

from __future__ import annotations

from pathlib import Path
from typing import Any


class EmulatorNotImplementedError(RuntimeError):
    pass


def run_verification(ir_path: Path, unpacked_path: Path, candidates_path: Path, out_dir: Path) -> dict[str, Any]:
    raise EmulatorNotImplementedError(
        "Opcode verification emulator is not implemented."
    )
