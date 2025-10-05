"""Compatibility wrapper around the opcode emulator verification harness."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


def run_verification(unpacked_json_path: str | Path, out_dir: str | Path) -> Dict[str, Any]:
    """Run the emulator-backed opcode verification pipeline."""

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ir_path = out_path / "lift_ir.json"
    candidates_path = out_path / "opcode_candidates.json"

    if not ir_path.exists() or not candidates_path.exists():
        from .lifter_core import run_lifter

        lifter_result = run_lifter(unpacked_json_path, out_path)
        if lifter_result.get("status") != "ok":
            return {
                "status": "error",
                "message": "lifter failed – cannot verify opcodes",
                "lifter_result": lifter_result,
            }

    from .emulator import run_verification as emulator_verification
    result = emulator_verification(ir_path, unpacked_json_path, candidates_path, out_path)

    if isinstance(result, dict) and result.get("status") == "ok":
        try:
            from .lifter_core import run_lifter

            run_lifter(unpacked_json_path, out_path)
        except Exception:  # pragma: no cover - lifter rerun best-effort
            pass

    return result


__all__ = ["run_verification"]
