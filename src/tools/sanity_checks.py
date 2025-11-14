"""Sanity checks covering reversible pipeline primitives.

This module exercises a couple of lightweight regression checks that are used
throughout the tooling stack:

* permutation helpers – applying an inverse permutation should reproduce the
  original byte sequence;
* LPH reversal + initv4 PRGA parity – a synthetic v14.4.2 style payload is
  reversed and then passed through the PRGA helper to ensure the combined
  pipeline continues to behave as expected.

Each invocation produces a Markdown report under ``out/sanity`` describing the
outcome of the checks so analysts can quickly spot regressions when working on
new payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import argparse
import logging
from pathlib import Path
from typing import Iterable, List, Sequence

from src.decoders.initv4_prga import apply_prga
from src.decoders.lph_reverse import reverse_lph

LOGGER = logging.getLogger(__name__)

__all__ = [
    "SanityCheckResult",
    "run_sanity_checks",
    "main",
]


@dataclass(frozen=True)
class SanityCheckResult:
    """Container capturing the outcome of a single sanity check."""

    name: str
    passed: bool
    detail: str


_PERMUTATION_SAMPLE = tuple([3, 0, 2, 1, 7, 5, 6, 4])
_PERMUTATION_INPUT = bytes(range(len(_PERMUTATION_SAMPLE)))

_V1442_LPH_PARAMS = {
    "steps": ["mask", "block_rotate", "inblock_permute", "rotate", "xor_mix"],
    "mask": {"mode": "xor", "value": 0x3C},
    "block_rotate": {"size": 8, "shift": 3, "direction": "right"},
    "inblock_permute": {"block_size": 4, "table": [1, 3, 0, 2]},
    "rotate": {"amount": 1, "direction": "left"},
    "xor_mix": {"mode": "rolling", "stride": 2, "seed": b"\x10\x20"},
}
_V1442_LPH_PAYLOAD = bytes.fromhex("20303878301e38380030383830203838")
_V1442_DECODED = bytes(range(1, 17))
_V1442_PRGA_KEY = bytes([0x10, 0x2A, 0x5C, 0x7F])
_V1442_PRGA_EXPECTED = bytes.fromhex("118935f8158ef5f0198bb5e81d8875e0")


def _apply_permutation(data: bytes, table: Sequence[int]) -> bytes:
    """Apply ``table`` so that ``result[i] = data[table[i]]``."""

    if len(data) != len(table):
        raise ValueError("permutation table must match data length")
    return bytes(data[int(target)] for target in table)


def _invert_permutation(table: Sequence[int]) -> List[int]:
    """Return the inverse permutation for ``table``."""

    inverse = [0] * len(table)
    for idx, target in enumerate(table):
        inverse[int(target)] = idx
    return inverse


def _run_permutation_roundtrip_check() -> SanityCheckResult:
    permuted = _apply_permutation(_PERMUTATION_INPUT, _PERMUTATION_SAMPLE)
    inverse = _invert_permutation(_PERMUTATION_SAMPLE)
    restored = _apply_permutation(permuted, inverse)
    passed = restored == _PERMUTATION_INPUT
    detail = "inverse permutation restored original bytes" if passed else "permutation round-trip failed"
    return SanityCheckResult("Permutation round-trip", passed, detail)


def _run_v1442_pipeline_check() -> SanityCheckResult:
    decoded = reverse_lph(_V1442_LPH_PAYLOAD, _V1442_LPH_PARAMS)
    if decoded != _V1442_DECODED:
        return SanityCheckResult(
            "LPH reverse (v14.4.2)",
            False,
            "reverse_lph output mismatch",
        )

    result = apply_prga(decoded, _V1442_PRGA_KEY)
    passed = result == _V1442_PRGA_EXPECTED
    detail = "reverse_lph + PRGA matched expected parity" if passed else "PRGA parity mismatch"
    return SanityCheckResult("LPH + PRGA parity (v14.4.2)", passed, detail)


def _render_markdown(results: Iterable[SanityCheckResult], *, run_name: str, timestamp: datetime) -> str:
    lines = [
        f"# Sanity Check Report — {run_name}",
        "",
        f"Generated: {timestamp.isoformat()}Z",
        "",
    ]
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"- **{status}** {result.name}: {result.detail}")
    lines.append("")
    summary = "PASS" if all(r.passed for r in results) else "FAIL"
    lines.append(f"Overall: {summary}")
    lines.append("")
    return "\n".join(lines)


def run_sanity_checks(*, output_dir: Path, run_name: str | None = None) -> Path:
    """Execute the built-in sanity checks and return the report path."""

    timestamp = datetime.utcnow()
    name = run_name or timestamp.strftime("run-%Y%m%d-%H%M%S")
    results = [
        _run_permutation_roundtrip_check(),
        _run_v1442_pipeline_check(),
    ]

    report_dir = output_dir / "sanity"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / f"{name}.md"
    report_content = _render_markdown(results, run_name=name, timestamp=timestamp)
    report_path.write_text(report_content, encoding="utf-8")

    LOGGER.info("Sanity checks written to %s", report_path)
    return report_path


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic sanity checks.")
    parser.add_argument("--output-dir", type=Path, default=Path("out"), help="Directory for sanity reports")
    parser.add_argument("--run-name", help="Optional run identifier used for the report filename")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point used by ``python -m src.tools.sanity_checks``."""

    args = _build_arg_parser().parse_args(argv)
    run_sanity_checks(output_dir=args.output_dir, run_name=args.run_name)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
