"""Local CI orchestration for the static Luraph analysis pipeline.

This helper stitches together the loader, bootstrap extractor, byte extractor,
collector, and parity harness so that contributors can sanity-check changes
quickly.  The default configuration targets the synthetic samples that ship with
this repository and writes results under ``out/ci_results``.  All analysis is
static; payloads are never executed and any optional parity keys are redacted
before reports are written.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from ..bootstrap.extract_bootstrap import identify_bootstrap_candidates
from ..io.loader import DEFAULT_EXTRACTION_THRESHOLD, load_lua_file
from .byte_extractor import generate_candidate_bytes
from .collector import collect_pipeline_candidates
from .parity_reporter import load_parity_report
from .parity_test import DEFAULT_COMPARE_LIMIT, ParityMismatchError, run_prga_parity
from .ensure_no_keys import ensure_no_keys, KeyLeakError
from .validate_json_schema import SchemaValidationError, validate_json_directory

LOGGER = logging.getLogger(__name__)

__all__ = ["CiSampleResult", "CiRunResult", "run_ci_pipeline", "main"]


@dataclass(slots=True)
class CiSampleResult:
    """Summary of artefacts generated for a single sample file."""

    sample: Path
    output_dir: Path
    raw_payload: Path
    manifest_path: Path
    bootstrap_candidates: Path
    bytes_metadata: Path
    pipeline_report: Path
    notes: List[str]


@dataclass(slots=True)
class CiRunResult:
    """Aggregate result for a CI pipeline run."""

    output_dir: Path
    summary_path: Path
    samples: List[CiSampleResult]
    parity_report: Optional[Path]
    parity_success: Optional[bool]


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Wrote %s", path)


def _write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")
    LOGGER.info("Wrote %s", path)


def _timestamped_output(base: Path, nightly: bool) -> Path:
    if not nightly:
        return base
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return base / "nightly" / stamp


def _run_sample(
    sample: Path,
    output_dir: Path,
    *,
    threshold: int,
) -> CiSampleResult:
    LOGGER.info("Running CI pipeline for %s", sample)
    sample_output = output_dir / sample.stem
    payload_dir = sample_output / "payloads"
    raw_payload_path = sample_output / "raw_payload.txt"
    manifest_path = sample_output / "raw_manifest.json"
    bootstrap_path = sample_output / "bootstrap_candidates.json"
    pipeline_path = sample_output / "pipeline_candidates.json"

    sample_output.mkdir(parents=True, exist_ok=True)

    raw_text, extracted, manifest = load_lua_file(
        sample,
        threshold=threshold,
        output_dir=payload_dir,
        include_manifest=True,
    )
    _write_text(raw_payload_path, raw_text)
    _write_json(manifest_path, manifest)

    candidates = identify_bootstrap_candidates(manifest, raw_text, payload_dir)
    candidate_dicts = [candidate.to_dict() for candidate in candidates]
    _write_json(bootstrap_path, candidate_dicts)

    metadata = generate_candidate_bytes(bootstrap_path, sample_output)
    metadata_path = sample_output / "bytes" / "meta.json"

    pipeline_report = collect_pipeline_candidates(
        candidate_dicts,
        manifest=manifest,
        byte_metadata=metadata,
        source_path=sample,
    )
    _write_json(pipeline_path, pipeline_report)

    notes: List[str] = []
    if not candidate_dicts:
        notes.append("No bootstrap candidates detected.")
    if not metadata:
        notes.append("No byte payloads decoded.")
    if not pipeline_report.get("pipelines"):
        notes.append("No pipeline candidates identified.")

    return CiSampleResult(
        sample=sample,
        output_dir=sample_output,
        raw_payload=raw_payload_path,
        manifest_path=manifest_path,
        bootstrap_candidates=bootstrap_path,
        bytes_metadata=metadata_path,
        pipeline_report=pipeline_path,
        notes=notes,
    )


def _run_parity(parity_sample: Path, output_dir: Path, limit: int) -> tuple[Path, bool]:
    LOGGER.info("Running parity harness for %s", parity_sample)
    report_path = output_dir / "parity_report.md"
    try:
        run_prga_parity(
            parity_sample,
            limit=limit,
            report_path=report_path,
            raise_on_mismatch=True,
            redact_keys=True,
        )
        success = True
    except ParityMismatchError as exc:
        LOGGER.warning("Parity mismatch detected: %s", exc)
        success = False
    except Exception as exc:  # pragma: no cover - defensive guard
        LOGGER.error("Failed to run parity harness: %s", exc)
        success = False

    if report_path.exists():
        try:
            report = load_parity_report(report_path)
        except Exception as exc:  # pragma: no cover - report parsing failure
            LOGGER.debug("Unable to parse parity report %s: %s", report_path, exc)
        else:
            success = report.success
    return report_path, success


def run_ci_pipeline(
    targets: Sequence[Path],
    *,
    parity_sample: Optional[Path] = None,
    output_dir: Path = Path("out/ci_results"),
    threshold: int = DEFAULT_EXTRACTION_THRESHOLD,
    nightly: bool = False,
    parity_limit: int = DEFAULT_COMPARE_LIMIT,
) -> CiRunResult:
    """Execute the local CI pipeline for the provided sample targets."""

    if not targets:
        raise ValueError("at least one target Lua file must be supplied")

    resolved_targets = [Path(target) for target in targets]
    for target in resolved_targets:
        if not target.exists():
            raise FileNotFoundError(f"sample not found: {target}")

    base_output = _timestamped_output(Path(output_dir), nightly)
    base_output.mkdir(parents=True, exist_ok=True)

    results: List[CiSampleResult] = []
    for target in resolved_targets:
        results.append(_run_sample(target, base_output, threshold=threshold))

    parity_report: Optional[Path] = None
    parity_success: Optional[bool] = None
    if parity_sample is not None:
        parity_report, parity_success = _run_parity(
            Path(parity_sample), base_output, parity_limit
        )

    summary = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
        "nightly": nightly,
        "samples": [
            {
                "sample": str(result.sample),
                "output_dir": str(result.output_dir),
                "notes": result.notes,
                "artefacts": {
                    "raw_payload": str(result.raw_payload),
                    "manifest": str(result.manifest_path),
                    "bootstrap_candidates": str(result.bootstrap_candidates),
                    "bytes_metadata": str(result.bytes_metadata),
                    "pipeline_report": str(result.pipeline_report),
                },
            }
            for result in results
        ],
    }
    if parity_report is not None:
        summary["parity"] = {
            "report": str(parity_report),
            "success": parity_success,
        }

    summary_path = base_output / "ci_summary.json"
    _write_json(summary_path, summary)

    try:
        ensure_no_keys(base_output)
    except KeyLeakError as exc:
        for violation in exc.violations:
            LOGGER.error(
                "Forbidden key field detected in CI artefact: %s %s",
                violation.file,
                violation.field_path,
            )
        raise

    try:
        validate_json_directory(base_output)
    except SchemaValidationError as exc:
        for issue in exc.issues:
            LOGGER.error(
                "JSON schema violation in CI artefact: %s %s -> %s",
                issue.file,
                issue.path,
                issue.message,
            )
        raise

    return CiRunResult(
        output_dir=base_output,
        summary_path=summary_path,
        samples=results,
        parity_report=parity_report,
        parity_success=parity_success,
    )


def _default_targets() -> List[Path]:
    candidates = [
        Path("tests/samples/Obfuscated3.lua"),
        Path("tests/samples/minimal_stub.lua"),
    ]
    return [path for path in candidates if path.exists()]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run loader→extractor→byte_extractor→collector→parity for sample payloads."
        )
    )
    parser.add_argument(
        "targets",
        nargs="*",
        type=Path,
        default=None,
        help="Lua samples to analyse (default: repository samples)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/ci_results"),
        help="Destination directory for CI artefacts (default: out/ci_results)",
    )
    parser.add_argument(
        "--parity-sample",
        type=Path,
        default=Path("tests/parity/sample_lph.bin"),
        help="Parity sample description (default: tests/parity/sample_lph.bin)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_EXTRACTION_THRESHOLD,
        help="Loader extraction threshold in bytes (default: %(default)s)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_COMPARE_LIMIT,
        help="Parity comparison limit in bytes (default: %(default)s)",
    )
    parser.add_argument(
        "--nightly",
        action="store_true",
        help="Store artefacts in a timestamped nightly/ directory",
    )
    parser.add_argument(
        "--no-parity",
        action="store_true",
        help="Skip the parity harness (useful when Lua runtime is unavailable)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    targets = args.targets if args.targets else _default_targets()
    parity_sample = None if args.no_parity else args.parity_sample

    try:
        run_ci_pipeline(
            targets,
            parity_sample=parity_sample,
            output_dir=args.output_dir,
            threshold=args.threshold,
            nightly=args.nightly,
            parity_limit=args.limit,
        )
    except FileNotFoundError as exc:
        LOGGER.error(str(exc))
        return 1
    except ValueError as exc:
        LOGGER.error(str(exc))
        return 1

    LOGGER.info("CI pipeline completed; artefacts written to %s", args.output_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
