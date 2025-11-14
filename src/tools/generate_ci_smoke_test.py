"""Generate smoke-test runs that ensure the detection pipeline does not crash."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from ..io.loader import DEFAULT_EXTRACTION_THRESHOLD
from .run_all_detection import ArtefactPaths, run_detection

LOGGER = logging.getLogger(__name__)

__all__ = [
    "SmokeScenario",
    "SmokeTestResult",
    "SmokeTestReport",
    "default_scenarios",
    "run_smoke_tests",
    "main",
]


@dataclass(slots=True)
class SmokeScenario:
    """Definition of a single smoke-test input case."""

    name: str
    description: str
    payload: str


@dataclass(slots=True)
class SmokeTestResult:
    """Outcome for a smoke-test scenario."""

    scenario: SmokeScenario
    output_dir: Path
    success: bool
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    artefacts: Optional[ArtefactPaths] = None


@dataclass(slots=True)
class SmokeTestReport:
    """Summary of all smoke-test runs."""

    output_dir: Path
    results: List[SmokeTestResult]
    report_path: Path

    @property
    def success(self) -> bool:
        return all(result.success for result in self.results)


def default_scenarios() -> List[SmokeScenario]:
    """Return built-in smoke-test scenarios."""

    return [
        SmokeScenario(
            name="empty",
            description="Empty Lua file should not crash the pipeline",
            payload="",
        ),
        SmokeScenario(
            name="whitespace",
            description="Whitespace-only input should be handled",
            payload="\n    \n-- comment only\n",
        ),
        SmokeScenario(
            name="truncated_string",
            description="Malformed string literal should still produce artefacts",
            payload="local value = \"unterminated\nreturn value",
        ),
    ]


def _write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _record_artefact_presence(result: SmokeTestResult) -> None:
    artefacts = result.artefacts
    if artefacts is None:
        return

    required = {
        "raw_payload": artefacts.raw_payload,
        "manifest": artefacts.manifest_json,
        "bootstrap": artefacts.chunks_json,
        "pipeline": artefacts.pipeline_json,
        "report": artefacts.report_md,
    }
    for label, path in required.items():
        if not path.exists():
            result.notes.append(f"Missing expected artefact: {label} ({path})")


def _serialise_result(result: SmokeTestResult) -> dict:
    artefact_paths: dict[str, str] = {}
    if result.artefacts is not None:
        artefact_paths = {
            "output_dir": str(result.artefacts.output_dir),
            "report": str(result.artefacts.report_md),
            "pipeline": str(result.artefacts.pipeline_json),
        }
    return {
        "scenario": result.scenario.name,
        "description": result.scenario.description,
        "success": result.success,
        "notes": result.notes,
        "error": result.error,
        "output_dir": str(result.output_dir),
        "artefacts": artefact_paths,
    }


def run_smoke_tests(
    *,
    scenarios: Optional[Sequence[SmokeScenario]] = None,
    output_dir: Path = Path("out/ci_smoke"),
    threshold: int = DEFAULT_EXTRACTION_THRESHOLD,
    keep_samples: bool = True,
) -> SmokeTestReport:
    """Execute smoke tests for the detection pipeline."""

    scenario_list = list(scenarios) if scenarios is not None else default_scenarios()
    if not scenario_list:
        raise ValueError("at least one scenario must be provided for smoke testing")

    output_dir = Path(output_dir)
    samples_dir = output_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    results: List[SmokeTestResult] = []

    for scenario in scenario_list:
        sample_path = samples_dir / f"{scenario.name}.lua"
        _write_text(sample_path, scenario.payload)
        scenario_output = output_dir / scenario.name

        LOGGER.info("Running smoke scenario %s", scenario.name)
        smoke_result = SmokeTestResult(
            scenario=scenario,
            output_dir=scenario_output,
            success=False,
            notes=[],
        )
        try:
            artefacts = run_detection(
                sample_path,
                output_dir=scenario_output,
                threshold=threshold,
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            LOGGER.exception("Smoke test %s failed", scenario.name)
            smoke_result.error = str(exc)
            smoke_result.notes.append("Pipeline raised an exception")
        else:
            smoke_result.artefacts = artefacts
            smoke_result.success = True
            _record_artefact_presence(smoke_result)

        results.append(smoke_result)

        if not keep_samples:
            try:
                sample_path.unlink()
            except OSError:  # pragma: no cover - cleanup best-effort
                LOGGER.debug("Unable to delete sample %s", sample_path)

    report_path = output_dir / "smoke_report.json"
    payload = {
        "success": all(result.success for result in results),
        "scenarios": [_serialise_result(result) for result in results],
    }
    _write_json(report_path, payload)

    return SmokeTestReport(output_dir=output_dir, results=results, report_path=report_path)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate CI smoke-test runs for the detection pipeline.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/ci_smoke"),
        help="Directory where smoke artefacts are written (default: out/ci_smoke).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_EXTRACTION_THRESHOLD,
        help="Extraction threshold used by the loader (default: %(default)s).",
    )
    parser.add_argument(
        "--remove-samples",
        action="store_true",
        help="Delete temporary sample inputs after running the smoke tests.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    report = run_smoke_tests(
        output_dir=args.output_dir,
        threshold=args.threshold,
        keep_samples=not args.remove_samples,
    )

    for result in report.results:
        status = "PASS" if result.success else "FAIL"
        LOGGER.info("[%s] %s", status, result.scenario.description)
        for note in result.notes:
            LOGGER.info("    note: %s", note)
        if result.error:
            LOGGER.info("    error: %s", result.error)

    LOGGER.info("Smoke report written to %s", report.report_path)
    return 0 if report.success else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
