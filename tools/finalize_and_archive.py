#!/usr/bin/env python3
"""Finalise an analysis run and archive the resulting artefacts.

This helper orchestrates the final steps after :mod:`run_all_detection` has
produced analysis data inside an ``out/`` directory.  It performs the
following actions:

* run the prettifier pipeline (``emit_pretty.sh``) so the prettified Lua is
  up-to-date;
* assemble a run manifest using :mod:`src.tools.generate_run_manifest` and
  persist it in ``runs/``;
* validate that no artefacts contain leaked key material via
  :mod:`src.tools.ensure_no_keys`;
* package the run into a sanitised ZIP archive using
  :mod:`src.tools.export_results_zip`;
* print a short summary for human reviewers.

The command refuses to proceed if leaked key material is discovered and never
persists session keys.  A ``--tag`` option is provided so callers can annotate
the manifest and summary with the detected Luraph version (e.g. ``14.4.2`` for
``Obfuscated3.lua``).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from src.tools.ensure_no_keys import EnsureNoKeysError, KeyLeakError, ensure_no_keys
from src.tools.export_results_zip import ExportSummary, export_results_zip
from src.tools.generate_run_manifest import (
    RunManifest,
    build_run_manifest,
    write_run_manifest,
)


LOGGER = logging.getLogger("finalize")


@dataclass(slots=True)
class FinalizeContext:
    """Collected information about the current run."""

    out_dir: Path
    runs_dir: Path
    target: str
    version_tag: str | None
    timestamp: datetime


def _run_emit_pretty(out_dir: Path, *, force: bool) -> None:
    script_path = PROJECT_ROOT / "src" / "tools" / "emit_pretty.sh"
    if not script_path.exists():
        raise FileNotFoundError(f"emit_pretty script not found at {script_path}")

    cmd = ["bash", str(script_path), "--out-dir", str(out_dir)]
    if force:
        cmd.append("--force")

    LOGGER.info("Running prettifier pipeline: %s", " ".join(cmd))
    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(PROJECT_ROOT))
    subprocess.run(cmd, check=True, env=env)


def _load_json(path: Path, *, required: bool = False, default: object | None = None) -> object:
    if not path.exists():
        if required:
            raise FileNotFoundError(f"Required artefact missing: {path}")
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _normalise_candidate_files(out_dir: Path, entries: Sequence[object] | None) -> List[Path]:
    paths: List[Path] = []
    if entries:
        for entry in entries:
            candidate = Path(str(entry))
            if not candidate.is_absolute():
                candidate = (out_dir / candidate).resolve()
            paths.append(candidate)
    if not paths:
        candidate_dir = out_dir / "opcode_maps"
        if candidate_dir.exists():
            paths.extend(sorted(candidate_dir.glob("*.json")))
    return paths


def _collect_artefact_map(out_dir: Path) -> Dict[str, Path]:
    candidates: Mapping[str, Iterable[str]] = {
        "raw_payload": ["raw_payload.txt", "raw_payload.bin"],
        "raw_manifest": ["raw_manifest.json"],
        "bootstrap_chunks": ["bootstrap_chunks.json"],
        "bootstrap_candidates": ["bootstrap_candidates.json"],
        "bytes_meta": ["bytes/meta.json"],
        "pipeline_report": ["pipeline_candidates.json"],
        "mapping_report": ["mapping_candidates.json"],
        "opcode_proposals": ["opcode_proposals.json"],
        "opcode_maps": ["opcode_maps"],
        "opcode_annotations": ["opcode_annotations.md"],
        "parity_report": ["parity_report.md"],
        "transform_profile": ["transform_profile.json"],
        "user_report": ["user_report.md"],
        "recommendations": ["recommendations.md"],
        "detection_report": ["detection_report.md"],
        "deobfuscated_pretty": ["deobfuscated_pretty.lua"],
        "run_manifest": ["runs"],
    }

    artefacts: Dict[str, Path] = {}
    for key, relative_candidates in candidates.items():
        for candidate in relative_candidates:
            path = (out_dir / candidate).resolve()
            if path.exists():
                artefacts[key] = path
                break
    return artefacts


def _build_manifest(
    context: FinalizeContext, *, pipeline_report: Mapping[str, object]
) -> RunManifest:
    out_dir = context.out_dir

    mapping_path = out_dir / "mapping_candidates.json"
    mapping_report = _load_json(mapping_path, default={})
    if not isinstance(mapping_report, MutableMapping):
        mapping_report = {}

    candidate_maps: Sequence[Mapping[str, object]] = []
    raw_candidates = pipeline_report.get("opcode_map_candidates")
    if isinstance(raw_candidates, Sequence):
        candidate_maps = [
            entry for entry in raw_candidates if isinstance(entry, MutableMapping)
        ]

    candidate_files = _normalise_candidate_files(
        out_dir, pipeline_report.get("opcode_map_files") if isinstance(pipeline_report, Mapping) else None
    )

    parity_summary = pipeline_report.get("parity_summary")
    if not isinstance(parity_summary, Mapping):
        parity_summary = None

    artefact_map = _collect_artefact_map(out_dir)

    manifest = build_run_manifest(
        target=context.target,
        pipeline_report=pipeline_report,
        mapping_report=mapping_report if isinstance(mapping_report, Mapping) else {},
        artefact_paths=artefact_map,
        candidate_maps=candidate_maps,
        candidate_map_files=candidate_files,
        parity_summary=parity_summary,
        version_hint=context.version_tag or pipeline_report.get("version_hint"),
        timestamp=context.timestamp,
    )
    return manifest


def _write_manifest(context: FinalizeContext, manifest: RunManifest) -> Path:
    runs_dir = context.runs_dir
    runs_dir.mkdir(parents=True, exist_ok=True)
    return write_run_manifest(runs_dir=runs_dir, manifest=manifest)


def _export_results(context: FinalizeContext) -> ExportSummary:
    return export_results_zip(
        source_dir=context.out_dir,
        runs_dir=context.runs_dir,
        timestamp=context.timestamp,
    )


def _scan_for_keys(base_dirs: Sequence[Path]) -> None:
    for directory in base_dirs:
        try:
            ensure_no_keys(directory)
        except KeyLeakError as exc:
            for violation in exc.violations:
                LOGGER.error("Forbidden key field: %s", violation)
            raise
        except EnsureNoKeysError:
            raise


def _print_summary(manifest: RunManifest, manifest_path: Path, summary: ExportSummary, context: FinalizeContext) -> None:
    tag_text = context.version_tag or manifest.version_hint or "unknown"
    print("Finalisation complete")
    print(f"  Run ID       : {manifest.run_id}")
    print(f"  Target       : {manifest.target}")
    print(f"  Version tag  : {tag_text}")
    print(f"  Manifest     : {manifest_path}")
    print(f"  Archive      : {summary.archive_path}")
    print(f"  Files archived: {len(summary.included)} (skipped {len(summary.skipped)})")


def _determine_target(args: argparse.Namespace, pipeline_report: Mapping[str, object] | None) -> str:
    if args.target:
        return str(args.target)
    if pipeline_report and isinstance(pipeline_report.get("target"), str):
        return str(pipeline_report["target"])
    return "unknown-target"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=Path("out"), help="Directory containing pipeline outputs")
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"), help="Directory where manifests and archives are stored")
    parser.add_argument("--target", type=str, default="", help="Name of the analysed input file")
    parser.add_argument("--tag", type=str, default="", help="Version tag to record (e.g. 14.4.2)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing prettified output if necessary")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    out_dir = (PROJECT_ROOT / args.out_dir).resolve() if not args.out_dir.is_absolute() else args.out_dir.resolve()
    runs_dir = (PROJECT_ROOT / args.runs_dir).resolve() if not args.runs_dir.is_absolute() else args.runs_dir.resolve()

    if not out_dir.exists():
        raise SystemExit(f"Output directory {out_dir} does not exist")

    timestamp = datetime.utcnow()

    context = FinalizeContext(
        out_dir=out_dir,
        runs_dir=runs_dir,
        target="",  # determined below
        version_tag=args.tag.strip() or None,
        timestamp=timestamp,
    )

    _run_emit_pretty(out_dir, force=args.force)

    pipeline_path = out_dir / "pipeline_candidates.json"
    pipeline_report = _load_json(pipeline_path, required=True, default={})
    if not isinstance(pipeline_report, MutableMapping):
        raise SystemExit(f"Unexpected pipeline report format in {pipeline_path}")

    context.target = _determine_target(args, pipeline_report)

    manifest = _build_manifest(context, pipeline_report=pipeline_report)
    manifest_path = _write_manifest(context, manifest)

    try:
        _scan_for_keys([out_dir, runs_dir])
    except EnsureNoKeysError:
        if manifest_path.exists():
            manifest_path.unlink()
        raise SystemExit("Sensitive key material detected; aborting finalisation")

    export_summary = _export_results(context)

    try:
        _scan_for_keys([runs_dir])
    except EnsureNoKeysError:
        if export_summary.archive_path.exists():
            export_summary.archive_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        raise SystemExit("Sensitive key material detected after archiving; aborting")

    _print_summary(manifest, manifest_path, export_summary, context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
