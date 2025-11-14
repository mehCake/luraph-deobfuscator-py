"""Inspect bootstrap pipeline by combining loader, extractor, and collector.

This module acts as an integration harness for CI.  It coordinates the loader,
bootstrap extractor, and pipeline collector, then validates that the observed
behaviour matches expectations for known Luraph versions (notably v14.4.2 for
``Obfuscated3.lua``).  When anomalies are detected the script fails loudly and
prints concrete follow-up actions.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from ..bootstrap.extract_bootstrap import (
    extract_bootstrap_chunks,
    identify_bootstrap_candidates,
)
from ..io.loader import DEFAULT_EXTRACTION_THRESHOLD, load_lua_file
from ..tools.byte_extractor import generate_candidate_bytes
from ..tools.collector import collect_pipeline_candidates


class InspectionError(RuntimeError):
    """Raised when inspection uncovers unexpected structures."""


def _format_payload_sizes(extracted: Dict[str, str]) -> Sequence[str]:
    lines: List[str] = []
    for name, payload in sorted(extracted.items()):
        size = len(payload.encode("utf-8", errors="ignore"))
        lines.append(f"{name}: {size} bytes")
    return lines


def _summarise_pipeline(report: Dict[str, object]) -> str:
    lines: List[str] = []
    pipeline = report.get("pipeline", [])
    pipeline_conf = float(report.get("pipeline_confidence", 0.0))
    pipeline_hints = report.get("pipeline_hints", []) or []
    lines.append(
        f"Pipeline operations: {len(pipeline)} step(s) | confidence={pipeline_conf:.2f}"
    )
    if pipeline:
        lines.append("  -> " + ", ".join(str(op) for op in pipeline))
    if pipeline_hints:
        lines.append("  hints: " + ", ".join(str(hint) for hint in pipeline_hints))

    for index, chunk in enumerate(report.get("chunks", []), start=1):
        kind = chunk.get("kind", "unknown")
        start = chunk.get("start", "?")
        end = chunk.get("end", "?")
        length = chunk.get("length", "?")
        confidence = float(chunk.get("confidence", 0.0))
        lines.append(
            f"[{index}] {kind} @ {start}-{end} len={length} | confidence={confidence:.2f}"
        )
        operations = chunk.get("operations") or []
        if operations:
            lines.append("     ops: " + ", ".join(str(op) for op in operations))
        hints = chunk.get("hints") or []
        if hints:
            lines.append("     hints: " + ", ".join(str(hint) for hint in hints))
        payload_size = chunk.get("payload_size")
        if payload_size:
            lines.append(f"     payload: {payload_size} bytes")
        error = chunk.get("payload_error")
        if error:
            lines.append(f"     payload_error: {error}")
    return "\n".join(lines)


def _derive_version_hint(path: Path) -> str | None:
    name = path.name.lower()
    if "obfuscated3" in name:
        return "14.4.2"
    if "obfuscated2" in name:
        return "14.4.1"
    if "obfuscated4" in name:
        return "14.4.3"
    return None


def _ensure_version_expectations(
    report: Dict[str, object], *, version_hint: str | None
) -> Iterable[str]:
    pipeline = list(report.get("pipeline", []) or [])
    suggestions: List[str] = []

    if not pipeline:
        raise InspectionError("Pipeline detection produced zero operations")

    if report.get("bootstrap_candidates") in (None, []):
        raise InspectionError("No bootstrap candidates identified")

    if version_hint == "14.4.2":
        expected_ops = {"string.char", "loadstring"}
        missing = expected_ops.difference(pipeline)
        if missing:
            raise InspectionError(
                "v14.4.2 inspection missing expected operations: "
                + ", ".join(sorted(missing))
            )
        if float(report.get("pipeline_confidence", 0.0)) < 0.3:
            raise InspectionError(
                "v14.4.2 pipeline confidence is unexpectedly low (<0.30)"
            )
        suggestions.append(
            "Pipeline shows string.char → loadstring, proceed to byte extraction and PRGA parity tests."
        )
    else:
        suggestions.append(
            "Review detected pipeline operations and adjust heuristics if critical steps are missing."
        )

    if any(chunk.get("resolvable") is False for chunk in report.get("chunks", [])):
        suggestions.append(
            "Some chunks are not statically resolvable; consider enhancing parser_tracer heuristics."
        )

    return suggestions


def _write_detection_report(
    output_dir: Path,
    summary: str,
    suggestions: Sequence[str],
) -> Path:
    report_path = output_dir / "detection_report.md"
    report_lines = ["# Detection Report", "", "## Summary", "", summary, ""]
    if suggestions:
        report_lines.extend(["## Suggested next steps", ""])
        report_lines.extend(f"- {item}" for item in suggestions)
        report_lines.append("")
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    return report_path


def inspect_payload(
    path: Path,
    *,
    output_dir: Path,
    threshold: int = DEFAULT_EXTRACTION_THRESHOLD,
    raw_name: str = "raw_payload.txt",
    manifest_name: str = "raw_manifest.json",
    chunks_name: str = "bootstrap_chunks.json",
    candidates_name: str = "bootstrap_candidates.json",
    bytes_meta_name: str = "meta.json",
    pipeline_name: str = "pipeline_candidates.json",
) -> Dict[str, object]:
    """Run loader → extractor → collector, returning the pipeline report."""

    payload_dir = output_dir / "payloads"
    raw_text, extracted, manifest = load_lua_file(
        path,
        threshold=threshold,
        output_dir=payload_dir,
        include_manifest=True,
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    raw_path = output_dir / raw_name
    raw_path.write_text(raw_text, encoding="utf-8")
    logging.info("Wrote normalised payload to %s", raw_path)

    manifest_path = output_dir / manifest_name
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    logging.info("Wrote manifest to %s", manifest_path)

    chunk_path = output_dir / chunks_name
    chunks = [
        {"kind": chunk.kind, "start": chunk.start, "end": chunk.end, "text": chunk.text}
        for chunk in extract_bootstrap_chunks(raw_text)
    ]
    chunk_path.write_text(json.dumps(chunks, indent=2) + "\n", encoding="utf-8")
    logging.info("Identified %d bootstrap chunk(s)", len(chunks))

    bootstrap_candidates = identify_bootstrap_candidates(manifest, raw_text, payload_dir)
    candidate_dicts = [candidate.to_dict() for candidate in bootstrap_candidates]

    candidate_path = output_dir / candidates_name
    candidate_path.write_text(json.dumps(candidate_dicts, indent=2) + "\n", encoding="utf-8")
    logging.info("Selected %d bootstrap candidate(s)", len(candidate_dicts))

    bytes_dir = output_dir / "bytes"
    bytes_dir.mkdir(parents=True, exist_ok=True)
    try:
        byte_metadata = generate_candidate_bytes(
            candidate_path,
            output_dir,
            meta_filename=bytes_meta_name,
        )
    except Exception as exc:  # pragma: no cover - surfaced later via validation
        logging.warning("Byte extraction failed: %s", exc)
        byte_metadata = []

    report = collect_pipeline_candidates(
        candidate_dicts,
        manifest=manifest,
        byte_metadata=byte_metadata,
        source_path=path,
    )
    report["bootstrap_candidates"] = candidate_dicts
    report["extracted_payloads"] = {
        name: len(payload.encode("utf-8", errors="ignore")) for name, payload in extracted.items()
    }

    pipeline_path = output_dir / pipeline_name
    pipeline_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    summary = _summarise_pipeline(report)
    version_hint = _derive_version_hint(path)
    suggestions = list(_ensure_version_expectations(report, version_hint=version_hint))

    detection_report = _write_detection_report(output_dir, summary, suggestions)
    report["detection_report"] = str(detection_report)
    report["suggestions"] = suggestions
    report["summary"] = summary

    payload_lines = _format_payload_sizes(extracted)
    if payload_lines:
        logging.info("Extracted payloads:\n%s", "\n".join(f"  {line}" for line in payload_lines))
    else:
        logging.info("No payloads exceeded extraction threshold.")

    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run loader, bootstrap extractor, and collector to summarise pipeline candidates.",
    )
    parser.add_argument("path", type=Path, help="Path to a Lua payload (e.g. Obfuscated3.lua)")
    parser.add_argument(
        "--output-dir", type=Path, default=Path("out"), help="Base directory for generated artefacts"
    )
    parser.add_argument(
        "--threshold", type=int, default=DEFAULT_EXTRACTION_THRESHOLD, help="Extraction threshold for loader"
    )
    parser.add_argument(
        "--raw-name", type=str, default="raw_payload.txt", help="Filename for the normalised payload"
    )
    parser.add_argument(
        "--manifest-name", type=str, default="raw_manifest.json", help="Filename for loader manifest"
    )
    parser.add_argument(
        "--chunks-name", type=str, default="bootstrap_chunks.json", help="Filename for legacy chunk report"
    )
    parser.add_argument(
        "--candidates-name", type=str, default="bootstrap_candidates.json", help="Filename for bootstrap candidate report"
    )
    parser.add_argument(
        "--bytes-meta-name", type=str, default="meta.json", help="Filename for byte metadata inside the bytes directory"
    )
    parser.add_argument(
        "--pipeline-name", type=str, default="pipeline_candidates.json", help="Filename for pipeline report"
    )

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        report = inspect_payload(
            args.path,
            output_dir=args.output_dir,
            threshold=args.threshold,
            raw_name=args.raw_name,
            manifest_name=args.manifest_name,
            chunks_name=args.chunks_name,
            candidates_name=args.candidates_name,
            bytes_meta_name=args.bytes_meta_name,
            pipeline_name=args.pipeline_name,
        )
    except InspectionError as exc:
        logging.error("Inspection failed: %s", exc)
        logging.error("Suggested next steps: run with --debug or inspect raw_manifest.json")
        return 1

    logging.info("Pipeline report written to %s", args.output_dir / args.pipeline_name)
    logging.info("Detection report written to %s", report["detection_report"])

    print(report["summary"])
    if report.get("suggestions"):
        print("\nSuggested next steps:")
        for item in report["suggestions"]:
            print(f"  - {item}")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
