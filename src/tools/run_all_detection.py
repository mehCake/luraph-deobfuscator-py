"""Run the full static detection pipeline on a Lua payload.

The orchestrator coordinates loader, bootstrap extraction, byte decoding, and
pipeline heuristics that are tuned for Luraph v14.4.2 by default.  Usage
example::

    python -m src.tools.run_all_detection \
        --file tests/samples/Obfuscated3.lua \
        --output-dir out \
        --debug

All analysis is static – payloads are never executed.  Session keys can be
supplied for parity checks via ``--use-key`` but are held only in-memory and
scrubbed once processing completes.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from ..bootstrap.extract_bootstrap import (
    BootstrapChunk,
    extract_bootstrap_chunks,
    identify_bootstrap_candidates,
)
from ..io.loader import DEFAULT_EXTRACTION_THRESHOLD, load_lua_file
from ..mappings.detect_mappings import detect_mapping_candidates
from ..vm.disassembler import Instruction
from ..vm.opcode_proposer import (
    OpcodeMapCandidate,
    generate_map_candidates,
    group_proposals_by_opcode,
    propose_opcode_mappings,
    render_ir_candidate,
)
from .auto_profile_builder import AutoProfileBuilderError, write_auto_profile
from .backup_manager import BackupPlan, snapshot_analysis_inputs
from .cleanup_on_exit import get_cleanup_manager
from .byte_extractor import generate_candidate_bytes
from .metrics_collector import MetricsCollector
from .collector import collect_pipeline_candidates
from .ensure_license import (
    ensure_license_file,
    ensure_license_headers,
    ensure_output_license,
)
from .ensure_no_keys import ensure_no_keys, KeyLeakError
from .validate_json_schema import SchemaValidationError, validate_json_directory
from .generate_handler_tests import generate_handler_tests
from .heuristics import detect_vm_style, score_base64_string, score_lph_header
from .hypothesis_scoring import score_pipeline_hypothesis
from .retry_on_error import retry_on_error
from .parity_reporter import load_parity_report
from .plugin_hooks import (
    PluginContext,
    PluginExecutionError,
    PluginKeyRequestError,
    PluginValidationError,
    discover_plugins,
    execute_plugins,
)
from .recommendations import (
    build_recommendation_checklist,
    write_recommendation_markdown,
)
from .report_to_user import build_user_summary, write_user_summary
from .visualize_pipeline import generate_pipeline_graphs, render_pipeline_graph
from .annotate_opcodes import generate_opcode_annotations, write_opcode_annotations

LOGGER = logging.getLogger(__name__)

__all__ = ["ArtefactPaths", "run_detection", "main"]


def _scrub_buffer(buffer: Optional[bytearray]) -> None:
    """Zero a bytearray in-place, ignoring ``None`` values."""

    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


def _copy_key_material(value: Optional[str]) -> Optional[bytearray]:
    """Convert an optional key string into a mutable buffer for safe wiping."""

    if value is None:
        return None
    return bytearray(value.encode("utf-8"))


from .generate_run_manifest import (
    build_run_manifest,
    write_run_manifest,
)


@dataclass(slots=True)
class ArtefactPaths:
    """Common output artefact locations."""

    output_dir: Path
    payload_dir: Path
    debug_dir: Path
    payload_debug_dir: Path
    chunk_debug_dir: Path
    raw_payload: Path
    raw_payload_bin: Path
    manifest_json: Path
    chunks_json: Path
    bootstrap_candidates_json: Path
    bytes_meta_json: Path
    pipeline_json: Path
    mapping_json: Path
    opcode_proposals: Path
    opcode_maps_dir: Path
    opcode_annotations_md: Path
    graph_dot: Path
    graphs_dir: Path
    report_md: Path
    ir_candidates_dir: Path
    user_report_md: Path
    recommendations_md: Path
    runs_dir: Path
    handler_tests_dir: Path
    metrics_dir: Path
    handler_tests_manifest: Optional[Path] = None
    handler_tests_definitions: Optional[Path] = None
    run_manifest_path: Optional[Path] = None
    metrics_path: Optional[Path] = None


def _determine_paths(base: Path, report: Optional[Path]) -> ArtefactPaths:
    output_dir = base
    payload_dir = output_dir / "payloads"
    debug_dir = output_dir / "debug"
    payload_debug_dir = debug_dir / "payloads"
    chunk_debug_dir = debug_dir / "chunks"
    raw_payload = output_dir / "raw_payload.txt"
    raw_payload_bin = debug_dir / "raw_payload.bin"
    manifest_json = output_dir / "raw_manifest.json"
    chunks_json = output_dir / "bootstrap_chunks.json"
    bootstrap_candidates_json = output_dir / "bootstrap_candidates.json"
    bytes_meta_json = output_dir / "bytes" / "meta.json"
    pipeline_json = output_dir / "pipeline_candidates.json"
    mapping_json = output_dir / "mapping_candidates.json"
    opcode_proposals = output_dir / "opcode_proposals.json"
    opcode_maps_dir = output_dir / "opcode_maps"
    opcode_annotations_md = output_dir / "opcode_annotations.md"
    graph_dot = output_dir / "pipeline_graph.dot"
    graphs_dir = output_dir / "graphs"
    ir_candidates_dir = output_dir / "ir_candidates"
    user_report_md = output_dir / "user_report.md"
    recommendations_md = output_dir / "recommendations.md"
    report_md = report if report is not None else output_dir / "detection_report.md"
    runs_dir = output_dir / "runs"
    metrics_dir = output_dir / "metrics"

    return ArtefactPaths(
        output_dir=output_dir,
        payload_dir=payload_dir,
        debug_dir=debug_dir,
        payload_debug_dir=payload_debug_dir,
        chunk_debug_dir=chunk_debug_dir,
        raw_payload=raw_payload,
        raw_payload_bin=raw_payload_bin,
        manifest_json=manifest_json,
        chunks_json=chunks_json,
        bootstrap_candidates_json=bootstrap_candidates_json,
        bytes_meta_json=bytes_meta_json,
        pipeline_json=pipeline_json,
        mapping_json=mapping_json,
        opcode_proposals=opcode_proposals,
        opcode_maps_dir=opcode_maps_dir,
        opcode_annotations_md=opcode_annotations_md,
        graph_dot=graph_dot,
        graphs_dir=graphs_dir,
        report_md=report_md,
        ir_candidates_dir=ir_candidates_dir,
        user_report_md=user_report_md,
        recommendations_md=recommendations_md,
        runs_dir=runs_dir,
        handler_tests_dir=output_dir / "handler_tests",
        metrics_dir=metrics_dir,
    )


def _register_cleanup_targets(paths: ArtefactPaths) -> None:
    """Register debug artefacts that should be purged on abnormal exits."""

    manager = get_cleanup_manager()
    for directory in {
        paths.debug_dir,
        paths.payload_debug_dir,
        paths.chunk_debug_dir,
        paths.output_dir / "intermediate",
    }:
        manager.register_temp_path(directory, secure_wipe=False)

    manager.register_temp_path(paths.raw_payload_bin, secure_wipe=True)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Wrote %s", path)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    LOGGER.info("Wrote %s", path)


def _load_instruction_dump(path: Path) -> List[Instruction]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - defensive
        LOGGER.debug("Failed to load instruction dump %s: %s", path, exc)
        return []
    instructions: List[Instruction] = []
    for index, entry in enumerate(payload):
        if not isinstance(entry, Mapping):
            continue
        try:
            opcode = int(entry.get("opcode", entry.get("opnum", 0)))
            a = int(entry.get("a", entry.get("A", 0)) or 0)
            b = int(entry.get("b", entry.get("B", 0)) or 0)
            c = int(entry.get("c", entry.get("C", 0)) or 0)
            pc = int(entry.get("pc", entry.get("index", index)))
        except Exception:  # pragma: no cover - coercion failure
            continue
        raw_value = entry.get("raw")
        raw_int = 0
        if isinstance(raw_value, int):
            raw_int = raw_value
        elif isinstance(raw_value, str):
            try:
                raw_int = int(raw_value, 0)
            except ValueError:
                raw_int = 0
        instruction = Instruction(index=pc, raw=raw_int, opcode=opcode, a=a, b=b, c=c)
        instructions.append(instruction)
    return instructions


def _write_ir_candidates(destination: Path, rendered: Sequence[str]) -> None:
    if not rendered:
        return
    destination.mkdir(parents=True, exist_ok=True)
    for index, text in enumerate(rendered, start=1):
        path = destination / f"candidate_{index:02d}.md"
        _write_text(path, text)


def _write_opcode_map_candidates(
    destination: Path, candidates: Sequence[OpcodeMapCandidate]
) -> List[Path]:
    """Persist candidate opcode maps to disk and return the written paths."""

    if not candidates:
        return []

    destination.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for index, candidate in enumerate(candidates, start=1):
        path = destination / f"candidate_{index:02d}.json"
        _write_json(path, candidate.as_dict())
        written.append(path)
    return written


def _chunk_to_mapping(chunk: BootstrapChunk) -> Dict[str, object]:
    return {
        "kind": chunk.kind,
        "start": chunk.start,
        "end": chunk.end,
        "text": chunk.text,
    }


def _format_payload_entry(name: str, payload: str) -> Tuple[str, List[str]]:
    payload_bytes = payload.encode("latin-1", errors="ignore")
    size = len(payload_bytes)
    heuristics: List[str] = []
    base64_score = score_base64_string(payload)
    if base64_score >= 0.5:
        heuristics.append(f"base64-likelihood={base64_score:.2f}")
    lph_score = score_lph_header(payload_bytes)
    if lph_score >= 0.5:
        heuristics.append(f"lph-header-likelihood={lph_score:.2f}")
    return f"**{name}** — {size} bytes", heuristics


def _format_chunk_table(chunks: Sequence[Mapping[str, object]]) -> List[str]:
    if not chunks:
        return ["No bootstrap chunks detected."]

    headers = "| # | Kind | Range | Length | Confidence | Hints |"
    separator = "|:-:|:-----|:------|:------:|:----------:|:------|"
    lines = [headers, separator]
    for index, chunk in enumerate(chunks, start=1):
        kind = str(chunk.get("kind", "?"))
        start = chunk.get("start", "?")
        end = chunk.get("end", "?")
        length = chunk.get("length", "?")
        confidence = chunk.get("confidence")
        hints = chunk.get("hints") or []
        hints_text = ", ".join(str(hint) for hint in hints)
        if isinstance(confidence, (int, float)):
            confidence_text = f"{confidence:.2f}"
        else:
            confidence_text = "?"
        range_text = f"{start}–{end}" if start != "?" and end != "?" else "?"
        lines.append(
            f"| {index} | {kind} | {range_text} | {length} | {confidence_text} | {hints_text} |"
        )
    return lines


def _summarise_pipeline(report: Mapping[str, object]) -> List[str]:
    pipeline = report.get("pipeline") or []
    confidence = report.get("pipeline_confidence", 0.0)
    hints = report.get("pipeline_hints") or []
    checksum_summary = report.get("checksum_summary") or {}
    opcode_handlers = report.get("opcode_handlers") or {}
    opcode_mnemonics = report.get("opcode_mnemonics") or {}
    opcode_candidates = report.get("opcode_map_candidates") or []

    lines = [
        f"Pipeline steps: {len(pipeline)} | confidence={float(confidence):.2f}",
    ]
    if pipeline:
        joined = ", ".join(str(step) for step in pipeline)
        lines.append(f"Sequence: `{joined}`")
    if hints:
        lines.append("Hints: " + ", ".join(str(hint) for hint in hints))
    vm_style = report.get("vm_style")
    if isinstance(vm_style, Mapping):
        style = str(vm_style.get("style", "unknown"))
        conf = float(vm_style.get("confidence", 0.0))
        lines.append(f"VM style heuristic: {style} (confidence {conf:.2f})")
    dispatcher_count = int(report.get("dispatcher_cfg_count", 0))
    if dispatcher_count:
        lines.append(f"Recovered dispatcher CFGs: {dispatcher_count}")
    total_checksums = int(checksum_summary.get("total", 0))
    if total_checksums:
        valid = int(checksum_summary.get("valid", 0))
        invalid = int(checksum_summary.get("invalid", total_checksums - valid))
        lines.append(
            f"Checksum validations: {valid}/{total_checksums} valid, {invalid} mismatch"
        )
    if opcode_handlers:
        def _opcode_key(item: str) -> tuple[int, int | str]:
            text = str(item)
            try:
                return (0, int(text, 0))
            except ValueError:
                return (1, text)

        entries: List[str] = []
        for opcode in sorted(opcode_handlers.keys(), key=_opcode_key):
            names = opcode_handlers[opcode]
            mnemonic_candidates = opcode_mnemonics.get(opcode) or opcode_mnemonics.get(
                str(opcode)
            )
            entry = f"{opcode}: {', '.join(names)}"
            if mnemonic_candidates:
                entry += f" -> {', '.join(mnemonic_candidates)}"
            entries.append(entry)
        if entries:
            lines.append("Opcode handlers: " + "; ".join(entries))
    if opcode_candidates:
        best_candidate = opcode_candidates[0]
        best_conf = float(best_candidate.get("confidence", 0.0))
        mapping = best_candidate.get("mapping") or {}
        preview: List[str] = []
        for opcode_key in sorted(mapping.keys(), key=lambda item: int(item, 0) if isinstance(item, str) else int(item)):
            mnemonic = mapping[opcode_key]
            preview.append(f"{opcode_key}->{mnemonic}")
            if len(preview) >= 5:
                break
        if preview:
            lines.append(
                "Top opcode map candidate: conf={:.2f} | {}".format(
                    best_conf, ", ".join(preview)
                )
            )
        else:
            lines.append(f"Top opcode map candidate: conf={best_conf:.2f}")
    return lines


def _summarise_mappings(report: Mapping[str, object], *, limit_pairs: int = 5) -> List[str]:
    tables = report.get("tables") or []
    total_tables = int(report.get("total_tables", 0))
    total_pairs = int(report.get("total_pairs", 0))
    lines = [f"Detected tables: {total_tables} | observed pairs: {total_pairs}"]
    if not tables:
        lines.append("No mapping candidates identified.")
        return lines

    for table in tables:
        name = str(table.get("name", "?"))
        confidence = float(table.get("confidence", 0.0))
        samples = int(table.get("samples", 0))
        permutation = float(table.get("permutation_score", 0.0))
        hints = table.get("hints") or []
        lines.append(
            f"- **{name}** — confidence={confidence:.2f}, samples={samples}, permutation={permutation:.2f}"
        )
        if hints:
            lines.append("  - hints: " + ", ".join(str(hint) for hint in hints))
        pairs = table.get("pairs") or []
        for pair in pairs[:limit_pairs]:
            index = pair.get("index")
            value = pair.get("value")
            score = float(pair.get("score", 0.0))
            support = pair.get("support")
            total = pair.get("total")
            lines.append(
                f"  - index {index} → {value} | score={score:.2f} (support {support}/{total})"
            )
        if len(pairs) > limit_pairs:
            lines.append(f"  - … {len(pairs) - limit_pairs} additional pair(s) omitted")
    return lines


def _summarise_chunk_checksums(
    chunks: Sequence[Mapping[str, object]]
) -> List[str]:
    """Produce Markdown bullet points describing checksum validation results."""

    lines: List[str] = []
    for index, chunk in enumerate(chunks, start=1):
        checksums = chunk.get("checksums") or []
        if not checksums:
            continue
        chunk_name = str(chunk.get("kind", "?"))
        range_text = f"{chunk.get('start', '?')}–{chunk.get('end', '?')}"
        lines.append(f"- Chunk {index} ({chunk_name}, {range_text})")
        for checksum in checksums:
            name = str(checksum.get("name", "?"))
            valid = bool(checksum.get("valid", False))
            confidence = float(checksum.get("confidence", 0.0))
            status = "valid" if valid else "mismatch"
            offset = checksum.get("offset", "?")
            expected = checksum.get("expected", b"")
            actual = checksum.get("actual", b"")
            if isinstance(expected, str):
                expected_bytes = expected.encode("latin-1", errors="ignore")
            else:
                expected_bytes = bytes(expected)
            if isinstance(actual, str):
                actual_bytes = actual.encode("latin-1", errors="ignore")
            else:
                actual_bytes = bytes(actual)
            lines.append(
                "  - {} @ offset {} — {} (confidence {:.2f})".format(
                    name,
                    offset,
                    status,
                    confidence,
                )
            )
            if not valid:
                lines.append(
                    "    - expected: {} | actual: {}".format(
                        expected_bytes.hex(), actual_bytes.hex()
                    )
                )
    if not lines:
        return ["- No checksum trailers detected."]
    return lines


def _render_report(
    *,
    target: Path,
    artefacts: ArtefactPaths,
    extracted: Mapping[str, str],
    pipeline_report: Mapping[str, object],
    mapping_report: Mapping[str, object],
) -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = [
        f"# Detection Report: {target.name}",
        "",
        f"Generated: {timestamp}",
        "",
        "## Artefacts",
        f"- Normalised payload: `{artefacts.raw_payload}`",
        f"- Bootstrap chunks: `{artefacts.chunks_json}`",
        f"- Pipeline candidates: `{artefacts.pipeline_json}`",
        f"- Mapping candidates: `{artefacts.mapping_json}`",
        f"- Opcode proposals: `{artefacts.opcode_proposals}`",
        f"- Opcode map candidates: `{artefacts.opcode_maps_dir}`",
        f"- Pipeline graph: `{artefacts.graph_dot}`",
        f"- Pipeline graphs (SVG): `{artefacts.graphs_dir}`",
        f"- Payload extracts: `{artefacts.payload_dir}`",
        f"- IR candidates: `{artefacts.ir_candidates_dir}`",
        "",
    ]

    lines.append("## Extracted Payloads")
    if extracted:
        for name, payload in sorted(extracted.items()):
            description, heuristics = _format_payload_entry(name, payload)
            lines.append(f"- {description}")
            for hint in heuristics:
                lines.append(f"  - {hint}")
    else:
        lines.append("- No payloads exceeded extraction threshold.")
    lines.append("")

    lines.append("## Pipeline Summary")
    lines.extend(_summarise_pipeline(pipeline_report))
    lines.append("")

    chunk_section = pipeline_report.get("chunks")
    if isinstance(chunk_section, Sequence):
        lines.append("### Bootstrap Chunks")
        lines.extend(_format_chunk_table(chunk_section))
        lines.append("")
        lines.append("### Checksum Validation")
        lines.extend(_summarise_chunk_checksums(chunk_section))
        lines.append("")

    lines.append("## Mapping Candidates")
    lines.extend(_summarise_mappings(mapping_report))
    lines.append("")

    lines.append("## Notes")
    lines.append(
        "- This report is generated using static detectors only; dynamic execution is never performed."
    )
    lines.append(
        "- Confidence scores are heuristic and should be validated against known-good samples."
    )
    lines.append("")

    return "\n".join(lines)


def run_detection(
    target: Path,
    *,
    output_dir: Path,
    threshold: int = DEFAULT_EXTRACTION_THRESHOLD,
    report_path: Optional[Path] = None,
    debug: bool = False,
    session_key: Optional[bytearray] = None,
    plugins: Optional[Sequence[str]] = None,
    plugin_search_dir: Optional[Path] = None,
) -> ArtefactPaths:
    """Run loader, extractors, detectors, and optional plugins for a payload."""

    artefacts = _determine_paths(output_dir, report_path)
    _register_cleanup_targets(artefacts)

    repo_root = Path(__file__).resolve().parents[2]
    license_path, _ = ensure_license_file(repo_root)

    metrics = MetricsCollector()

    target_path = Path(target)
    metrics.observe("threshold_bytes", threshold)
    metrics.observe("debug_enabled", bool(debug))
    metrics.observe("plugins_requested", len(plugins or []))
    metrics.observe("session_key_provided", session_key is not None)
    try:
        metrics.observe("input_size_bytes", target_path.stat().st_size)
    except OSError:  # pragma: no cover - filesystem race
        LOGGER.debug("Unable to stat input file %s for metrics", target_path)
    original_bytes: Optional[bytes] = None
    if debug:
        try:
            original_bytes = retry_on_error(
                target_path.read_bytes,
                retries=2,
                base_delay=0.1,
                exceptions=(OSError,),
                logger=LOGGER,
                operation="read original payload",
            )
        except OSError as exc:  # pragma: no cover - filesystem failure
            LOGGER.debug("Unable to read original payload bytes: %s", exc)

    key_buffer = session_key
    cleanup_manager = get_cleanup_manager()
    cleanup_manager.register_key_buffer("session_key", key_buffer)

    success = False
    try:
        raw_text, extracted, manifest = retry_on_error(
            lambda: load_lua_file(
                target_path,
                threshold=threshold,
                output_dir=artefacts.payload_dir,
                include_manifest=True,
            ),
            retries=3,
            base_delay=0.2,
            exceptions=(OSError,),
            logger=LOGGER,
            operation="load Lua payload",
        )
        _write_text(artefacts.raw_payload, raw_text)
        _write_json(artefacts.manifest_json, manifest)

        metrics.record_count("extracted_payloads", len(extracted))
        if isinstance(manifest, Mapping):
            metrics.record_count("manifest_entries", len(manifest))
        elif isinstance(manifest, Sequence) and not isinstance(manifest, (str, bytes)):
            metrics.record_count("manifest_entries", len(manifest))

        if debug:
            artefacts.debug_dir.mkdir(parents=True, exist_ok=True)
            artefacts.payload_debug_dir.mkdir(parents=True, exist_ok=True)
            artefacts.chunk_debug_dir.mkdir(parents=True, exist_ok=True)
            if original_bytes is not None:
                artefacts.raw_payload_bin.parent.mkdir(parents=True, exist_ok=True)
                artefacts.raw_payload_bin.write_bytes(original_bytes)
                LOGGER.debug("Wrote original payload bytes to %s", artefacts.raw_payload_bin)
            for name, payload_text in extracted.items():
                payload_bytes = payload_text.encode("latin-1", errors="ignore")
                bin_name = Path(name).with_suffix(".bin").name
                bin_path = artefacts.payload_debug_dir / bin_name
                try:
                    bin_path.write_bytes(payload_bytes)
                    LOGGER.debug("Wrote loader payload bytes to %s", bin_path)
                except OSError as exc:  # pragma: no cover - filesystem failure
                    LOGGER.debug("Failed to write loader payload %s: %s", bin_path, exc)

        chunks = [_chunk_to_mapping(chunk) for chunk in extract_bootstrap_chunks(raw_text)]
        _write_json(artefacts.chunks_json, chunks)
        metrics.record_count("bootstrap_chunks", len(chunks))

        bootstrap_candidates = identify_bootstrap_candidates(
            manifest, raw_text, artefacts.payload_dir
        )
        candidate_dicts = [candidate.to_dict() for candidate in bootstrap_candidates]
        _write_json(artefacts.bootstrap_candidates_json, candidate_dicts)
        metrics.record_count("bootstrap_candidates", len(candidate_dicts))

        try:
            byte_metadata = generate_candidate_bytes(
                artefacts.bootstrap_candidates_json,
                artefacts.output_dir,
                meta_filename=artefacts.bytes_meta_json.name,
            )
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("Failed to decode bootstrap bytes: %s", exc)
            byte_metadata = []
        metrics.record_count("byte_sequences", len(byte_metadata))

        pipeline_report = collect_pipeline_candidates(
            candidate_dicts,
            manifest=manifest,
            byte_metadata=byte_metadata,
            source_path=target_path,
            debug_dir=artefacts.chunk_debug_dir if debug else None,
        )
        pipeline_report["bootstrap_candidates"] = candidate_dicts
        handler_entries: List[Mapping[str, object]] = []
        for chunk_entry in pipeline_report.get("chunks", []):
            if not isinstance(chunk_entry, Mapping):
                continue
            handlers = chunk_entry.get("handler_map") or []
            for handler in handlers:
                if isinstance(handler, Mapping):
                    handler_entries.append(handler)

        metrics.record_count("handler_entries", len(handler_entries))

        proposals = propose_opcode_mappings(handler_entries)
        grouped = group_proposals_by_opcode(proposals)
        candidate_maps = generate_map_candidates(grouped)
        proposal_dicts = [proposal.as_dict() for proposal in proposals]
        candidate_dicts = [candidate.as_dict() for candidate in candidate_maps]
        pipeline_report["opcode_proposals"] = proposal_dicts
        pipeline_report["opcode_map_candidates"] = candidate_dicts
        candidate_files = _write_opcode_map_candidates(
            artefacts.opcode_maps_dir, candidate_maps
        )
        if candidate_files:
            pipeline_report["opcode_map_files"] = [str(path) for path in candidate_files]

        metrics.record_count("opcode_proposals", len(proposals))
        metrics.record_count("opcode_map_candidates", len(candidate_maps))

        parity_summary: Mapping[str, object] | None = None
        parity_report_path = artefacts.output_dir / "parity_report.md"
        if parity_report_path.exists():
            try:
                parity_report = load_parity_report(parity_report_path)
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.debug("Failed to parse parity report %s: %s", parity_report_path, exc)
            else:
                parity_summary = {
                    "success": parity_report.success,
                    "matching_prefix": parity_report.matching_prefix,
                    "limit": parity_report.limit,
                }
                pipeline_report["parity_summary"] = parity_summary
                metrics.observe("parity_success", parity_report.success)
                if isinstance(parity_report.matching_prefix, int):
                    metrics.observe("parity_matching_prefix", parity_report.matching_prefix)

        pipelines = pipeline_report.get("pipelines") or []
        metrics.record_count("pipeline_candidates", len(pipelines))
        metrics.observe("pipeline_confidence", pipeline_report.get("pipeline_confidence"))
        metrics.observe("version_hint", pipeline_report.get("version_hint"))
        for candidate in pipelines:
            if not isinstance(candidate, Mapping):
                continue
            context = candidate.get("scoring_context") or {}
            pipeline_component = context.get("pipeline_confidence")
            try:
                pipeline_component = float(pipeline_component)
            except (TypeError, ValueError):
                pipeline_component = float(pipeline_report.get("pipeline_confidence", 0.0) or 0.0)
            english_scores = [
                float(value)
                for value in context.get("english_scores", [])
                if isinstance(value, (int, float))
            ]
            lua_scores = [
                float(value)
                for value in context.get("lua_scores", [])
                if isinstance(value, (int, float))
            ]
            hypothesis = score_pipeline_hypothesis(
                pipeline_confidence=pipeline_component,
                english_scores=english_scores,
                lua_scores=lua_scores,
                parity=parity_summary,
                mapping_candidates=candidate_dicts,
            )
            candidate["confidence"] = round(hypothesis.overall, 4)
            candidate["hypothesis_score"] = {
                "overall": round(hypothesis.overall, 4),
                "components": {k: round(v, 4) for k, v in hypothesis.components.items()},
                "notes": list(hypothesis.notes),
            }

        if pipelines:
            top_candidate = pipelines[0]
            if isinstance(top_candidate, Mapping):
                metrics.observe("top_pipeline_confidence", top_candidate.get("confidence"))

        graph_paths = generate_pipeline_graphs(pipeline_report, artefacts.graphs_dir)
        if graph_paths:
            pipeline_report["pipeline_graph_files"] = [str(path) for path in graph_paths]
        metrics.record_count("pipeline_graphs", len(graph_paths))

        transform_profile_path = artefacts.output_dir / "transform_profile.json"
        try:
            profile_path = write_auto_profile(
                pipeline_report,
                candidate_dicts,
                transform_profile_path,
                extra_metadata={
                    "target": str(target_path),
                    "generated_at": datetime.utcnow().isoformat(timespec="seconds"),
                },
            )
        except AutoProfileBuilderError as exc:
            LOGGER.warning("Auto profile generation skipped: %s", exc)
            profile_path = None
        except ValueError as exc:  # pragma: no cover - defensive
            LOGGER.warning("Auto profile could not be saved: %s", exc)
            profile_path = None
        if profile_path:
            pipeline_report["transform_profile"] = str(profile_path)
        metrics.observe("profile_generated", bool(profile_path))

        handler_suite = generate_handler_tests(
            pipeline_report,
            output_dir=artefacts.handler_tests_dir,
            pipeline_path=artefacts.pipeline_json,
        )
        if handler_suite is not None:
            pipeline_report.setdefault("handler_tests", handler_suite.summary())
            artefacts.handler_tests_manifest = handler_suite.manifest_path
            artefacts.handler_tests_definitions = handler_suite.definitions_path
        metrics.observe("handler_tests_generated", handler_suite is not None)

        _write_json(artefacts.pipeline_json, pipeline_report)

        mapping_report = detect_mapping_candidates(chunks)
        _write_json(artefacts.mapping_json, mapping_report)
        tables = mapping_report.get("tables")
        if isinstance(tables, Sequence):
            metrics.record_count("mapping_tables", len(tables))

        _write_json(
            artefacts.opcode_proposals,
            {"proposals": proposal_dicts, "candidates": candidate_dicts},
        )

        dot = render_pipeline_graph(pipeline_report.get("pipeline", []))
        _write_text(artefacts.graph_dot, dot)

        instruction_dump = artefacts.output_dir / "lift_ir.json"
        instructions = _load_instruction_dump(instruction_dump)
        vm_style = detect_vm_style(instructions)
        pipeline_report["vm_style"] = asdict(vm_style)
        metrics.observe("vm_style", vm_style.style)
        metrics.observe("vm_style_confidence", vm_style.confidence)
        metrics.observe("vm_style_sample_size", vm_style.sample_size)
        if not instructions and candidate_maps:
            LOGGER.debug(
                "No instruction dump found at %s; IR listings will be placeholders.",
                instruction_dump,
            )
        rendered_ir = [
            render_ir_candidate(candidate, instructions) for candidate in candidate_maps
        ]
        _write_ir_candidates(artefacts.ir_candidates_dir, rendered_ir)
        metrics.record_count("ir_candidates", len(rendered_ir))

        opcode_annotations = generate_opcode_annotations(
            candidate_files,
            instructions,
        )
        write_opcode_annotations(artefacts.opcode_annotations_md, opcode_annotations)
        pipeline_report["opcode_annotations"] = {
            "path": str(artefacts.opcode_annotations_md),
            "candidates": len(opcode_annotations),
        }
        metrics.record_count("opcode_annotation_candidates", len(opcode_annotations))

        report_text = _render_report(
            target=target,
            artefacts=artefacts,
            extracted=extracted,
            pipeline_report=pipeline_report,
            mapping_report=mapping_report,
        )
        _write_text(artefacts.report_md, report_text)

        user_summary = build_user_summary(
            target=target_path.name,
            pipeline_report=pipeline_report,
            mapping_report=mapping_report,
            parity_report_path=parity_report_path if parity_report_path.exists() else None,
            transform_profile_path=profile_path,
            detection_report_path=artefacts.report_md,
        )
        write_user_summary(artefacts.user_report_md, user_summary)

        checklist = build_recommendation_checklist(
            target=target_path.name,
            pipeline_report=pipeline_report,
            mapping_report=mapping_report,
            parity_summary=pipeline_report.get("parity_summary"),
        )
        write_recommendation_markdown(artefacts.recommendations_md, checklist)

        ensure_output_license(license_path, artefacts.output_dir)
        ensure_license_headers(
            [
                artefacts.report_md,
                artefacts.user_report_md,
                artefacts.recommendations_md,
                artefacts.opcode_annotations_md,
            ]
        )

        artefact_map = {
            "raw_payload": artefacts.raw_payload,
            "raw_manifest": artefacts.manifest_json,
            "bootstrap_chunks": artefacts.chunks_json,
            "bootstrap_candidates": artefacts.bootstrap_candidates_json,
            "pipeline_report": artefacts.pipeline_json,
            "mapping_report": artefacts.mapping_json
            if artefacts.mapping_json.exists()
            else None,
            "opcode_proposals": artefacts.opcode_proposals,
            "opcode_map_dir": artefacts.opcode_maps_dir,
            "opcode_annotations": artefacts.opcode_annotations_md,
            "pipeline_graph": artefacts.graph_dot,
            "pipeline_graphs": artefacts.graphs_dir,
            "payload_dir": artefacts.payload_dir,
            "ir_candidates": artefacts.ir_candidates_dir,
            "user_report": artefacts.user_report_md,
            "recommendations": artefacts.recommendations_md,
            "detection_report": artefacts.report_md,
        }
        if artefacts.bytes_meta_json.exists():
            artefact_map["byte_metadata"] = artefacts.bytes_meta_json
        if profile_path:
            artefact_map["transform_profile"] = profile_path
        if parity_report_path.exists():
            artefact_map["parity_report"] = parity_report_path
        if artefacts.metrics_path:
            artefact_map["metrics_report"] = artefacts.metrics_path

        run_manifest = build_run_manifest(
            target=target_path.name,
            pipeline_report=pipeline_report,
            mapping_report=mapping_report,
            artefact_paths=artefact_map,
            candidate_maps=candidate_dicts,
            candidate_map_files=candidate_files,
            parity_summary=parity_summary,
            version_hint=pipeline_report.get("version_hint"),
        )
        manifest_path = write_run_manifest(runs_dir=artefacts.runs_dir, manifest=run_manifest)
        artefacts.run_manifest_path = manifest_path

        metrics_extra = {
            "pipeline_confidence": pipeline_report.get("pipeline_confidence"),
            "version_hint": pipeline_report.get("version_hint"),
        }
        if parity_summary is not None:
            metrics_extra["parity_success"] = parity_summary.get("success")
            match_prefix = parity_summary.get("matching_prefix")
            if isinstance(match_prefix, int):
                metrics_extra["parity_matching_prefix"] = match_prefix
        metrics_path = metrics.write_report(
            output_dir=artefacts.metrics_dir,
            run_id=run_manifest.run_id,
            extra=metrics_extra,
        )
        artefacts.metrics_path = metrics_path

        plugin_names = tuple(plugins or ())
        plugin_dir = plugin_search_dir or Path("plugins")
        if plugin_names:
            try:
                discovery = discover_plugins(plugin_dir, plugin_names, logger=LOGGER)
            except PluginValidationError as exc:
                raise RuntimeError(str(exc)) from exc
            for missing_plugin in discovery.missing:
                LOGGER.warning(
                    "Requested plugin '%s' was not found in %s", missing_plugin, plugin_dir
                )
            if discovery.plugins:
                plugin_metadata: Dict[str, object] = {
                    "artefact_paths": artefact_map.copy(),
                    "candidate_maps": candidate_dicts,
                    "candidate_map_files": [str(path) for path in candidate_files],
                    "parity_summary": parity_summary,
                    "version_hint": pipeline_report.get("version_hint"),
                }
                if artefacts.metrics_path:
                    plugin_metadata["metrics_report"] = str(artefacts.metrics_path)
                plugin_context = PluginContext(
                    artefacts=artefacts,
                    pipeline_report=pipeline_report,
                    mapping_report=mapping_report,
                    metadata=plugin_metadata,
                    session_key_provided=key_buffer is not None,
                )
                try:
                    execute_plugins(discovery.plugins, plugin_context, logger=LOGGER)
                except (PluginKeyRequestError, PluginExecutionError) as exc:
                    raise RuntimeError(str(exc)) from exc

        if debug:
            LOGGER.info("Debug artefacts written to %s", artefacts.debug_dir)

        extra_files = {
            "bootstrap_candidates": artefacts.bootstrap_candidates_json,
            "pipeline_report": artefacts.pipeline_json,
        }
        if artefacts.mapping_json.exists():
            extra_files["mapping_candidates"] = artefacts.mapping_json
        if artefacts.bytes_meta_json.exists():
            extra_files["byte_metadata"] = artefacts.bytes_meta_json

        backup_plan = BackupPlan(
            original_file=target_path,
            manifest_path=artefacts.manifest_json,
            bootstrap_chunks=artefacts.chunks_json,
            transform_profile=(
                transform_profile_path if transform_profile_path.exists() else None
            ),
            extra_files=extra_files,
        )
        snapshot_analysis_inputs(output_dir=artefacts.output_dir, plan=backup_plan)

        try:
            ensure_no_keys(artefacts.output_dir)
        except KeyLeakError as exc:
            for violation in exc.violations:
                LOGGER.error(
                    "Forbidden secret material detected: %s %s",
                    violation.file,
                    violation.field_path,
                )
            raise

        try:
            validate_json_directory(artefacts.output_dir)
        except SchemaValidationError as exc:
            for issue in exc.issues:
                LOGGER.error(
                    "JSON schema violation: %s %s -> %s",
                    issue.file,
                    issue.path,
                    issue.message,
                )
            raise

        success = True
        return artefacts
    finally:
        cleanup_manager.finalize(success)
        _scrub_buffer(key_buffer)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run loader, bootstrap extraction, pipeline analysis, and mapping detectors.",
    )
    parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="Target Lua payload (defaults tuned for Luraph v14.4.2).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out"),
        help="Directory where artefacts will be written (default: out)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_EXTRACTION_THRESHOLD,
        help="Extraction threshold for loader payload splitting (default: %(default)s)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="Override path for the Markdown report (default: out/detection_report.md)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose logging and emit binary debug artefacts.",
    )
    parser.add_argument(
        "--use-key",
        metavar="KEY",
        help=(
            "Session key for parity tooling; required to signal intentional key usage. "
            "The key is never persisted and is wiped from memory when processing completes."
        ),
    )
    parser.add_argument(
        "--plugin",
        dest="plugins",
        action="append",
        default=[],
        help=(
            "Name of an allowed plugin module located in the plugins/ directory. "
            "May be supplied multiple times."
        ),
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO, format="%(message)s"
    )

    cleanup_manager = get_cleanup_manager()
    key_buffer = _copy_key_material(args.use_key)
    cleanup_manager.register_key_buffer("session_key", key_buffer)
    args.use_key = None  # type: ignore[assignment]

    success = False
    exit_code = 0

    try:
        if key_buffer is not None:
            LOGGER.info(
                "Session key provided via --use-key; it will be used ephemerally and wiped after completion."
            )
        run_detection(
            args.file,
            output_dir=args.output_dir,
            threshold=args.threshold,
            report_path=args.report,
            debug=args.debug,
            session_key=key_buffer,
            plugins=args.plugins or None,
        )
        success = True
    except FileNotFoundError as exc:
        LOGGER.error(str(exc))
        exit_code = 1
    finally:
        cleanup_manager.finalize(success)
        _scrub_buffer(key_buffer)

    if success:
        LOGGER.info(
            "Detection report ready: %s",
            (args.report or (args.output_dir / "detection_report.md")),
        )

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
