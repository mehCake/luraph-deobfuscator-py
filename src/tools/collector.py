"""Collect pipeline hints from previously extracted bootstrap chunks."""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .byte_extractor import extract_bytes, from_numeric_table, from_string_char
from .heuristics import (
    ChecksumResult,
    classify_operation_markers,
    detect_checksums,
    detect_endianness,
    score_base64_string,
    score_lph_header,
    score_operation_sequence,
    score_permutation_sequence,
)
from .hypothesis_scoring import (
    estimate_english_likeliness,
    estimate_lua_token_density,
    score_pipeline_hypothesis,
)
from .parser_tracer import (
    FunctionTrace,
    HandlerMatch,
    match_handler_patterns,
    trace_pipeline_functions,
)
from ..decoders.lph_reverse import COMMON_PARAMETER_PRESETS
from ..vm.block_recover import DispatcherCFG, recover_dispatcher_cfg

LOGGER = logging.getLogger(__name__)

__all__ = ["ChunkAnalysis", "collect_pipeline_candidates"]


@dataclass(frozen=True)
class ChunkAnalysis:
    """Structured description of a bootstrap chunk."""

    kind: str
    start: int
    end: int
    length: int
    operations: Sequence[str]
    payload_size: Optional[int]
    payload_error: Optional[str]
    argument: Optional[str]
    traces: Sequence[FunctionTrace]
    hints: Sequence[str]
    confidence: float
    debug_payload_path: Optional[str] = None
    checksums: Sequence[ChecksumResult] = ()
    handler_map: Sequence[HandlerMatch] = ()
    dispatcher_cfg: Optional[DispatcherCFG] = None
    permutation_score: float = 0.0
    xor_score: float = 0.0
    english_score: float = 0.0
    lua_score: float = 0.0


_CALL_PATTERN = re.compile(
    r"\b(?:loadstring|load|string\.[A-Za-z_]\w*|bit32\.[A-Za-z_]\w*|math\.[A-Za-z_]\w*|table\.[A-Za-z_]\w*)",
)
_METHOD_PATTERN = re.compile(r":\s*([A-Za-z_]\w*)\s*\(")


def _dedupe_sequence(values: Iterable[str]) -> List[str]:
    collapsed: List[str] = []
    for value in values:
        if not collapsed or collapsed[-1] != value:
            collapsed.append(value)
    return collapsed


def _extract_operations(text: str) -> List[str]:
    operations: List[str] = []
    for match in _CALL_PATTERN.finditer(text):
        operations.append(match.group(0))
    for match in _METHOD_PATTERN.finditer(text):
        operations.append(f"method:{match.group(1)}")
    return operations


def _match_long_bracket(text: str, index: int) -> int | None:
    if text[index] != "[":
        return None
    depth = 0
    i = index + 1
    while i < len(text) and text[i] == "=":
        depth += 1
        i += 1
    if i < len(text) and text[i] == "[":
        return depth
    return None


def _skip_long_bracket(text: str, index: int, depth: int) -> int:
    closing = "]" + "=" * depth + "]"
    end = text.find(closing, index + 1)
    return len(text) if end == -1 else end + len(closing)


def _skip_short_string(text: str, index: int) -> int:
    quote = text[index]
    i = index + 1
    while i < len(text):
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(text)


def _skip_comment(text: str, index: int) -> int:
    if not text.startswith("--", index):
        return index
    index += 2
    if index < len(text) and text[index] == "[":
        depth = _match_long_bracket(text, index)
        if depth is not None:
            return _skip_long_bracket(text, index, depth)
    while index < len(text) and text[index] not in "\r\n":
        index += 1
    return index


def _find_balanced(text: str, index: int) -> int:
    opens = text[index]
    closes = {"(": ")", "[": "]", "{": "}"}.get(opens)
    if closes is None:
        return index
    depth = 1
    i = index + 1
    while i < len(text):
        ch = text[i]
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        if ch in {'"', "'"}:
            i = _skip_short_string(text, i)
            continue
        if ch == "[":
            lb = _match_long_bracket(text, i)
            if lb is not None:
                i = _skip_long_bracket(text, i, lb)
                continue
        if ch == opens:
            depth += 1
        elif ch == closes:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def _split_arguments(arguments: str) -> List[str]:
    parts: List[str] = []
    current: List[str] = []
    i = 0
    length = len(arguments)
    while i < length:
        if arguments.startswith("--", i):
            i = _skip_comment(arguments, i)
            continue

        ch = arguments[i]
        if ch in {'"', "'"}:
            end = _skip_short_string(arguments, i)
            current.append(arguments[i:end])
            i = end
            continue
        if ch == "[":
            lb = _match_long_bracket(arguments, i)
            if lb is not None:
                end = _skip_long_bracket(arguments, i, lb)
                current.append(arguments[i:end])
                i = end
                continue
        if ch in "({[":
            close = _find_balanced(arguments, i)
            current.append(arguments[i : close + 1])
            i = close + 1
            continue
        if ch == ",":
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current.clear()
            i += 1
            continue
        current.append(ch)
        i += 1
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _extract_first_argument(call_text: str) -> Optional[str]:
    paren = call_text.find("(")
    if paren == -1:
        return None
    close = _find_balanced(call_text, paren)
    if close <= paren:
        return None
    inner = call_text[paren + 1 : close]
    parts = _split_arguments(inner)
    return parts[0] if parts else None


def _safe_payload(kind: str, text: str) -> tuple[Optional[bytes], Optional[str], Optional[str]]:
    argument = None
    error = None
    payload: Optional[bytes] = None

    try:
        if kind == "string.char":
            payload = from_string_char(text)
        elif kind == "numeric_array":
            payload = from_numeric_table(text)
        elif kind in {"load", "loadstring"}:
            argument = _extract_first_argument(text)
            if argument:
                payload = extract_bytes(argument)
    except Exception as exc:  # pragma: no cover - robustness
        error = str(exc)

    return payload, error, argument


def _detect_xor_score(text: str) -> float:
    if not text:
        return 0.0
    xor_hits = len(re.findall(r"bit32\.bxor", text, flags=re.IGNORECASE))
    if xor_hits == 0:
        return 0.0
    loop_hits = len(re.findall(r"\b(for|while)\b", text))
    score = xor_hits * 0.12
    if loop_hits:
        score += min(0.4, loop_hits * 0.18)
    return max(0.0, min(1.0, score))


def _normalise_chunk_dict(chunk: Dict[str, Any]) -> Tuple[str, int, int, str]:
    kind = str(chunk.get("kind") or chunk.get("type") or "unknown")
    start = int(chunk.get("start", chunk.get("start_offset", 0)) or 0)
    end = int(chunk.get("end", chunk.get("end_offset", start)) or start)
    text = str(
        chunk.get("text")
        or chunk.get("snippet")
        or chunk.get("source")
        or ""
    )
    return kind, start, end, text


def _determine_version_hint(source_path: Optional[Path]) -> Optional[str]:
    if not source_path:
        return None
    name = source_path.name.lower()
    if "obfuscated3.lua" in name:
        return "v14.4.2"
    if "obfuscated2.lua" in name:
        return "v14.4.1"
    if any(label in name for label in ("obfuscated4.lua", "obfuscated5.lua", "obfuscated6.lua")):
        return "v14.4.3"
    return None


def _preferred_presets(version_hint: Optional[str]) -> List[str]:
    presets = [name for name, _preset in COMMON_PARAMETER_PRESETS]
    if not version_hint:
        return presets

    def _key(name: str) -> Tuple[int, str]:
        return (0, name) if version_hint in name else (1, name)

    return sorted(presets, key=_key)


def _normalise_stage_name(stage: str) -> str:
    stage = stage.lower().strip()
    mapping = {
        "stringchar": "string.char",
        "string_char": "string.char",
        "escaped-string": "string-escape",
        "loadstring": "loadstring",
        "load": "load",
        "numeric-array": "numeric-array",
        "method:permute": "permute",
        "perm": "permute",
        "permute": "permute",
        "method:prga": "prga",
        "prga": "prga",
        "bit32.bxor": "xor",
        "xor": "xor",
        "dispatcher": "vm_dispatch",
        "handler": "vm_dispatch",
        "vm": "vm_unpack",
    }
    return mapping.get(stage, stage)


def _build_pipeline_sequences(
    analyses: Sequence[ChunkAnalysis],
    manifest: Optional[Sequence[Dict[str, Any]]],
    byte_metadata: Optional[Sequence[Dict[str, Any]]],
    *,
    version_hint: Optional[str],
    pipeline_confidence: float,
    pipeline_hints: Sequence[str],
    english_scores: Sequence[float],
    lua_scores: Sequence[float],
) -> List[Dict[str, Any]]:
    steps: List[str] = []
    frequency_counter: Counter[str] = Counter()
    xor_scores = [analysis.xor_score for analysis in analyses if analysis.xor_score > 0]
    perm_scores = [analysis.permutation_score for analysis in analyses if analysis.permutation_score > 0]

    if manifest:
        for entry in manifest:
            entry_type = str(entry.get("type") or "").lower()
            note = str(entry.get("note") or "").lower()
            if entry_type == "escaped-string":
                steps.append("string-escape")
                frequency_counter["string-escape"] += 1
                if "string.char" in note or "stringchar" in note:
                    steps.append("string.char")
                    frequency_counter["string.char"] += 1
            elif entry_type == "numeric-array":
                steps.append("numeric-array")
                frequency_counter["numeric-array"] += 1
            elif entry_type in {"load", "loadstring"}:
                steps.append(entry_type)
                frequency_counter[entry_type] += 1

    for analysis in analyses:
        for op in analysis.operations:
            normalised = _normalise_stage_name(op)
            if normalised in {"permute", "prga", "xor"}:
                steps.append(normalised)
                frequency_counter[normalised] += 1
        if analysis.handler_map:
            steps.append("vm_dispatch")
        if analysis.dispatcher_cfg:
            steps.append("vm_unpack")
        if analysis.permutation_score >= 0.5:
            steps.append("permute")
        if analysis.xor_score >= 0.3:
            steps.append("xor")

    if byte_metadata:
        for entry in byte_metadata:
            hint = str(entry.get("endianness_hint") or "unknown")
            if hint != "unknown":
                steps.append(f"endianness:{hint}")
            if int(entry.get("size") or 0) > 0:
                frequency_counter["bytes"] += 1

    steps.extend(_normalise_stage_name(marker) for marker in pipeline_hints)

    sequence = _dedupe_sequence(_normalise_stage_name(step) for step in steps if step)

    freq_bonus = 0.0
    for key, count in frequency_counter.items():
        if key in {"string-escape", "string.char", "numeric-array"}:
            freq_bonus += min(0.04 * count, 0.12)
        elif key in {"permute", "prga", "xor", "loadstring", "load"}:
            freq_bonus += min(0.05 * count, 0.15)
        elif key == "bytes":
            freq_bonus += min(0.02 * count, 0.05)
    freq_bonus = min(freq_bonus, 0.25)

    perm_bonus = min(0.3, (max(perm_scores) if perm_scores else 0.0) * 0.5)
    xor_bonus = min(0.25, (max(xor_scores) if xor_scores else 0.0) * 0.6)
    operation_confidence = min(1.0, pipeline_confidence + freq_bonus + perm_bonus + xor_bonus)

    breakdown = {
        "operation_score": round(pipeline_confidence, 4),
        "frequency_bonus": round(freq_bonus, 4),
        "permutation_bonus": round(perm_bonus, 4),
        "xor_bonus": round(xor_bonus, 4),
    }

    hypothesis = score_pipeline_hypothesis(
        pipeline_confidence=operation_confidence,
        english_scores=english_scores,
        lua_scores=lua_scores,
    )

    resolved_version_hint = version_hint or "unknown"

    pipeline_entry = {
        "sequence": sequence,
        "confidence": round(hypothesis.overall, 4),
        "confidence_breakdown": breakdown,
        "version_hint": resolved_version_hint,
        "preferred_presets": _preferred_presets(resolved_version_hint),
        "hypothesis_score": {
            "overall": round(hypothesis.overall, 4),
            "components": {k: round(v, 4) for k, v in hypothesis.components.items()},
            "notes": list(hypothesis.notes),
        },
        "scoring_context": {
            "pipeline_confidence": operation_confidence,
            "english_scores": list(english_scores),
            "lua_scores": list(lua_scores),
        },
    }

    return [pipeline_entry]


def collect_pipeline_candidates(
    chunks: Sequence[Dict[str, Any]],
    *,
    manifest: Optional[Sequence[Dict[str, Any]]] = None,
    byte_metadata: Optional[Sequence[Dict[str, Any]]] = None,
    source_path: Optional[Path] = None,
    debug_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    analyses: List[ChunkAnalysis] = []
    pipeline_sequence: List[str] = []
    english_scores: List[float] = []
    lua_scores: List[float] = []

    if debug_dir is not None:
        debug_dir.mkdir(parents=True, exist_ok=True)

    handler_summary: dict[int, List[str]] = defaultdict(list)
    handler_mnemonics: dict[int, set[str]] = defaultdict(set)

    normalised_chunks = sorted(
        [
            {
                "kind": kind,
                "start": start,
                "end": end,
                "text": text,
                "raw": chunk,
            }
            for chunk in chunks
            for kind, start, end, text in (_normalise_chunk_dict(chunk),)
        ],
        key=lambda entry: entry["start"],
    )

    for item in normalised_chunks:
        chunk = item["raw"]
        kind = item["kind"]
        start = item["start"]
        end = item["end"]
        text = item["text"]
        operations = _extract_operations(text)

        payload, error, argument = _safe_payload(kind, text)
        traces: Sequence[FunctionTrace] = []
        payload_size: Optional[int] = None
        hints_extra: List[str] = []
        debug_payload_path: Optional[str] = None
        chunk_confidence = 0.0
        checksum_results: List[ChecksumResult] = []
        permutation_score = 0.0
        xor_score = _detect_xor_score(text)
        if xor_score > 0:
            hints_extra.append("xor-loop")
            chunk_confidence = max(chunk_confidence, min(0.6, xor_score))

        handler_matches: Sequence[HandlerMatch] = ()
        dispatcher_cfg: Optional[DispatcherCFG] = None
        english_score = 0.0
        lua_score = 0.0

        if payload is not None:
            payload_size = len(payload)
            try:
                payload_text = payload.decode("latin-1")
            except Exception:  # pragma: no cover - defensive
                payload_text = ""
            if payload_text:
                english_score = estimate_english_likeliness(payload_text)
                lua_score = estimate_lua_token_density(payload_text)
                english_scores.append(english_score)
                lua_scores.append(lua_score)
                traces = trace_pipeline_functions(payload_text)
                for trace in traces:
                    operations.extend(trace.calls)
                handler_matches = match_handler_patterns(payload_text)
                if handler_matches:
                    hints_extra.append("opcode-handlers")
                    for handler in handler_matches:
                        names = handler_summary[handler.opcode]
                        if handler.handler not in names:
                            names.append(handler.handler)
                        for mnemonic in handler.mnemonics:
                            handler_mnemonics[handler.opcode].add(mnemonic)
                    try:
                        dispatcher_cfg = recover_dispatcher_cfg(payload_text, handler_matches)
                    except Exception:  # pragma: no cover - defensive
                        dispatcher_cfg = None
                    else:
                        if dispatcher_cfg and dispatcher_cfg.blocks:
                            hints_extra.append("dispatcher-cfg")
                base64_score = score_base64_string(payload_text)
                if base64_score >= 0.6:
                    hints_extra.append("base64-payload")
                    chunk_confidence = max(chunk_confidence, base64_score)
            header_score = score_lph_header(payload)
            if header_score >= 0.6:
                hints_extra.append("lph-header")
                chunk_confidence = max(chunk_confidence, header_score)
            endian_kind, endian_score = detect_endianness(payload)
            if endian_kind != "unknown" and endian_score >= 0.5:
                hints_extra.append(f"{endian_kind}-endian")
                chunk_confidence = max(chunk_confidence, min(endian_score, 1.0))
            checksum_results = detect_checksums(payload)
            for checksum_result in checksum_results:
                hints_extra.append(checksum_result.status_hint())
                if checksum_result.valid:
                    chunk_confidence = max(chunk_confidence, checksum_result.confidence)
                else:
                    chunk_confidence = max(
                        chunk_confidence, max(0.1, checksum_result.confidence * 0.6)
                    )
            if kind == "numeric_array" and payload:
                permutation_score = score_permutation_sequence(list(payload))
                if permutation_score >= 0.5:
                    hints_extra.append("perm-array")
                    chunk_confidence = max(chunk_confidence, permutation_score)
            if debug_dir is not None:
                debug_filename = (
                    f"chunk_{len(analyses) + 1:03d}_{kind}_{start:05d}-{end:05d}.bin"
                )
                debug_path = debug_dir / debug_filename
                try:
                    debug_path.write_bytes(payload)
                    LOGGER.debug("Wrote chunk payload bytes to %s", debug_path)
                    debug_payload_path = str(debug_path)
                except OSError as exc:  # pragma: no cover - filesystem failure
                    LOGGER.debug("Failed to write debug payload %s: %s", debug_path, exc)

        if argument:
            argument_score = score_base64_string(argument)
            if argument_score >= 0.6:
                hints_extra.append("base64-argument")
                chunk_confidence = max(chunk_confidence, argument_score)

        deduped_operations = _dedupe_sequence(operations)
        op_confidence = score_operation_sequence(deduped_operations)
        chunk_confidence = max(chunk_confidence, op_confidence)
        hints = classify_operation_markers(deduped_operations)
        hints.extend(hints_extra)

        chunk_confidence = min(chunk_confidence, 1.0)

        analyses.append(
            ChunkAnalysis(
                kind=kind,
                start=start,
                end=end,
                length=end - start,
                operations=deduped_operations,
                payload_size=payload_size,
                payload_error=error,
                argument=argument,
                traces=traces,
                hints=tuple(_dedupe_sequence(hints)),
                confidence=chunk_confidence,
                debug_payload_path=debug_payload_path,
                checksums=tuple(checksum_results),
                handler_map=tuple(handler_matches),
                dispatcher_cfg=dispatcher_cfg,
                permutation_score=permutation_score,
                xor_score=xor_score,
                english_score=english_score,
                lua_score=lua_score,
            )
        )

        pipeline_sequence.extend(operations)

    collapsed_pipeline = _dedupe_sequence(pipeline_sequence)
    pipeline_confidence = score_operation_sequence(collapsed_pipeline)
    pipeline_hints = classify_operation_markers(collapsed_pipeline)

    total_checksums = sum(len(analysis.checksums) for analysis in analyses)
    valid_checksums = sum(
        1 for analysis in analyses for checksum in analysis.checksums if checksum.valid
    )
    invalid_checksums = total_checksums - valid_checksums

    chunk_entries: List[Dict[str, Any]] = []
    for analysis in analyses:
        analysis_dict = asdict(analysis)
        cfg = analysis.dispatcher_cfg
        if cfg is not None:
            analysis_dict["dispatcher_cfg"] = cfg.as_dict()
        raw_checksums = analysis_dict.get("checksums", []) or []
        normalised_checksums: List[Dict[str, Any]] = []
        for checksum_dict in raw_checksums:
            expected_raw = checksum_dict.get("expected", b"")
            actual_raw = checksum_dict.get("actual", b"")
            expected_bytes = (
                expected_raw.encode("latin-1", errors="ignore")
                if isinstance(expected_raw, str)
                else bytes(expected_raw)
            )
            actual_bytes = (
                actual_raw.encode("latin-1", errors="ignore")
                if isinstance(actual_raw, str)
                else bytes(actual_raw)
            )
            normalised_checksums.append(
                {
                    **checksum_dict,
                    "expected": expected_bytes.hex(),
                    "actual": actual_bytes.hex(),
                }
            )
        analysis_dict["checksums"] = normalised_checksums
        analysis_dict["hints"] = list(analysis_dict.get("hints", []))
        analysis_dict["operations"] = list(analysis_dict.get("operations", []))
        chunk_entries.append(
            {
                **analysis_dict,
                "traces": [
                    {
                        "name": trace.name,
                        "start": trace.start,
                        "end": trace.end,
                        "calls": list(trace.calls),
                    }
                    for trace in analysis.traces
                ],
                "handler_map": [
                    {
                        "opcode": handler.opcode,
                        "handler": handler.handler,
                        "start": handler.start,
                        "end": handler.end,
                        "mnemonics": list(handler.mnemonics),
                        "body": handler.body,
                    }
                    for handler in analysis.handler_map
                ],
            }
        )

    version_hint = _determine_version_hint(source_path) or "unknown"

    pipeline_sequences = _build_pipeline_sequences(
        analyses,
        manifest,
        byte_metadata,
        version_hint=version_hint,
        pipeline_confidence=pipeline_confidence,
        pipeline_hints=pipeline_hints,
        english_scores=english_scores,
        lua_scores=lua_scores,
    )

    return {
        "chunks": chunk_entries,
        "pipeline": collapsed_pipeline,
        "pipeline_confidence": pipeline_confidence,
        "pipeline_hints": pipeline_hints,
        "checksum_summary": {
            "total": total_checksums,
            "valid": valid_checksums,
            "invalid": invalid_checksums,
        },
        "opcode_handlers": {
            str(opcode): sorted(set(names)) for opcode, names in sorted(handler_summary.items())
        },
        "opcode_mnemonics": {
            str(opcode): sorted(mnemonics)
            for opcode, mnemonics in sorted(handler_mnemonics.items())
        },
        "dispatcher_cfg_count": sum(1 for entry in chunk_entries if entry.get("dispatcher_cfg")),
        "pipelines": pipeline_sequences,
        "version_hint": version_hint,
        "byte_candidates": list(byte_metadata or []),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Collect pipeline candidate operations")
    parser.add_argument(
        "--chunks",
        type=Path,
        default=Path("out") / "bootstrap_candidates.json",
        help="Input bootstrap candidate JSON report",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("out") / "raw_manifest.json",
        help="Loader manifest JSON (optional)",
    )
    parser.add_argument(
        "--bytes-meta",
        type=Path,
        default=Path("out") / "bytes" / "meta.json",
        help="Byte extractor metadata JSON (optional)",
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=None,
        help="Original Lua source path for version hints",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "pipeline_candidates.json",
        help="Destination JSON file for pipeline candidates",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not args.chunks.exists():
        LOGGER.error("Chunk file %s does not exist", args.chunks)
        return 1

    try:
        chunks = json.loads(args.chunks.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        LOGGER.error("Failed to parse chunk file %s: %s", args.chunks, exc)
        return 1

    if not isinstance(chunks, list):
        LOGGER.error("Chunk file must contain a JSON list")
        return 1

    manifest_data: Optional[List[Dict[str, Any]]] = None
    if args.manifest and args.manifest.exists():
        try:
            manifest_payload = json.loads(args.manifest.read_text(encoding="utf-8"))
            if isinstance(manifest_payload, list):
                manifest_data = manifest_payload
            else:
                LOGGER.warning("Manifest %s is not a list; ignoring", args.manifest)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Failed to parse manifest %s: %s", args.manifest, exc)

    byte_meta: Optional[List[Dict[str, Any]]] = None
    if args.bytes_meta and args.bytes_meta.exists():
        try:
            byte_payload = json.loads(args.bytes_meta.read_text(encoding="utf-8"))
            if isinstance(byte_payload, list):
                byte_meta = byte_payload
            else:
                LOGGER.warning("Byte metadata %s is not a list; ignoring", args.bytes_meta)
        except json.JSONDecodeError as exc:
            LOGGER.warning("Failed to parse byte metadata %s: %s", args.bytes_meta, exc)

    report = collect_pipeline_candidates(
        chunks,
        manifest=manifest_data,
        byte_metadata=byte_meta,
        source_path=args.source,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    LOGGER.info("Analysed %d chunk(s) -> %d pipeline hints", len(chunks), len(report["pipeline"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

