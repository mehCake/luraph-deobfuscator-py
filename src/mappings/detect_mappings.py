"""Analyse bootstrap tables to derive opcode or permutation mapping candidates."""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from ..tools.heuristics import score_permutation_sequence

LOGGER = logging.getLogger(__name__)

__all__ = [
    "MappingPairScore",
    "MappingCandidate",
    "detect_mapping_candidates",
]

_ASSIGN_PATTERN = re.compile(
    r"(?P<name>[A-Za-z_][\w]*)\s*\[\s*(?P<index>[^\]]+)\s*\]\s*=\s*(?P<value>[^,\n]+)"
)
_TABLE_PREFIX_PATTERN = re.compile(r"([A-Za-z_][\w]*)\s*=\s*\{")
_KEY_VALUE_PATTERN = re.compile(r"\[\s*(?P<index>[^\]]+)\s*\]\s*=\s*(?P<value>.+)")

_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9]+")
_MAX_PERMUTATION = 1024


@dataclass(frozen=True)
class MappingPairScore:
    """Score assigned to a proposed mapping pair."""

    index: int
    value: int
    score: float
    support: int
    total: int

    def as_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "value": self.value,
            "score": round(self.score, 4),
            "support": self.support,
            "total": self.total,
        }


@dataclass(frozen=True)
class MappingCandidate:
    """Aggregate mapping proposal for a single table or byte payload."""

    name: str
    pairs: Sequence[MappingPairScore]
    confidence: float
    samples: int
    permutation_score: float
    hints: Sequence[str]
    source: str = "table"
    sequence: Sequence[int] | None = None
    stats: Mapping[str, object] | None = None
    affine_params: Tuple[int, int, int] | None = None
    length: int | None = None
    version_hint: str | None = None

    def as_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "name": self.name,
            "source": self.source,
            "confidence": round(self.confidence, 4),
            "samples": self.samples,
            "permutation_score": round(self.permutation_score, 4),
            "hints": list(self.hints),
            "pairs": [pair.as_dict() for pair in self.pairs],
        }
        if self.sequence is not None:
            preview = list(self.sequence[: min(16, len(self.sequence))])
            data["sequence_preview"] = preview
        if self.stats is not None:
            data["stats"] = dict(self.stats)
        if self.affine_params is not None:
            a, b, modulus = self.affine_params
            data["affine_params"] = {"a": a, "b": b, "modulus": modulus}
        if self.length is not None:
            data["length"] = self.length
        if self.version_hint is not None:
            data["version_hint"] = self.version_hint
        return data


def _slugify(name: str) -> str:
    slug = _SLUG_PATTERN.sub("_", name).strip("_")
    return slug or "mapping"


def _coerce_int(value: str) -> Optional[int]:
    text = value.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.lower().startswith("0b"):
            return int(text, 2)
        if text.lower().startswith("-0x"):
            return -int(text[1:], 16)
        return int(text, 10)
    except ValueError:
        return None


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


def _find_balanced(text: str, index: int, opens: str, closes: str) -> int:
    depth = 1
    i = index + 1
    while i < len(text):
        if text.startswith("--", i):
            i = _skip_comment(text, i)
            continue
        ch = text[i]
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


def _split_table_entries(body: str) -> List[str]:
    entries: List[str] = []
    current: List[str] = []
    i = 0
    length = len(body)
    paren = brace = bracket = 0
    while i < length:
        if body.startswith("--", i):
            i = _skip_comment(body, i)
            continue
        ch = body[i]
        if ch in {'"', "'"}:
            end = _skip_short_string(body, i)
            current.append(body[i:end])
            i = end
            continue
        if ch == "[":
            lb = _match_long_bracket(body, i)
            if lb is not None:
                end = _skip_long_bracket(body, i, lb)
                current.append(body[i:end])
                i = end
                continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren = max(paren - 1, 0)
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace = max(brace - 1, 0)
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket = max(bracket - 1, 0)
        if ch == "," and paren == 0 and brace == 0 and bracket == 0:
            entry = "".join(current).strip()
            if entry:
                entries.append(entry)
            current.clear()
            i += 1
            continue
        current.append(ch)
        i += 1
    entry = "".join(current).strip()
    if entry:
        entries.append(entry)
    return entries


def _mod_inverse(value: int, modulus: int) -> Optional[int]:
    value %= modulus
    try:
        return pow(value, -1, modulus)
    except ValueError:
        return None


def _analyse_sequence(values: Sequence[int], *, version_hint: str | None = None) -> Dict[str, object]:
    length = len(values)
    if length == 0:
        return {"length": 0, "permutation_score": 0.0}

    unique_values = len(set(values))
    unique_ratio = unique_values / length
    min_value = min(values)
    max_value = max(values)
    span = max_value - min_value + 1

    perm_score = score_permutation_sequence(values)
    zero_based = set(values) == set(range(length))
    one_based = set(values) == set(range(1, length + 1))
    contiguous = unique_values == length and span == length
    base_value = 0
    if zero_based:
        base_value = 0
    elif one_based:
        base_value = 1
    else:
        base_value = min_value if contiguous else 0
    normalised = [value - base_value for value in values]
    is_permutation = unique_values == length and set(normalised) == set(range(length))

    affine_params: Tuple[int, int, int] | None = None
    affine_score = 0.0
    if length >= 3 and length <= _MAX_PERMUTATION and is_permutation:
        modulus = length
        adjusted = normalised
        indices = list(range(length))
        for i in range(length - 1):
            for j in range(i + 1, length):
                diff_index = (indices[j] - indices[i]) % modulus
                if diff_index == 0:
                    continue
                inv = _mod_inverse(diff_index, modulus)
                if inv is None:
                    continue
                diff_value = (adjusted[j] - adjusted[i]) % modulus
                factor = (diff_value * inv) % modulus
                bias = (adjusted[i] - factor * indices[i]) % modulus
                matches = sum(
                    1
                    for idx, value in enumerate(adjusted)
                    if (factor * idx + bias) % modulus == value % modulus
                )
                score = matches / length
                if score > affine_score:
                    affine_score = score
                    affine_params = (factor, bias, modulus)
                if affine_score >= 0.99:
                    break
            if affine_score >= 0.99:
                break

    cycles = _cycle_metrics(normalised) if is_permutation else {}

    v1442_bonus = 0.0
    if version_hint == "v14.4.2" and length in {256, 512, 1024}:
        # Luraph 14.4.2 permutations typically operate on power-of-two tables
        # and exhibit strong affine structure.
        v1442_bonus = 0.1 + (0.15 if affine_score >= 0.8 else 0.05)

    hints: List[str] = []
    if is_permutation:
        hints.append("permutation")
    if affine_score >= 0.8:
        hints.append("affine-mapping")
    if v1442_bonus > 0:
        hints.append("v14.4.2-pattern")

    stats: Dict[str, object] = {
        "length": length,
        "unique_ratio": round(unique_ratio, 4),
        "min": int(min_value),
        "max": int(max_value),
        "permutation_score": round(perm_score, 4),
        "is_permutation": is_permutation,
        "contiguous": contiguous,
        "affine_score": round(affine_score, 4),
    }
    if cycles:
        stats.update(cycles)
    else:
        stats["cycle_count"] = 0
        stats["longest_cycle"] = 0

    confidence = (
        0.45 * perm_score
        + 0.25 * unique_ratio
        + 0.2 * affine_score
        + v1442_bonus
    )

    return {
        "length": length,
        "hints": hints,
        "confidence": min(confidence, 1.0),
        "permutation_score": perm_score,
        "affine_params": affine_params,
        "stats": stats,
        "sequence": tuple(values),
    }


def _cycle_metrics(values: Sequence[int]) -> Dict[str, object]:
    length = len(values)
    if length == 0:
        return {}
    seen = [False] * length
    cycles = 0
    longest = 0
    for start in range(length):
        if seen[start]:
            continue
        node = start
        cycle_len = 0
        while 0 <= node < length and not seen[node]:
            seen[node] = True
            node = values[node]
            cycle_len += 1
            if cycle_len > length:
                break
        if cycle_len > 0:
            cycles += 1
            longest = max(longest, cycle_len)
    return {"cycle_count": cycles, "longest_cycle": longest}


def _iter_table_literals(text: str) -> Iterable[Tuple[str, str]]:
    for match in _TABLE_PREFIX_PATTERN.finditer(text):
        name = match.group(1)
        brace_index = match.end() - 1
        end = _find_balanced(text, brace_index, "{", "}")
        if end <= brace_index:
            continue
        body = text[brace_index + 1 : end]
        yield name, body


def _collect_pairs(text: str) -> MutableMapping[str, List[Tuple[int, int]]]:
    pairs: MutableMapping[str, List[Tuple[int, int]]] = defaultdict(list)

    for name, body in _iter_table_literals(text):
        sequential_index = 1
        for entry in _split_table_entries(body):
            match = _KEY_VALUE_PATTERN.match(entry)
            if match:
                index = _coerce_int(match.group("index"))
                value = _coerce_int(match.group("value"))
                if index is None or value is None:
                    continue
                pairs[name].append((index, value))
                continue
            value = _coerce_int(entry)
            if value is None:
                continue
            pairs[name].append((sequential_index, value))
            sequential_index += 1
        if sequential_index == 1:
            LOGGER.debug("No sequential entries detected for table %s", name)

    for match in _ASSIGN_PATTERN.finditer(text):
        index = _coerce_int(match.group("index"))
        value = _coerce_int(match.group("value"))
        if index is None or value is None:
            continue
        name = match.group("name")
        pairs[name].append((index, value))

    return pairs


def _generate_integer_sequences(
    payload: bytes,
    *,
    endianness_hint: str | None = None,
) -> Iterable[Tuple[Sequence[int], Dict[str, object]]]:
    length = len(payload)
    if length == 0:
        return []

    candidates: List[Tuple[Sequence[int], Dict[str, object]]] = []
    preferred_order = [endianness_hint] if endianness_hint in {"little", "big"} else []
    for byte_width in (1, 2, 4):
        if length % byte_width != 0:
            continue
        entry_count = length // byte_width
        if entry_count == 0 or entry_count > _MAX_PERMUTATION:
            continue
        orders = preferred_order + [order for order in ("little", "big") if order not in preferred_order]
        for order in orders:
            values = [
                int.from_bytes(payload[i : i + byte_width], order, signed=False)
                for i in range(0, length, byte_width)
            ]
            candidates.append(
                (
                    values,
                    {
                        "byte_width": byte_width,
                        "endianness": order,
                        "entries": entry_count,
                    },
                )
            )
    return candidates


def _analyse_byte_payload(
    name: str,
    payload: bytes,
    metadata: Mapping[str, object],
    *,
    version_hint: str | None = None,
) -> Optional[MappingCandidate]:
    best_candidate: Optional[MappingCandidate] = None
    best_score = 0.0
    endianness_hint = metadata.get("endianness_hint") if isinstance(metadata, Mapping) else None

    for values, info in _generate_integer_sequences(payload, endianness_hint=endianness_hint):
        analysis = _analyse_sequence(values, version_hint=version_hint)
        perm_score = float(analysis.get("permutation_score", 0.0))
        if perm_score < 0.4:
            continue

        hints = list(dict.fromkeys(analysis.get("hints", [])))
        hints.append(f"width={info['byte_width']}")
        hints.append(f"endianness={info['endianness']}")

        candidate = MappingCandidate(
            name=name,
            pairs=(),
            confidence=float(analysis.get("confidence", 0.0)),
            samples=len(values),
            permutation_score=perm_score,
            hints=tuple(hints),
            source="bytes",
            sequence=analysis.get("sequence"),
            stats={**analysis.get("stats", {}), **info},
            affine_params=analysis.get("affine_params"),
            length=analysis.get("length"),
            version_hint=version_hint,
        )

        score = candidate.confidence + perm_score
        if version_hint == "v14.4.2" and len(values) in {256, 512, 1024}:
            score += 0.1

        if score > best_score:
            best_score = score
            best_candidate = candidate

    return best_candidate


def _write_mapping_file(
    candidate: MappingCandidate,
    *,
    output_dir: Path,
    index: int,
) -> Optional[Path]:
    if candidate.sequence is None:
        return None

    mapping = [int(value) for value in candidate.sequence]
    inverse: Dict[int, int] | None = None
    length = len(mapping)
    if length and len(set(mapping)) == length:
        inverse = {int(value): index for index, value in enumerate(mapping)}

    file_name = f"{index:03d}_{_slugify(candidate.name)}.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": candidate.name,
        "source": candidate.source,
        "length": length,
        "mapping": mapping,
        "inverse": inverse,
        "confidence": round(candidate.confidence, 4),
        "permutation_score": round(candidate.permutation_score, 4),
        "hints": list(candidate.hints),
        "stats": dict(candidate.stats or {}),
    }
    if candidate.affine_params is not None:
        a, b, modulus = candidate.affine_params
        payload["affine_params"] = {"a": a, "b": b, "modulus": modulus}
    if candidate.version_hint:
        payload["version_hint"] = candidate.version_hint

    path = output_dir / file_name
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _score_table(
    name: str,
    entries: Sequence[Tuple[int, int]],
    *,
    version_hint: str | None = None,
) -> Optional[MappingCandidate]:
    if not entries:
        return None

    by_index: MutableMapping[int, Counter[int]] = defaultdict(Counter)
    for index, value in entries:
        by_index[index][value] += 1

    scored_pairs: List[MappingPairScore] = []
    support_total = 0
    confidence_parts: List[float] = []

    for index in sorted(by_index.keys()):
        counter = by_index[index]
        total = sum(counter.values())
        value, support = counter.most_common(1)[0]
        score = support / total if total else 0.0
        scored_pairs.append(
            MappingPairScore(index=index, value=value, score=score, support=support, total=total)
        )
        confidence_parts.append(score)
        support_total += total

    confidence = sum(confidence_parts) / len(confidence_parts) if confidence_parts else 0.0
    scored_pairs.sort(key=lambda pair: pair.index)

    ordered = sorted(entries, key=lambda pair: pair[0])
    ordered_values = [value for _, value in ordered]
    sequence_analysis = _analyse_sequence(ordered_values, version_hint=version_hint)
    permutation_score = float(sequence_analysis.get("permutation_score", 0.0))
    combined_confidence = min(
        1.0,
        0.6 * confidence + 0.4 * float(sequence_analysis.get("confidence", 0.0)),
    )

    hints: List[str] = list(dict.fromkeys(sequence_analysis.get("hints", [])))
    if permutation_score >= 0.75 and "likely-permutation" not in hints:
        hints.append("likely-permutation")
    elif permutation_score >= 0.5 and "maybe-permutation" not in hints:
        hints.append("maybe-permutation")

    return MappingCandidate(
        name=name,
        pairs=scored_pairs,
        confidence=combined_confidence,
        samples=support_total,
        permutation_score=permutation_score,
        hints=tuple(hints),
        sequence=sequence_analysis.get("sequence"),
        stats=sequence_analysis.get("stats"),
        affine_params=sequence_analysis.get("affine_params"),
        length=sequence_analysis.get("length"),
        version_hint=version_hint,
    )


def detect_mapping_candidates(
    chunks: Sequence[Mapping[str, object]],
    *,
    byte_entries: Sequence[Mapping[str, object]] | None = None,
    output_dir: Path | str | None = None,
    version_hint: str | None = None,
) -> Dict[str, object]:
    """Derive permutation/opcode mapping proposals from bootstrap chunks and byte payloads."""

    aggregate: MutableMapping[str, List[Tuple[int, int]]] = defaultdict(list)

    for chunk in chunks:
        if not isinstance(chunk, Mapping):
            continue
        text = chunk.get("text") or chunk.get("snippet")
        if not isinstance(text, str):
            continue
        pairs = _collect_pairs(text)
        for name, values in pairs.items():
            aggregate[name].extend(values)

    candidates: List[MappingCandidate] = []
    for name, entries in aggregate.items():
        candidate = _score_table(name, entries, version_hint=version_hint)
        if candidate is not None:
            candidates.append(candidate)

    byte_candidates: List[MappingCandidate] = []
    if byte_entries:
        for entry in byte_entries:
            payload_obj = entry.get("payload") if isinstance(entry, Mapping) else None
            if isinstance(payload_obj, bytearray):
                payload = bytes(payload_obj)
            elif isinstance(payload_obj, bytes):
                payload = payload_obj
            else:
                continue
            name = str(entry.get("name", "byte_candidate"))
            metadata = entry.get("metadata") if isinstance(entry, Mapping) else entry
            if not isinstance(metadata, Mapping):
                metadata = {}
            candidate = _analyse_byte_payload(name, payload, metadata, version_hint=version_hint)
            if candidate is not None:
                byte_candidates.append(candidate)

    candidates.sort(key=lambda cand: (-cand.confidence, -cand.samples, cand.name))
    byte_candidates.sort(key=lambda cand: (-cand.confidence, -cand.samples, cand.name))

    mapping_files: List[str] = []
    if output_dir is not None:
        mapping_path = Path(output_dir)
        all_candidates = candidates + byte_candidates
        for index, candidate in enumerate(all_candidates):
            written = _write_mapping_file(candidate, output_dir=mapping_path, index=index)
            if written is not None:
                mapping_files.append(str(written))

    return {
        "tables": [candidate.as_dict() for candidate in candidates],
        "byte_tables": [candidate.as_dict() for candidate in byte_candidates],
        "total_tables": len(candidates),
        "total_pairs": sum(candidate.samples for candidate in candidates),
        "byte_table_count": len(byte_candidates),
        "mapping_files": mapping_files,
    }


def _normalise_input(payload: object) -> Sequence[Mapping[str, object]]:
    if isinstance(payload, Mapping) and "chunks" in payload:
        chunks = payload["chunks"]
        if not isinstance(chunks, Sequence):
            raise TypeError("'chunks' entry must be a sequence")
        return [chunk for chunk in chunks if isinstance(chunk, Mapping)]
    if isinstance(payload, Sequence):
        return [chunk for chunk in payload if isinstance(chunk, Mapping)]
    raise TypeError("Unsupported payload format: expected list or mapping with 'chunks'")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Detect mapping candidates from bootstrap tables")
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("out") / "bootstrap_chunks.json",
        help="JSON file containing bootstrap chunk data or pipeline report",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "mapping_candidates.json",
        help="Destination JSON file for mapping candidate report",
    )
    parser.add_argument(
        "--bytes-meta",
        type=Path,
        help="Optional metadata JSON produced by byte_extractor",
    )
    parser.add_argument(
        "--bytes-dir",
        type=Path,
        help="Directory containing byte_extractor outputs (expects meta.json)",
    )
    parser.add_argument(
        "--mapping-dir",
        type=Path,
        default=Path("out") / "mappings",
        help="Directory to write resolved mapping JSON files",
    )
    parser.add_argument(
        "--version-hint",
        help="Optional Luraph version hint (e.g., v14.4.2)",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if not args.source.exists():
        LOGGER.error("Source file %s does not exist", args.source)
        return 1

    payload = json.loads(args.source.read_text(encoding="utf-8"))

    try:
        chunks = _normalise_input(payload)
    except TypeError as exc:
        LOGGER.error(str(exc))
        return 1

    byte_entries: List[Mapping[str, object]] = []
    metadata_entries: Optional[List[Mapping[str, object]]] = None
    meta_path: Optional[Path] = None
    if args.bytes_meta:
        meta_path = args.bytes_meta
    elif args.bytes_dir:
        candidate_meta = args.bytes_dir / "meta.json"
        if candidate_meta.exists():
            meta_path = candidate_meta
        else:
            LOGGER.warning("No meta.json found in %s", args.bytes_dir)

    if meta_path and meta_path.exists():
        try:
            metadata_raw = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            LOGGER.error("Failed to parse %s: %s", meta_path, exc)
            return 1
        if isinstance(metadata_raw, list):
            metadata_entries = [entry for entry in metadata_raw if isinstance(entry, Mapping)]
        else:
            LOGGER.warning("Metadata file %s did not contain a list", meta_path)

    if metadata_entries:
        for entry in metadata_entries:
            path_value = entry.get("path")
            if not isinstance(path_value, str):
                continue
            entry_path = Path(path_value)
            if not entry_path.is_absolute() and meta_path is not None:
                entry_path = meta_path.parent / entry_path
            if not entry_path.exists():
                LOGGER.debug("Skipping %s (missing file)", entry_path)
                continue
            try:
                payload_bytes = entry_path.read_bytes()
            except OSError as exc:
                LOGGER.debug("Failed to read %s: %s", entry_path, exc)
                continue
            byte_entries.append(
                {
                    "name": entry.get("name", entry_path.stem),
                    "payload": payload_bytes,
                    "metadata": entry,
                }
            )

    report = detect_mapping_candidates(
        chunks,
        byte_entries=byte_entries,
        output_dir=args.mapping_dir,
        version_hint=args.version_hint,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    LOGGER.info(
        "Analysed %d chunk(s) -> %d table(s) with %d pair observations",
        len(chunks),
        report["total_tables"],
        report["total_pairs"],
    )
    if byte_entries:
        LOGGER.info("Processed %d byte candidate(s)", len(byte_entries))
    if report.get("mapping_files"):
        LOGGER.info("Wrote %d mapping artefact(s) into %s", len(report["mapping_files"]), args.mapping_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
