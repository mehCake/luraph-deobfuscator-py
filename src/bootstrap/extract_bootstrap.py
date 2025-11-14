"""Utilities for extracting bootstrap constructs from Lua payloads.

This module exposes two complementary APIs:

``extract_bootstrap_chunks``
    Legacy helper that scans a Lua payload string directly and extracts
    top-level constructs such as ``loadstring`` calls or large
    ``string.char`` invocations.  Existing tooling still relies on this
    behaviour, so it remains intact.

``identify_bootstrap_candidates``
    Newer analysis routine that consumes the loader manifest emitted by
    :mod:`src.io.loader`.  It inspects the recorded chunks, evaluates a
    handful of heuristics (keyword references, byte-level
    autocorrelation, payload size, etc.), and emits a structured report
    describing the most promising bootstrap candidates.  The companion
    CLI writes ``out/bootstrap_candidates.json`` for downstream stages.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, asdict
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

# Default thresholds for identifying "large" ``string.char`` payloads.
DEFAULT_STRING_CHAR_ARG_THRESHOLD = 32
DEFAULT_STRING_CHAR_LENGTH_THRESHOLD = 256

_DEFAULT_MAX_SNIPPET = 256
_MIN_CONFIDENCE = 0.25
_REFERENCE_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("load", re.compile(r"\bload\b", re.IGNORECASE)),
    ("loadstring", re.compile(r"\bloadstring\b", re.IGNORECASE)),
    ("string.char", re.compile(r"string\.char", re.IGNORECASE)),
    ("bit32", re.compile(r"\bbit32\b", re.IGNORECASE)),
    ("math", re.compile(r"\bmath\b", re.IGNORECASE)),
)


@dataclass(frozen=True)
class BootstrapChunk:
    """A segment of the Lua payload that contains a bootstrap construct."""

    kind: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class ManifestEntry:
    """Structured representation of a loader manifest entry."""

    type: str
    start_offset: int
    end_offset: int
    payload_length: int
    source_length: int
    payload_file: Optional[str] = None
    note: Optional[str] = None

    @property
    def length(self) -> int:
        return max(0, self.end_offset - self.start_offset)


@dataclass(frozen=True)
class BootstrapCandidate:
    """Description of an extracted bootstrap candidate chunk."""

    kind: str
    start_offset: int
    end_offset: int
    confidence: float
    references: List[str]
    reasons: List[str]
    snippet: str
    autocorrelation: Dict[str, float]
    payload_length: int
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "type": self.kind,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "confidence": round(self.confidence, 4),
            "references": self.references,
            "reasons": self.reasons,
            "snippet": self.snippet,
            "autocorrelation": self.autocorrelation,
            "payload_length": self.payload_length,
        }
        if self.note:
            data["note"] = self.note
        return data


def extract_bootstrap_chunks(
    source: str,
    *,
    min_string_char_args: int = DEFAULT_STRING_CHAR_ARG_THRESHOLD,
    min_string_char_length: int = DEFAULT_STRING_CHAR_LENGTH_THRESHOLD,
) -> List[BootstrapChunk]:
    """Extract likely bootstrap constructs from a Lua payload string."""

    top_level_mask = _compute_top_level_mask(source)

    chunks: List[BootstrapChunk] = []

    # ``loadstring`` / ``load`` calls are typically used to bootstrap payloads.
    for match in re.finditer(r"\b(loadstring|load)\b\s*\(", source):
        start = match.start()
        if start >= len(top_level_mask) or not top_level_mask[start]:
            continue

        call_start = start
        paren_index = match.end() - 1
        end = _find_balanced_close(source, paren_index, "(", ")")
        if end <= call_start:
            continue
        chunk_text = source[call_start:end]
        chunks.append(BootstrapChunk(match.group(1), call_start, end, chunk_text))

    # Large ``string.char`` arrays often contain encoded bytecode.
    for match in re.finditer(r"string\.char\s*\(", source):
        start = match.start()
        if start >= len(top_level_mask) or not top_level_mask[start]:
            continue

        paren_index = match.end() - 1
        end = _find_balanced_close(source, paren_index, "(", ")")
        if end <= start:
            continue
        inner = source[paren_index + 1 : end - 1]
        arg_count = _count_arguments(inner)
        if arg_count < min_string_char_args and len(inner) < min_string_char_length:
            continue

        chunk_text = source[start:end]
        chunks.append(BootstrapChunk("string.char", start, end, chunk_text))

    # Collect numeric array literals at the top level.
    for brace_index in _iter_char_indices(source, "{"):
        if brace_index >= len(top_level_mask) or not top_level_mask[brace_index]:
            continue

        end = _find_balanced_close(source, brace_index, "{", "}")
        if end <= brace_index:
            continue

        inner = source[brace_index + 1 : end - 1]
        if not _NUMERIC_ARRAY_PATTERN.fullmatch(inner.strip()):
            continue

        chunk_text = source[brace_index:end]
        chunks.append(BootstrapChunk("numeric_array", brace_index, end, chunk_text))

    chunks.sort(key=lambda chunk: chunk.start)
    return chunks


def _manifest_entry_from_dict(data: Dict[str, Any]) -> ManifestEntry:
    try:
        start = int(data.get("start_offset", 0))
        end = int(data.get("end_offset", start))
    except (TypeError, ValueError):
        start = int(data.get("start_offset") or 0)
        end = start
    payload_length = int(data.get("payload_length") or max(0, end - start))
    source_length = int(data.get("source_length") or max(0, end - start))
    return ManifestEntry(
        type=str(data.get("type") or "unknown"),
        start_offset=start,
        end_offset=end,
        payload_length=payload_length,
        source_length=source_length,
        payload_file=data.get("payload_file"),
        note=data.get("note"),
    )


def _resolve_payload_bytes(entry: ManifestEntry, base_dir: Path) -> bytes:
    path_str = entry.payload_file
    if not path_str:
        return b""
    path = Path(path_str)
    candidates: List[Path] = []
    if path.is_absolute():
        candidates.append(path)
    else:
        candidates.append((base_dir / path).resolve())
        candidates.append(base_dir / path)
        candidates.append(path)
        candidates.append(path.resolve())
    for candidate in candidates:
        try:
            return candidate.read_bytes()
        except OSError:
            continue
    LOGGER.debug("Unable to read payload file %s (checked %s)", path_str, candidates)
    return b""


def _extract_snippet(
    entry: ManifestEntry,
    raw_text: Optional[str],
    manifest_base: Path,
    *,
    max_length: int,
) -> str:
    snippet = ""
    if raw_text is not None:
        start = max(0, min(entry.start_offset, len(raw_text)))
        end = max(start, min(entry.end_offset, len(raw_text)))
        snippet = raw_text[start:end]
    if not snippet and entry.payload_file:
        payload_text = _resolve_payload_bytes(entry, manifest_base)
        if payload_text:
            snippet = payload_text.decode("utf-8", errors="ignore")
    snippet = snippet.strip()
    if len(snippet) > max_length:
        return snippet[: max_length - 1] + "…"
    return snippet


def _autocorrelation(payload: bytes, *, max_lag: int = 32) -> Dict[str, float]:
    length = len(payload)
    if length <= 1:
        return {"score": 0.0, "best_lag": 0, "length": length}

    best_score = 0.0
    best_lag = 0
    max_lag = min(max_lag, length // 2)
    for lag in range(1, max_lag + 1):
        matches = sum(1 for i in range(length - lag) if payload[i] == payload[i + lag])
        total = max(1, length - lag)
        score = matches / total
        if score > best_score:
            best_score = score
            best_lag = lag
    return {"score": round(best_score, 4), "best_lag": best_lag, "length": length}


def _find_references(snippet: str, note: Optional[str]) -> List[str]:
    text = snippet or ""
    refs: List[str] = []
    for name, pattern in _REFERENCE_PATTERNS:
        if pattern.search(text) or (note and pattern.search(note)):
            refs.append(name)
    return refs


def _compute_confidence(
    entry: ManifestEntry,
    references: Sequence[str],
    autocorr: Dict[str, float],
) -> Tuple[float, List[str]]:
    confidence = 0.0
    reasons: List[str] = []

    if entry.type in {"loadstring", "load"}:
        confidence += 0.45
        reasons.append("load/loadstring call")
    elif entry.type == "escaped-string" and entry.note and "string.char" in entry.note:
        confidence += 0.3
        reasons.append("string.char encoded payload")
    elif entry.type == "numeric-array":
        confidence += 0.2
        reasons.append("numeric array literal")

    if entry.payload_length >= 1024:
        confidence += 0.2
        reasons.append("payload >= 1KiB")
    elif entry.payload_length >= 256:
        confidence += 0.1
        reasons.append("payload >= 256 bytes")

    if references:
        confidence += 0.2
        reasons.append(f"references {', '.join(sorted(set(references)))}")

    score = autocorr.get("score", 0.0)
    if score >= 0.6:
        confidence += 0.2
        reasons.append(f"autocorrelation {score:.2f} (high)")
    elif score >= 0.3:
        confidence += 0.1
        reasons.append(f"autocorrelation {score:.2f}")

    if entry.note and "load" in entry.note.lower():
        confidence += 0.05
        reasons.append("note mentions load")

    confidence = min(1.0, confidence)
    return confidence, reasons


def identify_bootstrap_candidates(
    manifest_data: Sequence[Dict[str, Any]],
    raw_text: Optional[str],
    manifest_base: Path,
    *,
    max_snippet: int = _DEFAULT_MAX_SNIPPET,
) -> List[BootstrapCandidate]:
    candidates: List[BootstrapCandidate] = []
    for entry_dict in manifest_data:
        entry = _manifest_entry_from_dict(entry_dict)
        payload_bytes = _resolve_payload_bytes(entry, manifest_base)
        snippet = _extract_snippet(entry, raw_text, manifest_base, max_length=max_snippet)
        references = _find_references(snippet, entry.note)
        autocorr = _autocorrelation(payload_bytes if payload_bytes else snippet.encode("utf-8", errors="ignore"))
        confidence, reasons = _compute_confidence(entry, references, autocorr)

        LOGGER.debug(
            "Evaluated manifest entry %s [%d, %d): confidence %.2f",
            entry.type,
            entry.start_offset,
            entry.end_offset,
            confidence,
        )

        if confidence < _MIN_CONFIDENCE and not references:
            continue

        candidate = BootstrapCandidate(
            kind=entry.type,
            start_offset=entry.start_offset,
            end_offset=entry.end_offset,
            confidence=confidence,
            references=list(sorted(set(references))),
            reasons=reasons,
            snippet=snippet,
            autocorrelation=autocorr,
            payload_length=entry.payload_length,
            note=entry.note,
        )
        candidates.append(candidate)
        LOGGER.info(
            "Selected bootstrap candidate %s [%d, %d) confidence %.2f due to %s",
            candidate.kind,
            candidate.start_offset,
            candidate.end_offset,
            candidate.confidence,
            "; ".join(candidate.reasons) or "heuristics",
        )

    candidates.sort(key=lambda cand: cand.confidence, reverse=True)
    return candidates


def _compute_top_level_mask(source: str) -> List[bool]:
    mask = [False] * len(source)
    paren = brace = bracket = 0
    i = 0
    length = len(source)

    while i < length:
        if source.startswith("--", i):
            if (lb := _match_long_bracket(source, i + 2)) is not None:
                i = _skip_long_bracket(source, i + 2, lb)
            else:
                newline = source.find("\n", i + 2)
                i = length if newline == -1 else newline + 1
            continue

        ch = source[i]

        if ch in {'"', "'"}:
            i = _skip_short_string(source, i)
            continue

        if (lb := _match_long_bracket(source, i)) is not None:
            i = _skip_long_bracket(source, i, lb)
            continue

        mask[i] = paren == 0 and brace == 0 and bracket == 0

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

        i += 1

    return mask


def _iter_char_indices(source: str, char: str) -> Iterable[int]:
    index = source.find(char)
    while index != -1:
        yield index
        index = source.find(char, index + 1)


def _match_long_bracket(source: str, index: int) -> Optional[int]:
    if index >= len(source) or source[index] != "[":
        return None

    end = index + 1
    while end < len(source) and source[end] == "=":
        end += 1
    if end < len(source) and source[end] == "[":
        return end - index - 1
    return None


def _skip_long_bracket(source: str, index: int, equals_count: int) -> int:
    closing = "]" + "=" * equals_count + "]"
    end = source.find(closing, index + 1)
    return len(source) if end == -1 else end + len(closing)


def _skip_short_string(source: str, index: int) -> int:
    quote = source[index]
    i = index + 1
    while i < len(source):
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return len(source)


def _find_balanced_close(source: str, start: int, open_char: str, close_char: str) -> int:
    if start >= len(source) or source[start] != open_char:
        return start

    depth = 1
    i = start + 1
    length = len(source)

    while i < length:
        if source.startswith("--", i):
            if (lb := _match_long_bracket(source, i + 2)) is not None:
                i = _skip_long_bracket(source, i + 2, lb)
            else:
                newline = source.find("\n", i + 2)
                i = length if newline == -1 else newline + 1
            continue

        ch = source[i]

        if ch in {'"', "'"}:
            i = _skip_short_string(source, i)
            continue

        if (lb := _match_long_bracket(source, i)) is not None:
            i = _skip_long_bracket(source, i, lb)
            continue

        if ch == open_char:
            depth += 1
            i += 1
            continue

        if ch == close_char:
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue

        i += 1

    return start


def _count_arguments(inner: str) -> int:
    parts = [part.strip() for part in inner.split(",")]
    return sum(1 for part in parts if part)


_NUMERIC_ARRAY_PATTERN = re.compile(
    r"""(?x)
    \A
    (?:
        \s*
        -?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
        \s*
        (?:,
            \s*
            -?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
            \s*
        )*
        ,?
        \s*
    )?
    \Z
    """
)


def _chunks_to_json(chunks: Sequence[BootstrapChunk]) -> str:
    return json.dumps([asdict(chunk) for chunk in chunks], indent=2) + "\n"


def _candidates_to_json(candidates: Sequence[BootstrapCandidate]) -> str:
    return json.dumps([candidate.to_dict() for candidate in candidates], indent=2) + "\n"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="latin-1")


def _load_manifest(path: Path) -> Sequence[Dict[str, Any]]:
    data = json.loads(_read_text(path))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        manifest = data.get("manifest")
        if isinstance(manifest, list):
            return manifest
    raise ValueError("Manifest file must contain a JSON array of entries")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Analyse loader manifests to identify bootstrap candidates or "
            "fallback to legacy direct source scanning."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help=(
            "Path to raw_manifest.json (preferred). A non-JSON file triggers "
            "legacy scanning of Lua source text."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "bootstrap_candidates.json",
        help=(
            "Destination for the JSON report (default: out/bootstrap_candidates.json)."
            " Legacy mode reuses this path for bootstrap_chunks.json output."
        ),
    )
    parser.add_argument(
        "--min-string-char-args",
        type=int,
        default=DEFAULT_STRING_CHAR_ARG_THRESHOLD,
        help="Minimum number of arguments for string.char() chunks to be captured.",
    )
    parser.add_argument(
        "--min-string-char-length",
        type=int,
        default=DEFAULT_STRING_CHAR_LENGTH_THRESHOLD,
        help="Minimum character length for string.char() chunks to be captured.",
    )
    parser.add_argument(
        "--raw-text",
        type=Path,
        help="Path to the normalized raw payload text (used for manifest analysis).",
    )
    parser.add_argument(
        "--max-snippet",
        type=int,
        default=_DEFAULT_MAX_SNIPPET,
        help="Maximum snippet length to include in candidate summaries.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (default: INFO).",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(message)s")

    if args.path.suffix.lower() != ".json":
        text = _read_text(args.path)
        LOGGER.info("Legacy scan of %s", args.path)
        chunks = extract_bootstrap_chunks(
            text,
            min_string_char_args=args.min_string_char_args,
            min_string_char_length=args.min_string_char_length,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(_chunks_to_json(chunks), encoding="utf-8")
        LOGGER.info("Wrote %d chunk(s) to %s", len(chunks), args.output)
        if chunks:
            for chunk in chunks:
                LOGGER.info(
                    "%s chunk at [%d, %d) length=%d",
                    chunk.kind,
                    chunk.start,
                    chunk.end,
                    chunk.end - chunk.start,
                )
        else:
            LOGGER.info("No bootstrap constructs detected.")
        return 0

    manifest_entries = _load_manifest(args.path)
    raw_text: Optional[str] = None
    if args.raw_text:
        raw_text = _read_text(args.raw_text)
    else:
        fallback = args.path.with_name("raw_payload.txt")
        if fallback.exists():
            raw_text = _read_text(fallback)
        else:
            LOGGER.warning(
                "Raw text not provided; snippets will be limited to payload artefacts."
            )

    manifest_base = args.path.parent.resolve()
    LOGGER.info(
        "Analysing manifest %s (base %s) with %d entries",
        args.path,
        manifest_base,
        len(manifest_entries),
    )
    candidates = identify_bootstrap_candidates(
        manifest_entries,
        raw_text,
        manifest_base,
        max_snippet=args.max_snippet,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(_candidates_to_json(candidates), encoding="utf-8")
    LOGGER.info("Wrote %d bootstrap candidate(s) to %s", len(candidates), args.output)
    if not candidates:
        LOGGER.info("No bootstrap candidates detected.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
