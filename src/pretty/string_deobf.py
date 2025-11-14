"""String table deobfuscation helpers.

This module provides a best-effort pipeline that attempts to recover the
original contents of obfuscated string tables commonly found in Luraph 14.4.x
payloads.  Each string is scored after running a collection of decoding
strategies covering base encodings, custom alphabet remappings, XOR/PRGA style
byte mixing, and a simple run-length decoder.  The helpers never execute Lua –
all analysis is purely static – and the resulting candidates are written to JSON
files so analysts can quickly inspect the highest ranking decodings.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import string
import binascii
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "DecodingCandidate",
    "StringEntryResult",
    "decode_string_table",
    "decode_tables_from_file",
    "main",
    "write_candidates",
]

_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
_PREVIEW_MAX = 120

_CUSTOM_ALPHABETS: Tuple[str, ...] = (
    # Common permutations seen in Luraph v14.4.2 payloads.
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",  # digits first
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",  # URL safe ordering
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/",  # upper + digits
)

_COMMON_XOR_KEYS: Tuple[int, ...] = (0x13, 0x27, 0x35, 0x47, 0x5A, 0xA5)


@dataclass
class DecodingCandidate:
    """Single decoding attempt with metadata."""

    method: str
    decoded: bytes
    score: float
    printable_ratio: float
    notes: Tuple[str, ...]

    def to_serialisable(self) -> Mapping[str, object]:
        preview = _preview_text(self.decoded)
        return {
            "method": self.method,
            "score": round(self.score, 4),
            "printable_ratio": round(self.printable_ratio, 4),
            "length": len(self.decoded),
            "preview": preview,
            "base64": base64.b64encode(self.decoded).decode("ascii"),
            "notes": list(self.notes),
        }


@dataclass
class StringEntryResult:
    """Decoded candidate list for a single string entry."""

    index: int
    original: str
    candidates: Tuple[DecodingCandidate, ...]

    def to_serialisable(self) -> Mapping[str, object]:
        return {
            "index": self.index,
            "original": self.original,
            "candidates": [candidate.to_serialisable() for candidate in self.candidates],
        }


def decode_string_table(
    table_name: str,
    values: Sequence[str],
    *,
    max_candidates: int = 5,
    custom_alphabets: Sequence[str] = _CUSTOM_ALPHABETS,
    xor_keys: Sequence[int] = _COMMON_XOR_KEYS,
) -> Mapping[str, object]:
    """Return structured decoding candidates for *values*.

    The returned mapping is JSON serialisable and contains per-entry candidate
    lists along with summary statistics.  Only the top ``max_candidates``
    decodings – ranked by their heuristic scores – are kept for each entry.
    """

    LOGGER.info("Decoding string table \"%s\" (entries=%d)", table_name, len(values))
    entries: List[StringEntryResult] = []
    for index, raw_value in enumerate(values):
        candidates = _decode_entry(raw_value, custom_alphabets=custom_alphabets, xor_keys=xor_keys)
        if candidates:
            ordered = sorted(candidates, key=lambda item: item.score, reverse=True)[:max_candidates]
        else:
            ordered = []
        entries.append(StringEntryResult(index=index, original=raw_value, candidates=tuple(ordered)))

    summary = {
        "table": table_name,
        "entries": len(values),
        "decoded_entries": sum(1 for entry in entries if entry.candidates),
        "average_candidates": (
            sum(len(entry.candidates) for entry in entries) / len(entries) if entries else 0.0
        ),
    }

    return {
        "table": table_name,
        "summary": summary,
        "entries": [entry.to_serialisable() for entry in entries],
    }


def write_candidates(payload: Mapping[str, object], *, output_dir: Path) -> Path:
    """Write ``payload`` to ``output_dir`` using the contained table name."""

    table_name = str(payload.get("table") or "strings")
    destination = output_dir / f"{table_name}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote string candidates to %s", destination)
    return destination


def decode_tables_from_file(path: Path, *, default_name: Optional[str] = None) -> Tuple[str, List[str]]:
    """Load a JSON string table description from *path*.

    The loader accepts either a raw list of strings, an object with ``strings``
    or ``values`` keys, or a mapping where keys are integers.  When a name is
    absent the *default_name* value is used.
    """

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, Mapping):
        name = str(data.get("name") or default_name or path.stem)
        if "strings" in data and isinstance(data["strings"], Sequence):
            values = list(map(str, data["strings"]))
        elif "values" in data and isinstance(data["values"], Sequence):
            values = list(map(str, data["values"]))
        else:
            # treat mapping as index->value
            values = [str(data[key]) for key in sorted(data.keys(), key=str)]
        return name, values
    if isinstance(data, Sequence):
        return default_name or path.stem, [str(item) for item in data]
    raise TypeError("Unsupported string table format; expected array or mapping")


def _decode_entry(
    text: str,
    *,
    custom_alphabets: Sequence[str],
    xor_keys: Sequence[int],
) -> List[DecodingCandidate]:
    base_candidates: List[Tuple[str, bytes, List[str]]] = []

    # Treat the raw string as bytes – useful for tables that already embed
    # escaped characters (e.g. \xNN sequences) after loader normalisation.
    raw_bytes = text.encode("latin-1", errors="ignore")
    base_candidates.append(("raw", raw_bytes, ["latin-1 bytes"]))

    for method, decoded, notes in _initial_decodings(text, custom_alphabets=custom_alphabets):
        base_candidates.append((method, decoded, notes))

    candidates: List[DecodingCandidate] = []
    seen_payloads: Dict[bytes, str] = {}

    for method, payload, notes in base_candidates:
        for candidate in _expand_payload(payload, method, base_notes=tuple(notes), xor_keys=xor_keys):
            if candidate.decoded in seen_payloads:
                continue
            seen_payloads[candidate.decoded] = candidate.method
            candidates.append(candidate)

    return candidates


def _initial_decodings(
    text: str,
    *,
    custom_alphabets: Sequence[str],
) -> Iterable[Tuple[str, bytes, List[str]]]:
    stripped = text.strip()

    # Base64 / URL-safe base64.
    if _looks_like_base64(stripped):
        try:
            decoded = base64.b64decode(stripped, validate=False)
            yield ("base64", decoded, ["base64 decode"])
        except (binascii.Error, ValueError):
            LOGGER.debug("Failed base64 decode for %s", stripped)

    # Base85.
    if _looks_like_base85(stripped):
        try:
            decoded = base64.a85decode(stripped, ignorechars=" \n\r\t")
            yield ("base85", decoded, ["base85 decode"])
        except (ValueError, binascii.Error):
            LOGGER.debug("Failed base85 decode for %s", stripped)

    # Custom base64 alphabets.
    for alphabet in custom_alphabets:
        translated = _remap_alphabet(stripped, alphabet)
        if translated is None:
            continue
        try:
            decoded = base64.b64decode(translated, validate=False)
        except (ValueError, binascii.Error):
            continue
        yield (f"base64({alphabet[:6]}…)", decoded, ["custom alphabet"])


def _expand_payload(
    payload: bytes,
    base_method: str,
    *,
    base_notes: Tuple[str, ...],
    xor_keys: Sequence[int],
) -> Iterable[DecodingCandidate]:
    score, printable, notes = _score_payload(payload)
    yield DecodingCandidate(
        method=base_method,
        decoded=payload,
        score=score,
        printable_ratio=printable,
        notes=base_notes + notes,
    )

    # Attempt XOR / PRGA-like unmixing using common small keys.
    if payload:
        for key in xor_keys:
            decoded = bytes(byte ^ key for byte in payload)
            score, printable, notes = _score_payload(decoded)
            if score <= 0.2:
                continue
            yield DecodingCandidate(
                method=f"{base_method}+xor({key:#04x})",
                decoded=decoded,
                score=score,
                printable_ratio=printable,
                notes=base_notes + (f"xor key {key:#04x}",) + notes,
            )

    # Attempt simple RLE decoding when the payload looks like count/value pairs.
    rle_decoded = _decode_simple_rle(payload)
    if rle_decoded is not None:
        score, printable, notes = _score_payload(rle_decoded)
        yield DecodingCandidate(
            method=f"{base_method}+rle",
            decoded=rle_decoded,
            score=score,
            printable_ratio=printable,
            notes=base_notes + ("simple RLE",) + notes,
        )


def _score_payload(payload: bytes) -> Tuple[float, float, Tuple[str, ...]]:
    if not payload:
        return 0.0, 0.0, ("empty",)

    printable = sum(1 for byte in payload if byte in _PRINTABLE) / len(payload)
    ascii_letters = sum(1 for byte in payload if chr(byte) in string.ascii_letters)
    alpha_ratio = ascii_letters / len(payload)
    null_ratio = payload.count(0) / len(payload)

    score = 0.6 * printable + 0.3 * alpha_ratio + 0.1 * (1.0 - null_ratio)
    notes: List[str] = []
    if printable > 0.85:
        notes.append("mostly printable")
    elif printable > 0.6:
        notes.append("partially printable")
    if alpha_ratio > 0.3:
        notes.append("alphabetic bias")
    if null_ratio > 0.1:
        notes.append("contains nulls")

    return score, printable, tuple(notes)


def _decode_simple_rle(payload: bytes) -> Optional[bytes]:
    if len(payload) < 4 or len(payload) % 2:
        return None
    total = 0
    output = bytearray()
    it = iter(payload)
    try:
        for count in it:
            value = next(it)
            total += count
            if total > 16_384:
                return None
            output.extend([value] * count)
    except StopIteration:
        return None
    if not output or len(output) <= len(payload):
        return None
    return bytes(output)


def _remap_alphabet(text: str, alphabet: str) -> Optional[str]:
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    if len(alphabet) < len(standard):
        return None
    translation = str.maketrans(alphabet[:64], standard)
    translated = text.translate(translation)
    if translated == text:
        # no change – skip to avoid duplicates
        return None
    if not _looks_like_base64(translated):
        return None
    return translated


def _looks_like_base64(text: str) -> bool:
    if not text or any(ch.isspace() for ch in text):
        text = text.replace("\n", "").replace("\r", "")
    if len(text) < 8:
        return False
    return all(ch in string.ascii_letters + string.digits + "+/=\n\r" for ch in text)


def _looks_like_base85(text: str) -> bool:
    if len(text) < 10:
        return False
    return all(33 <= ord(ch) <= 126 or ch.isspace() for ch in text)


def _preview_text(payload: bytes) -> str:
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        decoded = payload.decode("latin-1", errors="replace")
    decoded = decoded.replace("\n", "\\n").replace("\r", "\\r")
    if len(decoded) > _PREVIEW_MAX:
        return decoded[: _PREVIEW_MAX - 3] + "..."
    return decoded


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for the string deobfuscator."""

    parser = argparse.ArgumentParser(description="Deobfuscate string tables")
    parser.add_argument("input", type=Path, help="Path to string table JSON")
    parser.add_argument("--name", help="Override table name")
    parser.add_argument("--out-dir", type=Path, default=Path("out/strings"), help="Destination directory")
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=5,
        help="Maximum candidates per entry (default: 5)",
    )
    args = parser.parse_args(argv)

    table_name, values = decode_tables_from_file(args.input, default_name=args.name)
    payload = decode_string_table(table_name, values, max_candidates=args.max_candidates)
    write_candidates(payload, output_dir=args.out_dir)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI
    raise SystemExit(main())
