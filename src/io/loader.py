"""Utilities for loading Lua sources and extracting large payloads."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

# Threshold (inclusive) for string literal extraction in bytes.
DEFAULT_EXTRACTION_THRESHOLD = 1024

# Regular expression that covers long bracket strings, single-quoted, and double-quoted
# Lua literals. The order matters: long strings are matched first to avoid greedy
# consumption inside quotes.
_STRING_PATTERN = re.compile(
    r"""
    (?P<long>\[(?P<equals>=*)\[(?P<long_content>.*?)(?<!\\)\](?P=equals)\])
    |
    (?P<double>"(?P<double_content>(?:[^"\\]|\\.)*)")
    |
    (?P<single>'(?P<single_content>(?:[^'\\]|\\.)*)')
    """,
    re.DOTALL | re.VERBOSE,
)
_CONCAT_PATTERN = re.compile(r"\s*\.\.\s*", re.DOTALL)
_NUMERIC_ARRAY_PATTERN = re.compile(r"\{(?P<body>[\s0-9xXa-fA-F,\.\-+eE]+)\}", re.DOTALL)
_STRING_CHAR_PATTERN = re.compile(r"string\.char\s*\(", re.IGNORECASE)
_LOAD_CALL_PATTERN = re.compile(r"\b(loadstring|load)\s*\(", re.IGNORECASE)
_NUMBER_PATTERN = re.compile(r"[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)")


@dataclass
class ChunkRecord:
    """Record describing an extracted chunk for manifest output."""

    type: str
    start_offset: int
    end_offset: int
    payload_length: int
    source_length: int
    payload_file: Optional[str] = None
    note: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        data = {
            "type": self.type,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "payload_length": self.payload_length,
            "source_length": self.source_length,
        }
        if self.payload_file is not None:
            data["payload_file"] = self.payload_file
        if self.note:
            data["note"] = self.note
        return data


@dataclass
class _PayloadWriter:
    """Helper responsible for writing payload artefacts safely."""

    directory: Optional[Path]
    base_filename: str
    threshold: int
    counters: Dict[str, int] = field(default_factory=dict)

    def write(
        self,
        chunk_type: str,
        payload: bytes,
        *,
        prefer_text: bool = False,
        text_content: Optional[str] = None,
    ) -> Optional[Path]:
        if self.directory is None:
            return None
        if len(payload) < self.threshold:
            return None

        index = self.counters.get(chunk_type, 0) + 1
        self.counters[chunk_type] = index
        suffix = "txt" if prefer_text else "bin"
        filename = f"{self.base_filename}_{chunk_type}_{index:03d}.{suffix}"
        path = self.directory / filename
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if prefer_text:
                content = text_content if text_content is not None else payload.decode(
                    "utf-8", errors="ignore"
                )
                path.write_text(content, encoding="utf-8")
            else:
                path.write_bytes(payload)
        except OSError as exc:  # pragma: no cover - filesystem failure
            LOGGER.warning("Unable to write payload %s: %s", path, exc)
            return None

        LOGGER.info("Wrote %s chunk to %s (%d bytes)", chunk_type, path, len(payload))
        return path


def _iter_string_literal_matches(source: str) -> Iterator[Tuple[re.Match[str], str]]:
    """Yield regex matches and decoded contents for string literals."""

    for match in _STRING_PATTERN.finditer(source):
        if match.group("long") is not None:
            content = match.group("long_content")
        elif match.group("double") is not None:
            content = _unescape_lua_string(match.group("double_content"))
        else:
            content = _unescape_lua_string(match.group("single_content"))
        yield match, content


def _group_concatenated_strings(source: str) -> List[Dict[str, Any]]:
    """Group adjacent string literals joined by the concatenation operator."""

    matches = list(_iter_string_literal_matches(source))
    groups: List[Dict[str, Any]] = []
    i = 0
    while i < len(matches):
        match, content = matches[i]
        start = match.start()
        end = match.end()
        pieces = [content]
        j = i + 1
        while j < len(matches):
            next_match, next_content = matches[j]
            between = source[end:next_match.start()]
            if not _CONCAT_PATTERN.fullmatch(between):
                break
            pieces.append(next_content)
            end = next_match.end()
            j += 1
        groups.append(
            {
                "start": start,
                "end": end,
                "content": "".join(pieces),
            }
        )
        i = j
    return groups

def _normalize_line_endings(text: str) -> str:
    """Normalize all line endings to Unix newlines.

    Args:
        text: The input text with arbitrary line endings.

    Returns:
        The text with all CRLF/CR sequences replaced by LF.
    """

    # First collapse CRLF to LF, then standalone CR.
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _iter_string_literals(source: str) -> Iterator[Tuple[str, str]]:
    """Yield all string literal matches and their extracted contents.

    Args:
        source: Normalized Lua source code.

    Yields:
        Tuples of (match_text, inner_content).
    """

    for match in _STRING_PATTERN.finditer(source):
        if match.group("long") is not None:
            content = match.group("long_content")
        elif match.group("double") is not None:
            content = _unescape_lua_string(match.group("double_content"))
        else:
            content = _unescape_lua_string(match.group("single_content"))
        yield match.group(0), content


def _unescape_lua_string(content: str) -> str:
    """Decode a Lua short string literal body."""

    mapping = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\\": "\\",
        '"': '"',
        "'": "'",
    }

    result: List[str] = []
    i = 0
    while i < len(content):
        ch = content[i]
        if ch != "\\":
            result.append(ch)
            i += 1
            continue

        i += 1
        if i >= len(content):
            result.append("\\")
            break

        esc = content[i]
        i += 1
        if esc in mapping:
            result.append(mapping[esc])
            continue

        if esc.isdigit():
            digits = esc
            while i < len(content) and len(digits) < 3 and content[i].isdigit():
                digits += content[i]
                i += 1
            try:
                result.append(chr(int(digits, 10)))
            except ValueError:
                result.append("\\" + digits)
            continue

        if esc == "x":
            hex_digits = content[i : i + 2]
            if len(hex_digits) == 2 and re.fullmatch(r"[0-9a-fA-F]{2}", hex_digits):
                result.append(chr(int(hex_digits, 16)))
                i += 2
                continue
            result.append("\\x")
            continue

        if esc == "z":
            while i < len(content) and content[i] in " \t\r\n":
                i += 1
            continue

        result.append("\\" + esc)

    return "".join(result)


def _parse_number(token: str) -> int:
    token = token.strip()
    if not token:
        raise ValueError("empty token")
    if token.lower().startswith("0x"):
        return int(token, 16)
    if any(ch in token for ch in ".eE"):
        return int(float(token))
    return int(token, 10)


def _parse_number_sequence(body: str) -> List[int]:
    values: List[int] = []
    for token in _NUMBER_PATTERN.findall(body):
        try:
            values.append(_parse_number(token))
        except ValueError:
            LOGGER.debug("Skipping unparsable numeric token: %s", token)
    return values


def _append_note(base: Optional[str], addition: str) -> str:
    return f"{base}; {addition}" if base else addition


def _find_matching_paren(source: str, open_index: int) -> int:
    depth = 0
    i = open_index
    in_short: Optional[str] = None
    in_long: Optional[int] = None
    escape = False
    length = len(source)

    while i < length:
        ch = source[i]
        if in_short:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_short:
                in_short = None
            i += 1
            continue

        if in_long is not None:
            if ch == "]":
                eq_count = 0
                j = i + 1
                while j < length and source[j] == "=":
                    eq_count += 1
                    j += 1
                if j < length and source[j] == "]" and eq_count == in_long:
                    in_long = None
                    i = j + 1
                    continue
            i += 1
            continue

        if ch in ('"', "'"):
            in_short = ch
            i += 1
            continue

        if ch == "[":
            eq_count = 0
            j = i + 1
            while j < length and source[j] == "=":
                eq_count += 1
                j += 1
            if j < length and source[j] == "[":
                in_long = eq_count
                i = j + 1
                continue

        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1

    return -1


def _iter_string_char_calls(source: str) -> Iterator[Tuple[int, int, str]]:
    for match in _STRING_CHAR_PATTERN.finditer(source):
        open_index = match.end() - 1
        close_index = _find_matching_paren(source, open_index)
        if close_index == -1:
            continue
        yield match.start(), close_index + 1, source[open_index + 1 : close_index]


def _iter_load_calls(source: str) -> Iterator[Tuple[str, int, int, str]]:
    for match in _LOAD_CALL_PATTERN.finditer(source):
        open_index = match.end() - 1
        close_index = _find_matching_paren(source, open_index)
        if close_index == -1:
            continue
        name = match.group(1).lower()
        yield name, match.start(), close_index + 1, source[open_index + 1 : close_index]


def _collect_numeric_arrays(
    source: str,
    manifest: List[ChunkRecord],
    writer: _PayloadWriter,
) -> None:
    for match in _NUMERIC_ARRAY_PATTERN.finditer(source):
        body = match.group("body")
        values = _parse_number_sequence(body)
        payload_bytes: bytes
        prefer_text = False
        text_payload: Optional[str] = None
        note: Optional[str] = None
        if not values:
            payload_bytes = b""
            note = "no numeric tokens"
        elif all(0 <= value <= 255 for value in values):
            payload_bytes = bytes(value & 0xFF for value in values)
        else:
            text_payload = ",".join(str(value) for value in values)
            payload_bytes = text_payload.encode("utf-8")
            prefer_text = True
            note = _append_note(note, "values exceed byte range")

        path = writer.write(
            "numeric_array",
            payload_bytes,
            prefer_text=prefer_text,
            text_content=text_payload,
        )
        if path is None:
            if writer.directory is None:
                note = _append_note(note, "no payload directory configured")
            elif len(payload_bytes) < writer.threshold:
                note = _append_note(note, f"below threshold ({len(payload_bytes)} bytes)")
            else:
                note = _append_note(note, "failed to write payload")

        manifest.append(
            ChunkRecord(
                type="numeric-array",
                start_offset=match.start(),
                end_offset=match.end(),
                payload_length=len(payload_bytes),
                source_length=match.end() - match.start(),
                payload_file=str(path) if path is not None else None,
                note=note,
            )
        )


def _collect_string_char_sequences(
    source: str,
    manifest: List[ChunkRecord],
    writer: _PayloadWriter,
) -> None:
    for start, end, body in _iter_string_char_calls(source):
        values = _parse_number_sequence(body)
        note: Optional[str] = "string.char call"
        prefer_text = False
        text_payload: Optional[str] = None
        if not values:
            payload_bytes = b""
            note = _append_note(note, "no numeric tokens")
        elif all(0 <= value <= 255 for value in values):
            payload_bytes = bytes(value & 0xFF for value in values)
        else:
            text_payload = ",".join(str(value) for value in values)
            payload_bytes = text_payload.encode("utf-8")
            prefer_text = True
            note = _append_note(note, "values exceed byte range")

        path = writer.write(
            "stringchar",
            payload_bytes,
            prefer_text=prefer_text,
            text_content=text_payload,
        )
        if path is None:
            if writer.directory is None:
                note = _append_note(note, "no payload directory configured")
            elif len(payload_bytes) < writer.threshold:
                note = _append_note(note, f"below threshold ({len(payload_bytes)} bytes)")
            else:
                note = _append_note(note, "failed to write payload")

        manifest.append(
            ChunkRecord(
                type="escaped-string",
                start_offset=start,
                end_offset=end,
                payload_length=len(payload_bytes),
                source_length=end - start,
                payload_file=str(path) if path is not None else None,
                note=note,
            )
        )


def _collect_load_calls(
    source: str,
    manifest: List[ChunkRecord],
) -> None:
    for name, start, end, arguments in _iter_load_calls(source):
        payload_bytes = arguments.encode("utf-8", errors="ignore")
        manifest.append(
            ChunkRecord(
                type="loadstring" if name == "loadstring" else "load",
                start_offset=start,
                end_offset=end,
                payload_length=len(payload_bytes),
                source_length=end - start,
                note=None,
            )
        )


def _collect_chunks(
    source: str,
    *,
    threshold: int,
    payload_dir: Optional[Path],
    base_filename: str,
) -> Tuple[Dict[str, str], List[ChunkRecord]]:
    manifest: List[ChunkRecord] = []
    string_payloads = extract_large_strings(
        source,
        threshold=threshold,
        output_dir=payload_dir,
        base_filename=base_filename,
        manifest=manifest,
    )

    writer = _PayloadWriter(directory=payload_dir, base_filename=base_filename, threshold=threshold)
    _collect_numeric_arrays(source, manifest, writer)
    _collect_string_char_sequences(source, manifest, writer)
    _collect_load_calls(source, manifest)

    return string_payloads, manifest


def extract_large_strings(
    source: str,
    *,
    threshold: int = DEFAULT_EXTRACTION_THRESHOLD,
    output_dir: Optional[Path] = None,
    base_filename: str = "payload",
    manifest: Optional[List[ChunkRecord]] = None,
) -> Dict[str, str]:
    """Extract large string literals from Lua source code.

    Args:
        source: Lua source code.
        threshold: The minimum size (in bytes) for extraction.
        output_dir: Optional output directory for writing payload files.
        base_filename: Prefix for generated payload files.

    Returns:
        Mapping of generated filenames to extracted payload text.
    """

    if threshold < 0:
        raise ValueError("threshold must be non-negative")

    extracted: Dict[str, str] = {}
    groups = _group_concatenated_strings(source)
    payload_dir = output_dir
    for index, group in enumerate(groups, start=1):
        content = group["content"]
        payload_bytes = content.encode("utf-8", errors="ignore")
        filename = f"{base_filename}_{index:03d}.txt"
        path_str: Optional[str] = None
        if payload_dir is not None and len(payload_bytes) > threshold:
            path = payload_dir / filename
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                path_str = str(path)
                LOGGER.info("Wrote payload %s (%d bytes)", path, len(payload_bytes))
            except OSError as exc:  # pragma: no cover - filesystem failure
                LOGGER.warning("Unable to write payload %s: %s", path, exc)
        if len(payload_bytes) > threshold:
            extracted[filename] = content
        note: Optional[str] = None
        if len(payload_bytes) <= threshold:
            note = f"below threshold ({len(payload_bytes)} bytes)"
        if manifest is not None:
            manifest.append(
                ChunkRecord(
                    type="escaped-string",
                    start_offset=group["start"],
                    end_offset=group["end"],
                    payload_length=len(payload_bytes),
                    source_length=group["end"] - group["start"],
                    payload_file=path_str,
                    note=note,
                )
            )
    return extracted


def load_lua_file(
    path: Path | str,
    *,
    threshold: int = DEFAULT_EXTRACTION_THRESHOLD,
    output_dir: Optional[Path] = None,
    include_manifest: bool = False,
) -> Tuple[str, Dict[str, str]] | Tuple[str, Dict[str, str], List[Dict[str, Any]]]:
    """Load and normalize a Lua file, optionally extracting large strings.

    Args:
        path: Path to the Lua file.
        threshold: Threshold for string literal extraction.
        output_dir: Directory to store extracted payload files.

    Returns:
        When ``include_manifest`` is False, returns ``(normalized_source, payload_map)``.
        When True, returns ``(normalized_source, payload_map, manifest_entries)`` where the
        manifest is a list of dictionaries suitable for JSON serialization.
    """

    lua_path = Path(path)
    if not lua_path.is_file():
        raise FileNotFoundError(f"Lua source not found: {lua_path}")

    try:
        text = lua_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = lua_path.read_text(encoding="latin-1")

    normalized = _normalize_line_endings(text)
    payload_dir = output_dir
    extracted, manifest = _collect_chunks(
        normalized,
        threshold=threshold,
        payload_dir=payload_dir,
        base_filename=lua_path.stem,
    )
    if include_manifest:
        return normalized, extracted, [record.as_dict() for record in manifest]
    return normalized, extracted


def _write_raw_payload(raw_text: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(raw_text, encoding="utf-8")
    LOGGER.info("Wrote raw payload to %s", output_path)


def _format_payload_report(manifest: Sequence[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for entry in manifest:
        payload_file = entry.get("payload_file")
        payload_length = entry.get("payload_length")
        chunk_type = entry.get("type")
        if payload_file:
            lines.append(
                f"{payload_file} ({chunk_type}, {payload_length} bytes)"
            )
    return lines


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Load a Lua file, normalize line endings, and extract large string payloads."
        )
    )
    parser.add_argument("path", type=Path, help="Path to the Lua source (e.g., Obfuscated3.lua)")
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_EXTRACTION_THRESHOLD,
        help="Extraction size threshold in bytes (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out"),
        help="Directory where payload files will be written (default: %(default)s)",
    )
    parser.add_argument(
        "--raw-name",
        type=str,
        default="raw_payload.txt",
        help="Filename for the normalized source inside the output directory",
    )

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    output_dir = args.output_dir
    raw_output_path = output_dir / args.raw_name
    payload_dir = output_dir / "payloads"
    manifest_path = output_dir / "raw_manifest.json"

    raw_text, extracted, manifest = load_lua_file(
        args.path,
        threshold=args.threshold,
        output_dir=payload_dir,
        include_manifest=True,
    )
    _write_raw_payload(raw_text, raw_output_path)

    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        LOGGER.info("Wrote manifest to %s", manifest_path)
    except OSError as exc:  # pragma: no cover - filesystem failure
        LOGGER.warning("Failed to write manifest %s: %s", manifest_path, exc)

    report_lines = _format_payload_report(manifest)
    if report_lines:
        print("Extracted payloads:")
        for line in report_lines:
            print(f"  {line}")
    else:
        print("No payload files were written.")

    print(f"Raw payload written to {raw_output_path}")
    print(f"Manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
