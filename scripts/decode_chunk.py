#!/usr/bin/env python3
"""Utility to decode a single chunk from ``Obfuscated.json``.

The helper mirrors the initv4 bootstrapper pipeline as closely as possible:

* Collect the chunk into a single printable blob.
* Attempt to recover the initv4 alphabet from the bootstrapper (if available)
  and decode the blob using the initv4 basE91 variant.
* Fall back to the default alphabet or an ascii85 decode when basE91 fails.
* Apply the script-key XOR stage followed by the index XOR mixing.

When the final byte stream cannot be decoded as UTF-8 the script emits a
formatted Lua comment containing a hex/ASCII view of the payload instead of a
binary artefact.  This keeps the output text-based while still exposing the raw
bytes for further manual analysis.
"""

from __future__ import annotations

import argparse
import base64
import bz2
import json
import lzma
import re
import zlib
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

DEFAULT_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~\"'\\"
)

ALPHABET_PATTERN = re.compile(r"([!-~]{85,})")


def _load_json(path: Path) -> list[object]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _normalise_chunk(chunk: object) -> str:
    if isinstance(chunk, str):
        return chunk
    if isinstance(chunk, Sequence):
        try:
            return "".join(str(part) for part in chunk)
        except Exception as exc:  # pragma: no cover - defensive
            raise TypeError(f"Chunk cannot be concatenated: {chunk!r}") from exc
    raise TypeError(f"Unsupported chunk type: {type(chunk)!r}")


def _prepare_alphabet(candidate: Optional[str]) -> tuple[str, dict[str, int], int]:
    if candidate:
        unique = []
        seen: set[str] = set()
        for char in candidate:
            if char in seen:
                continue
            seen.add(char)
            unique.append(char)
        if len(unique) >= 85:
            alphabet = "".join(unique)
            return alphabet, {symbol: idx for idx, symbol in enumerate(alphabet)}, len(alphabet)
    alphabet = DEFAULT_ALPHABET
    return alphabet, {symbol: idx for idx, symbol in enumerate(alphabet)}, len(alphabet)


def _decode_base91(blob: str, *, alphabet: Optional[str] = None) -> bytes:
    """Decode *blob* using the initv4 basE91 alphabet."""

    alphabet, mapping, base = _prepare_alphabet(alphabet)
    value = -1
    buffer = 0
    bits = 0
    output = bytearray()

    for char in blob:
        if char.isspace():
            continue
        if char not in mapping:
            raise ValueError(f"invalid initv4 symbol: {char!r}")
        symbol = mapping[char]
        if value < 0:
            value = symbol
            continue

        value += symbol * base
        buffer |= value << bits
        if value & 0x1FFF > 88:
            bits += 13
        else:
            bits += 14

        while bits >= 8:
            output.append(buffer & 0xFF)
            buffer >>= 8
            bits -= 8

        value = -1

    if value + 1:
        buffer |= value << bits
        output.append(buffer & 0xFF)

    return bytes(output)


def _decode_ascii85(blob: str) -> bytes:
    try:
        return base64.a85decode(
            blob.encode("ascii"),
            adobe=False,
            ignorechars=b"\r\n\t ",
        )
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError(f"ascii85 decode failed: {exc}") from exc


def _apply_script_key_transform(data: bytes, key_bytes: bytes) -> bytes:
    if not data:
        return b""

    key_len = len(key_bytes)
    output = bytearray(len(data))
    for index, value in enumerate(data):
        if key_len:
            value ^= key_bytes[index % key_len]
        value ^= index & 0xFF
        output[index] = value & 0xFF
    return bytes(output)


def _iter_decoders(alphabet: Optional[str]) -> Iterable[tuple[str, Callable[[str], bytes]]]:
    yield "ascii85", _decode_ascii85
    yield "base91", lambda blob: _decode_base91(blob, alphabet=alphabet)


def decode_chunk(
    chunk: object,
    script_key: str,
    *,
    alphabet: Optional[str] = None,
) -> tuple[bytes, str, Optional[str], list[str]]:
    """Decode *chunk* with the initv4 pipeline.

    The helper now continues iterating through the configured decoders until one
    of them produces human readable text (either directly or after a secondary
    compression stage is peeled away).  When all strategies fail to recover
    UTF-8 we return the best-effort byte stream alongside the recorded notes so
    callers can render a hexdump fallback."""

    joined = _normalise_chunk(chunk)
    last_error: Optional[str] = None
    best_attempt: Optional[tuple[bytes, str, list[str]]] = None

    for name, decoder in _iter_decoders(alphabet):
        try:
            decoded = decoder(joined)
        except Exception as exc:  # pragma: no cover - decode fallback
            last_error = f"{name} decode failed: {exc}"
            continue

        output = _apply_script_key_transform(decoded, script_key.encode("utf-8"))
        text, notes = _attempt_transforms(output)
        if text is not None:
            return output, name, text, notes

        if best_attempt is None:
            best_attempt = (output, name, notes)

    if best_attempt is not None:
        decoded, strategy, notes = best_attempt
        return decoded, strategy, None, notes

    if last_error:
        raise ValueError(last_error)
    raise ValueError("no decode strategy succeeded")


def _auto_detect_alphabet(path: Optional[Path]) -> Optional[str]:
    if not path:
        return None
    text = path.read_text(encoding="utf-8", errors="ignore")
    longest: Optional[str] = None
    for candidate in ALPHABET_PATTERN.findall(text):
        if len(set(candidate)) >= 85:
            if longest is None or len(candidate) > len(longest):
                longest = candidate
    return longest


def _attempt_transforms(data: bytes) -> tuple[Optional[str], list[str]]:
    attempts: list[str] = []
    # zlib/bzip2/lzma are the most common secondary wrappers.
    for name, func in (
        ("zlib", zlib.decompress),
        ("bz2", bz2.decompress),
        ("lzma", lzma.decompress),
    ):
        try:
            transformed = func(data)
        except Exception:
            continue
        try:
            return transformed.decode("utf-8"), [f"{name} decompression succeeded"]
        except UnicodeDecodeError:
            attempts.append(f"{name} decompression produced non-UTF-8 bytes")

    # Some payloads encode printable hex after the ascii85 layer.
    if data and all(chr(byte) in "0123456789abcdefABCDEF\r\n\t " for byte in data):
        stripped_bytes = bytearray()
        for byte in data:
            ch = chr(byte)
            if ch in "\r\n\t ":
                continue
            stripped_bytes.append(byte)
        stripped = bytes(stripped_bytes)
        if len(stripped) % 2 == 0:
            try:
                decoded = bytes.fromhex(stripped.decode("ascii"))
            except ValueError:
                attempts.append("ascii hex decode failed")
            else:
                try:
                    return decoded.decode("utf-8"), ["hex decode succeeded"]
                except UnicodeDecodeError:
                    attempts.append("hex decode produced non-UTF-8 bytes")

    try:
        return data.decode("utf-8"), ["raw UTF-8 decode succeeded"]
    except UnicodeDecodeError:
        attempts.append("raw UTF-8 decode failed")

    return None, attempts


def _format_hexdump(data: bytes, *, width: int = 16) -> str:
    lines: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decode a chunk from Obfuscated.json")
    parser.add_argument("json_path", type=Path, help="Path to Obfuscated.json")
    parser.add_argument("chunk_index", type=int, help="Chunk index to decode (1-based)")
    parser.add_argument("output", type=Path, help="Where to write the decoded bytes")
    parser.add_argument("--script-key", required=True, help="Script key for XOR stage")
    parser.add_argument(
        "--bootstrapper",
        type=Path,
        help="Optional path to initv4 bootstrapper for alphabet recovery",
    )
    args = parser.parse_args()

    data = _load_json(args.json_path)
    index = args.chunk_index
    if index < 0 or index >= len(data):
        raise IndexError(f"chunk_index {index} out of bounds for {len(data)} entries")

    chunk = data[index]
    alphabet = _auto_detect_alphabet(args.bootstrapper) if args.bootstrapper else None
    decoded, strategy, text, notes = decode_chunk(
        chunk, args.script_key, alphabet=alphabet
    )

    if text is None:
        hexdump = _format_hexdump(decoded)
        attempts = ", ".join(notes) if notes else "none"
        lines = [
            f"-- chunk {index} ({len(decoded)} bytes) decoded with {strategy}; unable to recover UTF-8",
            f"-- additional attempts: {attempts}",
            "return [[",
            hexdump,
            "]]",
            "",
        ]
        args.output.write_text("\n".join(lines), encoding="utf-8")
        print(
            f"Decoded chunk {index} -> {args.output} ({len(decoded)} bytes, emitted hexdump)")
        return

    args.output.write_text(text, encoding="utf-8")
    extra = f"; {notes[0]}" if notes else ""
    print(
        f"Decoded chunk {index} -> {args.output} ({len(decoded)} bytes, UTF-8 text via {strategy}{extra})"
    )


if __name__ == "__main__":
    main()
