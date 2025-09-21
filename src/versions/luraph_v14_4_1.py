"""Version handler for the Luraph v14.4.1 ``initv4`` bootstrap format."""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from ..utils_pkg import strings as string_utils
from . import OpSpec, PayloadInfo, VersionHandler, register_handler
from .luraph_v14_2_json import LuraphV142JSON

_INITV4_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)
_INITV4_DECODE = {symbol: index for index, symbol in enumerate(_INITV4_ALPHABET)}
_INITV4_BASE = len(_INITV4_ALPHABET)

_BASE64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

_INIT_STUB_RE = re.compile(r"init_fn\s*\(", re.IGNORECASE)
_SCRIPT_KEY_ASSIGN_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*(?P<expr>[^\n;]+)",
    re.IGNORECASE,
)
_HIGH_ENTROPY_RE = re.compile(rf"[{re.escape(_INITV4_ALPHABET)}]{{200,}}")
_JSON_BLOCKS = (
    re.compile(r"\[\[(\s*\{.*?\})\]\]", re.DOTALL),
    re.compile(r'"(\{\s*\"constants\".*?\})"', re.DOTALL),
)


def _decode_base91(blob: str) -> bytes:
    """Decode a base91-like blob using the initv4 alphabet."""

    value = -1
    buffer = 0
    bits = 0
    output = bytearray()

    for char in blob:
        if char.isspace():
            continue
        if char not in _INITV4_DECODE:
            raise ValueError(f"invalid initv4 symbol: {char!r}")
        symbol = _INITV4_DECODE[char]
        if value < 0:
            value = symbol
            continue

        value += symbol * _INITV4_BASE
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


def _encode_base91(data: bytes) -> str:
    """Encode *data* using the initv4 alphabet (for fixtures/tests)."""

    buffer = 0
    bits = 0
    encoded: List[str] = []

    for byte in data:
        buffer |= byte << bits
        bits += 8
        if bits > 13:
            value = buffer & 0x1FFF
            if value > 88:
                buffer >>= 13
                bits -= 13
            else:
                value = buffer & 0x3FFF
                buffer >>= 14
                bits -= 14
            encoded.append(_INITV4_ALPHABET[value % _INITV4_BASE])
            encoded.append(_INITV4_ALPHABET[value // _INITV4_BASE])

    if bits:
        encoded.append(_INITV4_ALPHABET[buffer % _INITV4_BASE])
        if bits > 7 or buffer > _INITV4_BASE:
            encoded.append(_INITV4_ALPHABET[buffer // _INITV4_BASE])

    return "".join(encoded)


def _score_decoded_bytes(data: bytes) -> float:
    """Return a heuristic score describing how plausible *data* looks."""

    if not data:
        return 0.0
    if data.startswith(b"\x1bLua"):
        return 1.0

    printable = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    zero_ratio = data.count(0) / len(data)
    score = printable / len(data) if data else 0.0
    score = max(0.1, score - zero_ratio * 0.1)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return max(0.0, min(score, 1.0))

    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        score = max(score, 0.9)
    lowered = stripped.lower()
    if "bytecode" in lowered or "constants" in lowered:
        score = max(score, 0.95)
    score = max(score, string_utils.text_score(text))
    return max(0.0, min(score, 1.0))


def _decode_attempts(
    blob: str, script_key: str
) -> Tuple[bytes, Dict[str, object]]:
    """Try multiple decode strategies and pick the most plausible result."""

    cleaned = blob.strip()
    if not cleaned:
        return b"", {"decode_method": "empty", "decode_attempts": []}

    key_bytes = script_key.encode("utf-8") if script_key else b""
    attempts: List[Dict[str, object]] = []
    errors: Dict[str, str] = {}

    def _record(method: str, raw: Optional[bytes]) -> None:
        if raw is None:
            return
        decoded = string_utils.xor_bytes(raw, key_bytes) if key_bytes else raw
        attempts.append(
            {
                "method": method,
                "data": decoded,
                "size": len(decoded),
                "score": _score_decoded_bytes(decoded),
            }
        )

    allow_base91 = cleaned and any(ch not in _BASE64_CHARSET for ch in cleaned)
    if allow_base91:
        try:
            decoded = _decode_base91(cleaned)
        except ValueError as exc:
            errors["base91"] = str(exc)
        else:
            _record("base91", decoded)

    base_candidate = string_utils.maybe_base64(cleaned)
    if base_candidate:
        _record("base64", base_candidate)

    if not base_candidate and cleaned:
        base_chars = sum(1 for ch in cleaned if ch in _BASE64_CHARSET)
        if base_chars / len(cleaned) > 0.9:
            stripped = re.sub(r"[^A-Za-z0-9+/=_-]", "", cleaned)
            if stripped:
                padded = stripped + "=" * (-len(stripped) % 4)
                try:
                    _record("base64-relaxed", base64.b64decode(padded, validate=False))
                except Exception as exc:  # pragma: no cover - defensive
                    errors.setdefault("base64-relaxed", str(exc))

    hex_candidate = string_utils.maybe_hex(cleaned)
    if hex_candidate:
        _record("hex", hex_candidate)

    decimal_candidate = cleaned.strip()
    if decimal_candidate and re.fullmatch(r"[0-9\s,;:\-]+", decimal_candidate):
        numbers: List[int] = []
        for chunk in re.findall(r"-?\d+", decimal_candidate):
            try:
                numbers.append(int(chunk, 10) & 0xFF)
            except ValueError:
                continue
        if len(numbers) >= 4:
            _record("decimal", bytes(numbers))

    if not attempts:
        raise ValueError("unable to decode payload blob")

    attempts.sort(key=lambda entry: (entry["score"], entry["size"]), reverse=True)
    best = attempts[0]
    base91_present = any(entry["method"] == "base91" for entry in attempts)

    metadata: Dict[str, object] = {
        "decode_method": best["method"],
        "decode_score": round(float(best["score"]), 4),
        "decode_attempts": [
            {
                "method": entry["method"],
                "size": entry["size"],
                "score": round(float(entry["score"]), 4),
            }
            for entry in attempts
        ],
    }
    if best["score"] < 0.25:
        metadata["low_confidence"] = True
    if base91_present and best["method"] != "base91":
        metadata["fallback_used"] = True
    if errors:
        metadata["decode_errors"] = errors

    return best["data"], metadata


def decode_blob(encoded_blob: str, script_key: str) -> bytes:
    """Decode an ``initv4`` payload using base91 + XOR heuristics."""

    data, _ = decode_blob_with_metadata(encoded_blob, script_key)
    return data


def decode_blob_with_metadata(
    encoded_blob: str, script_key: str
) -> Tuple[bytes, Dict[str, object]]:
    """Decode *encoded_blob* and return both data and decode metadata."""

    return _decode_attempts(encoded_blob, script_key)


def _extract_script_key(text: str) -> Tuple[Optional[str], Dict[str, str]]:
    """Return a literal script key and metadata describing the expression."""

    match = _SCRIPT_KEY_ASSIGN_RE.search(text)
    metadata: Dict[str, str] = {}
    if not match:
        return None, metadata
    expr = match.group("expr").strip()
    metadata["script_key_expr"] = expr
    literal = re.search(r"(['\"])(?P<value>[^'\"]+)\1", expr)
    if literal:
        metadata["script_key_source"] = "literal"
        return literal.group("value"), metadata
    metadata["script_key_source"] = "expression"
    return None, metadata


def _anchor_index(text: str) -> int:
    match = _INIT_STUB_RE.search(text)
    if match:
        return match.start()
    return 0


def _locate_json_block(text: str, *, start: int) -> Tuple[str, int, int, Dict[str, object]] | None:
    for pattern in _JSON_BLOCKS:
        match = pattern.search(text, pos=start)
        if not match:
            continue
        candidate = match.group(1).strip()
        try:
            data = json.loads(candidate)
        except Exception:
            continue
        if isinstance(data, dict):
            begin, end = match.span(1)
            return candidate, begin, end, data
    return None


def _locate_base64_blob(text: str, *, start: int) -> Tuple[str, int, int] | None:
    best: Tuple[str, int, int] | None = None
    for match in _HIGH_ENTROPY_RE.finditer(text, pos=start):
        blob = match.group(0)
        span = match.span(0)
        if best is None or len(blob) > len(best[0]):
            best = (blob, span[0], span[1])
    if best:
        return best
    # Fallback to earlier blobs if none appeared after ``start``
    if start:
        for match in _HIGH_ENTROPY_RE.finditer(text):
            blob = match.group(0)
            span = match.span(0)
            if best is None or len(blob) > len(best[0]):
                best = (blob, span[0], span[1])
    return best


_BASE_OPCODE_TABLE: Dict[int, OpSpec] = LuraphV142JSON().opcode_table()


class LuraphV1441(VersionHandler):
    """Handle ``initv4`` bootstrap loaders used by Luraph v14.4.1.

    The bootstrap embeds a JSON object (when ``write_json`` is enabled) or a
    plain base64 blob containing the VM bytecode and constant pool.  Regardless
    of the transport, the payload must be XOR-decrypted with the user-visible
    ``script_key`` before it can be lifted.  This handler extracts metadata about
    the key, records the payload format, and returns decrypted bytes to the
    pipeline.
    """

    name = "v14.4.1"
    priority = 80

    def matches(self, text: str) -> bool:
        return (
            _HIGH_ENTROPY_RE.search(text) is not None
            and _INIT_STUB_RE.search(text) is not None
            and _SCRIPT_KEY_ASSIGN_RE.search(text) is not None
        )

    def locate_payload(self, text: str) -> PayloadInfo | None:
        script_key, key_meta = _extract_script_key(text)
        base_meta: Dict[str, object] = dict(key_meta)
        if script_key:
            base_meta["script_key"] = script_key

        start = _anchor_index(text)
        json_block = _locate_json_block(text, start=start)
        if json_block is not None:
            blob, begin, end, data = json_block
            meta = dict(base_meta)
            meta["format"] = "json"
            return PayloadInfo(blob, begin, end, data=data, metadata=meta)

        base64_blob = _locate_base64_blob(text, start=start)
        if base64_blob is None:
            return None

        blob, begin, end = base64_blob
        meta = dict(base_meta)
        meta.setdefault("format", "base64")
        return PayloadInfo(blob, begin, end, metadata=meta)

    def extract_bytecode(self, payload: PayloadInfo) -> bytes:
        metadata = payload.metadata or {}
        if payload.metadata is None:
            payload.metadata = metadata
        provider = metadata.get("script_key_provider")
        script_key = metadata.get("script_key")
        if script_key:
            provider = provider or "literal"

        override = metadata.pop("_script_key_override", None)
        if not script_key and override:
            script_key = str(override)
            provider = "override"

        if not script_key:
            env_key = os.environ.get("LURAPH_SCRIPT_KEY", "")
            if env_key:
                script_key = env_key
                provider = provider or "environment"

        if not script_key:
            raise RuntimeError(
                "Luraph v14.4.1 payloads require a script key. Supply one via --script-key or the LURAPH_SCRIPT_KEY environment variable."
            )

        raw, decode_meta = decode_blob_with_metadata(payload.text, script_key)
        metadata["decoded_bytes"] = len(raw)
        metadata.update({key: value for key, value in decode_meta.items() if key != "decode_attempts"})
        if decode_meta.get("decode_attempts"):
            metadata["decode_attempts"] = decode_meta["decode_attempts"]
        if provider:
            metadata["script_key_provider"] = provider
        metadata.setdefault("format", metadata.get("format", "base64"))

        try:
            decoded_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = ""
        if decoded_text:
            stripped = decoded_text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    mapping = json.loads(stripped)
                except json.JSONDecodeError:
                    pass
                else:
                    payload.data = mapping
                    metadata["decoded_json"] = True
                    if isinstance(mapping, dict) and isinstance(mapping.get("script"), str):
                        metadata["script_payload"] = True

        return raw

    def opcode_table(self) -> Dict[int, OpSpec]:
        return dict(_BASE_OPCODE_TABLE)


register_handler(LuraphV1441)

HANDLER = LuraphV1441()

__all__ = ["LuraphV1441", "decode_blob", "decode_blob_with_metadata", "HANDLER"]
