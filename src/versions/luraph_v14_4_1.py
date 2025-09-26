"""Version handler for the Luraph v14.4.1 ``initv4`` bootstrap format."""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from types import SimpleNamespace
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set, Tuple

from ..utils_pkg import strings as string_utils
from . import OpSpec, PayloadInfo, VersionHandler, register_handler
from .luraph_v14_2_json import LuraphV142JSON
from .initv4 import InitV4Bootstrap, InitV4Decoder

_INITV4_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)
_INITV4_DECODE = {symbol: index for index, symbol in enumerate(_INITV4_ALPHABET)}
_INITV4_BASE = len(_INITV4_ALPHABET)
_ALPHABET_CACHE: Dict[str, Tuple[str, Dict[str, int], int]] = {}

_BASE64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

_INIT_STUB_RE = re.compile(r"init_fn\s*\(", re.IGNORECASE)
_SCRIPT_KEY_ASSIGN_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*(?P<expr>[^\n;]+)",
    re.IGNORECASE,
)
_HIGH_ENTROPY_RE = re.compile(rf"[{re.escape(_INITV4_ALPHABET)}]{{200,}}")
_CHUNK_STRING_RE = re.compile(
    rf'(["\'])([{re.escape(_INITV4_ALPHABET)}]{{40,}})\1'
)
_JSON_BLOCKS = (
    re.compile(r"\[\[(\s*\{.*?\})\]\]", re.DOTALL),
    re.compile(r'"(\{\s*\"constants\".*?\})"', re.DOTALL),
)


def _prepare_alphabet(
    override: Optional[str],
) -> Tuple[str, Dict[str, int], int]:
    if override:
        if override in _ALPHABET_CACHE:
            return _ALPHABET_CACHE[override]
        if len(override) >= 85 and len(set(override)) == len(override):
            table = {symbol: index for index, symbol in enumerate(override)}
            prepared = (override, table, len(override))
            _ALPHABET_CACHE[override] = prepared
            return prepared
    return _INITV4_ALPHABET, _INITV4_DECODE, _INITV4_BASE


def _decode_base91(blob: str, *, alphabet: Optional[str] = None) -> bytes:
    """Decode a base91-like blob using the initv4 alphabet."""

    _, decode_map, alphabet_base = _prepare_alphabet(alphabet)
    value = -1
    buffer = 0
    bits = 0
    output = bytearray()

    for char in blob:
        if char.isspace():
            continue
        if char not in decode_map:
            raise ValueError(f"invalid initv4 symbol: {char!r}")
        symbol = decode_map[char]
        if value < 0:
            value = symbol
            continue

        value += symbol * alphabet_base
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


def _apply_script_key_transform(data: bytes, key_bytes: bytes) -> bytes:
    """Apply the initv4 XOR/index mixing to *data* using *key_bytes*.

    The bootstrapper feeds the decoded blob through a simple XOR pipeline: the
    payload bytes are XORed with the repeating script key and then XORed with
    the current byte index.  This helper mirrors that routine so both the
    handler and tests can share the logic.
    """

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


@dataclass
class _DecodeAttempt:
    method: str
    alphabet_source: str
    data: bytes
    size: int
    score: float

    def as_metadata(self) -> Dict[str, object]:
        return {
            "method": self.method,
            "size": self.size,
            "score": round(float(self.score), 4),
            "alphabet_source": self.alphabet_source,
        }


def _decode_attempts(
    blob: str,
    script_key: str,
    *,
    alphabet: Optional[str] = None,
    alphabet_source: Optional[str] = None,
) -> Tuple[bytes, Dict[str, object]]:
    """Try multiple decode strategies and pick the most plausible result."""

    cleaned = blob.strip()
    if not cleaned:
        return b"", {"decode_method": "empty", "decode_attempts": []}

    key_bytes = script_key.encode("utf-8") if script_key else b""
    attempts: List[_DecodeAttempt] = []
    errors: Dict[str, str] = {}

    def _record(
        method: str,
        raw: Optional[bytes],
        *,
        alphabet_source: str = "n/a",
    ) -> None:
        if raw is None:
            return
        decoded = _apply_script_key_transform(raw, key_bytes)
        attempts.append(
            _DecodeAttempt(
                method=method,
                alphabet_source=alphabet_source,
                data=decoded,
                size=len(decoded),
                score=_score_decoded_bytes(decoded),
            )
        )

    prefer_base91 = any(ch not in _BASE64_CHARSET for ch in cleaned) if cleaned else False
    allow_base91 = len(cleaned) >= 2
    forced_base91 = allow_base91 and not prefer_base91
    if allow_base91:
        alphabet_candidates: List[Tuple[str, Optional[str]]] = []
        if alphabet:
            label = alphabet_source or "bootstrapper"
            alphabet_candidates.append((label, alphabet))
        alphabet_candidates.append(("default", None))

        seen_alphabets: Set[str] = set()
        for source, candidate in alphabet_candidates:
            actual_alphabet, _, _ = _prepare_alphabet(candidate)
            if actual_alphabet in seen_alphabets:
                continue
            seen_alphabets.add(actual_alphabet)
            try:
                decoded = _decode_base91(cleaned, alphabet=candidate)
            except ValueError as exc:
                errors[f"base91[{source}]"] = str(exc)
            else:
                _record("base91", decoded, alphabet_source=source)

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

    if forced_base91:
        for entry in attempts:
            if entry.method == "base91":
                entry.score = max(0.0, entry.score - 0.05)

    attempts.sort(key=lambda entry: (entry.score, entry.size), reverse=True)
    best = attempts[0]
    base91_present = any(entry.method == "base91" for entry in attempts)

    metadata: Dict[str, object] = {
        "decode_method": best.method,
        "decode_score": round(float(best.score), 4),
        "decode_attempts": [entry.as_metadata() for entry in attempts],
        "script_key_length": len(key_bytes),
        "index_xor": True,
        "alphabet_source": best.alphabet_source,
    }
    if best.score < 0.25:
        metadata["low_confidence"] = True
    if base91_present and best.method != "base91":
        metadata["fallback_used"] = True
    if forced_base91 and base91_present:
        metadata.setdefault("base91_forced", True)
    if errors:
        metadata["decode_errors"] = errors

    return best.data, metadata


def decode_blob(
    encoded_blob: str,
    script_key: str,
    *,
    alphabet: Optional[str] = None,
) -> bytes:
    """Decode an ``initv4`` payload using base91 + script-key/index XOR."""

    data, _ = decode_blob_with_metadata(
        encoded_blob,
        script_key,
        alphabet=alphabet,
    )
    return data


def looks_like_vm_bytecode(
    data: bytes,
    opcode_map: Optional[Mapping[int, object]] = None,
) -> bool:
    """Return ``True`` when *data* resembles initv4 VM bytecode."""

    if not data or len(data) < 16:
        return False

    probe_len = min(200, len(data))

    if opcode_map:
        hits = 0
        for byte in data[:probe_len]:
            if isinstance(byte, int) and byte in opcode_map:
                hits += 1
        return hits / probe_len >= 0.5

    non_printable = sum(1 for byte in data[:probe_len] if byte < 32 or byte > 126)
    threshold = int(0.3 * probe_len)
    return non_printable >= threshold


def decode_blob_with_metadata(
    encoded_blob: str,
    script_key: str,
    *,
    alphabet: Optional[str] = None,
    alphabet_source: Optional[str] = None,
) -> Tuple[bytes, Dict[str, object]]:
    """Decode *encoded_blob* and return both data and decode metadata."""

    return _decode_attempts(
        encoded_blob,
        script_key,
        alphabet=alphabet,
        alphabet_source=alphabet_source,
    )


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


def _locate_payload_chunks(text: str, *, start: int) -> List[Tuple[str, int, int]]:
    primary: List[Tuple[str, int, int]] = []
    secondary: List[Tuple[str, int, int]] = []
    for match in _CHUNK_STRING_RE.finditer(text):
        chunk = match.group(2)
        begin, end = match.span(2)
        if begin >= start:
            primary.append((chunk, begin, end))
        else:
            secondary.append((chunk, begin, end))
    if primary or secondary:
        return primary + secondary

    best: Tuple[str, int, int] | None = None
    for match in _HIGH_ENTROPY_RE.finditer(text, pos=start):
        blob = match.group(0)
        span = match.span(0)
        if best is None or len(blob) > len(best[0]):
            best = (blob, span[0], span[1])
    if best:
        return [best]

    if start:
        for match in _HIGH_ENTROPY_RE.finditer(text):
            blob = match.group(0)
            span = match.span(0)
            if best is None or len(blob) > len(best[0]):
                best = (blob, span[0], span[1])
    return [best] if best else []


_BASE_OPCODE_TABLE: Dict[int, OpSpec] = dict(LuraphV142JSON().opcode_table())

_ADDITIONAL_SPECS: Tuple[OpSpec, ...] = (
    OpSpec("NOT", ("a", "b")),
    OpSpec("LEN", ("a", "b")),
    OpSpec("CONCAT", ("a", "b", "c")),
    OpSpec("TFORLOOP", ("a", "offset", "c")),
)

_CANONICAL_OPCODE_SPECS: Dict[str, OpSpec] = {}
_existing = {spec.mnemonic.upper() for spec in _BASE_OPCODE_TABLE.values()}
_next_opcode = max(_BASE_OPCODE_TABLE.keys(), default=0) + 1
for extra in _ADDITIONAL_SPECS:
    name = extra.mnemonic.upper()
    if name in _existing:
        continue
    _BASE_OPCODE_TABLE[_next_opcode] = extra
    _existing.add(name)
    _next_opcode += 1

_CANONICAL_OPCODE_SPECS.update(
    {spec.mnemonic.upper(): spec for spec in _BASE_OPCODE_TABLE.values()}
)


class LuraphV1441(VersionHandler):
    """Handle ``initv4`` bootstrap loaders used by Luraph v14.4.1.

    The bootstrap embeds a JSON object (when ``write_json`` is enabled) or a
    plain base64 blob containing the VM bytecode and constant pool.  Regardless
    of the transport, the payload must be XOR-decrypted with the user-visible
    ``script_key`` before it can be lifted.  This handler extracts metadata about
    the key, records the payload format, and returns decrypted bytes to the
    pipeline.
    """

    name = "luraph_v14_4_initv4"
    priority = 80

    def __init__(self) -> None:
        self._bootstrapper: InitV4Bootstrap | None = None
        self._bootstrap_meta: Dict[str, object] = {}
        self._alphabet_override: Optional[str] = None
        self._alphabet_override_source: Optional[str] = None
        self._opcode_override: Dict[int, OpSpec] | None = None
        self._debug_bootstrap: bool = False
        self._bootstrap_debug_log: Optional[Path] = None

    def apply_manual_bootstrap_overrides(
        self,
        *,
        alphabet: Optional[str] = None,
        opcode_map: Optional[Mapping[int, str]] = None,
    ) -> None:
        if alphabet:
            cleaned = alphabet.strip()
            if cleaned:
                self._alphabet_override = cleaned
                self._alphabet_override_source = "manual_override"
        if opcode_map:
            table: Dict[int, OpSpec] = {}
            for key, name in opcode_map.items():
                try:
                    opcode = int(key)
                except (TypeError, ValueError):
                    continue
                cleaned = str(name).strip().upper()
                if not cleaned:
                    continue
                spec = _CANONICAL_OPCODE_SPECS.get(cleaned)
                if spec is None:
                    spec = OpSpec(cleaned, ())
                table[opcode] = spec
            if table:
                self._opcode_override = dict(sorted(table.items()))

    def matches(self, text: str) -> bool:
        return (
            _HIGH_ENTROPY_RE.search(text) is not None
            and _INIT_STUB_RE.search(text) is not None
            and _SCRIPT_KEY_ASSIGN_RE.search(text) is not None
        )

    # ------------------------------------------------------------------
    def set_bootstrap_debug_options(self, *, enabled: bool, log_path: Path | None = None) -> None:
        self._debug_bootstrap = bool(enabled)
        self._bootstrap_debug_log = Path(log_path) if log_path else None

    def set_bootstrapper(self, path: Path | str) -> Dict[str, object]:
        bootstrap = InitV4Bootstrap.load(path)
        self._bootstrapper = bootstrap
        alphabet, mapping, table, summary = bootstrap.extract_metadata(
            _BASE_OPCODE_TABLE,
            debug=self._debug_bootstrap,
            debug_log=self._bootstrap_debug_log,
        )

        ctx = SimpleNamespace(
            script_key=None,
            bootstrapper_path=bootstrap.path,
            debug_bootstrap=self._debug_bootstrap,
            bootstrap_debug_log=self._bootstrap_debug_log,
        )
        decoder = InitV4Decoder(ctx, bootstrap=bootstrap)

        if decoder.alphabet:
            alphabet = decoder.alphabet
        self._alphabet_override = alphabet
        if alphabet:
            self._alphabet_override_source = (
                "manual_override"
                if getattr(decoder, "_manual_override_alphabet", False)
                else "bootstrapper"
            )

        override_table: Dict[int, OpSpec] = dict(table)
        if decoder.has_custom_opcodes() and decoder.opcode_map:
            for opcode, name in decoder.opcode_map.items():
                spec = _CANONICAL_OPCODE_SPECS.get(name.upper())
                if spec is not None:
                    override_table[opcode] = spec
        self._opcode_override = dict(sorted(override_table.items()))

        meta: Dict[str, object] = dict(summary)
        meta.setdefault("path", str(bootstrap.path))
        if alphabet:
            meta.setdefault("alphabet_length", len(alphabet))

        if decoder.has_custom_opcodes():
            extracted_map = decoder.opcode_map or {}
            meta.setdefault("opcode_map_entries", len(extracted_map))
            meta.setdefault("opcode_map", dict(sorted(extracted_map.items())))
        elif mapping:
            meta.setdefault("opcode_map_entries", len(mapping))

        for key, value in bootstrap.iter_metadata():
            meta.setdefault(key, value)

        self._bootstrap_meta = meta
        return dict(meta)

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

        chunk_entries = _locate_payload_chunks(text, start=start)
        if not chunk_entries:
            return None

        chunks = [entry[0] for entry in chunk_entries]
        begin = chunk_entries[0][1]
        end = chunk_entries[-1][2]
        meta = dict(base_meta)
        meta.setdefault("format", "base64")
        if chunks:
            meta["_chunks"] = list(chunks)
            meta["chunk_count"] = len(chunks)
            meta["chunks"] = [
                {"offset": entry[1], "end": entry[2], "length": len(chunks[index])}
                for index, entry in enumerate(chunk_entries)
            ]
        payload_text = chunks[0] if chunks else ""
        return PayloadInfo(payload_text, begin, end, metadata=meta)

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
                "Luraph initv4 (v14.4.1) payloads require a script key. Supply one via --script-key or the LURAPH_SCRIPT_KEY environment variable."
            )

        alphabet = self._alphabet_override
        if alphabet:
            metadata.setdefault("alphabet_length", len(alphabet))

        chunk_texts_raw = metadata.pop("_chunks", None)
        chunk_texts: List[str] | None = None
        if isinstance(chunk_texts_raw, (list, tuple)):
            filtered: List[str] = []
            for entry in chunk_texts_raw:
                if isinstance(entry, str) and entry:
                    filtered.append(entry)
            if filtered:
                chunk_texts = filtered

        if chunk_texts:
            decoded_parts: List[bytes] = []
            chunk_methods: List[str] = []
            chunk_alphabets: List[str] = []
            chunk_attempts: List[Dict[str, object]] = []
            chunk_meta_details: List[Dict[str, object]] = []
            chunk_decoded_bytes: List[int] = []
            chunk_encoded_lengths = [len(chunk) for chunk in chunk_texts]

            for index, chunk in enumerate(chunk_texts):
                part, part_meta = decode_blob_with_metadata(
                    chunk,
                    script_key,
                    alphabet=alphabet,
                    alphabet_source=self._alphabet_override_source,
                )
                decoded_parts.append(part)
                chunk_decoded_bytes.append(len(part))
                chunk_methods.append(str(part_meta.get("decode_method", "")))
                chunk_alphabets.append(str(part_meta.get("alphabet_source", "")))

                attempts = part_meta.get("decode_attempts", [])
                if isinstance(attempts, list):
                    for entry in attempts:
                        attempt_entry = dict(entry)
                        attempt_entry["chunk_index"] = index
                        chunk_attempts.append(attempt_entry)

                sanitised = {
                    key: value
                    for key, value in part_meta.items()
                    if key not in {"decode_attempts"}
                }
                sanitised["chunk_index"] = index
                chunk_meta_details.append(sanitised)

            raw = b"".join(decoded_parts)

            method_set = {method for method in chunk_methods if method}
            if method_set:
                if len(method_set) == 1:
                    decode_method = next(iter(method_set))
                else:
                    decode_method = "mixed"
            else:
                decode_method = "unknown"

            alphabet_set = {source for source in chunk_alphabets if source}
            if alphabet_set:
                if len(alphabet_set) == 1:
                    alphabet_source = next(iter(alphabet_set))
                else:
                    alphabet_source = "mixed"
            else:
                alphabet_source = "n/a"

            decode_meta: Dict[str, object] = {
                "decode_method": decode_method,
                "alphabet_source": alphabet_source,
                "chunk_count": len(chunk_texts),
                "chunk_lengths": chunk_encoded_lengths,
                "chunk_decoded_bytes": chunk_decoded_bytes,
                "chunk_methods": chunk_methods,
                "chunk_alphabet_sources": chunk_alphabets,
                "chunk_meta": chunk_meta_details,
                "index_xor": any(
                    bool(meta.get("index_xor")) for meta in chunk_meta_details
                ),
                "script_key_length": len(script_key),
            }
            if chunk_attempts:
                decode_meta["decode_attempts"] = chunk_attempts

            aggregated_errors: List[Dict[str, object]] = []
            for meta in chunk_meta_details:
                errors = meta.get("decode_errors")
                if errors:
                    aggregated_errors.append(
                        {
                            "chunk_index": meta.get("chunk_index"),
                            "errors": errors,
                        }
                    )
            if aggregated_errors:
                decode_meta["decode_errors"] = aggregated_errors

            for flag in ("low_confidence", "fallback_used", "base91_forced"):
                if any(meta.get(flag) for meta in chunk_meta_details):
                    decode_meta[flag] = True

        else:
            raw, decode_meta = decode_blob_with_metadata(
                payload.text,
                script_key,
                alphabet=alphabet,
                alphabet_source=self._alphabet_override_source,
            )
        metadata["decoded_bytes"] = len(raw)
        metadata.update({key: value for key, value in decode_meta.items() if key != "decode_attempts"})
        if decode_meta.get("decode_attempts"):
            metadata["decode_attempts"] = decode_meta["decode_attempts"]
        if provider:
            metadata["script_key_provider"] = provider
        metadata.setdefault("format", metadata.get("format", "base64"))
        if self._bootstrap_meta:
            summary = {
                key: value for key, value in self._bootstrap_meta.items() if key != "extraction"
            }
            if summary:
                metadata.setdefault("bootstrapper", dict(summary))
            extraction_meta = self._bootstrap_meta.get("extraction")
            if isinstance(extraction_meta, dict) and extraction_meta:
                metadata.setdefault("bootstrapper_metadata", dict(extraction_meta))

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
        if self._opcode_override:
            return dict(self._opcode_override)
        return dict(_BASE_OPCODE_TABLE)


register_handler(LuraphV1441)


class LuraphV1441Legacy(LuraphV1441):
    """Backward-compatible alias for the legacy ``v14.4.1`` version name."""

    name = "v14.4.1"


register_handler(LuraphV1441Legacy)

HANDLER = LuraphV1441()

__all__ = [
    "LuraphV1441",
    "LuraphV1441Legacy",
    "decode_blob",
    "decode_blob_with_metadata",
    "looks_like_vm_bytecode",
    "HANDLER",
]
