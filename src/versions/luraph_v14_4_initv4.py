"""Helpers for decoding Luraph ``initv4`` payloads.

This module provides two public entry points that the rest of the codebase
expects:

``decode_blob``
    Decode a single base91 blob using the initv4 alphabet and script key
    transformations.

``InitV4Decoder``
    A light-weight helper used by the pipeline and tests to locate payload
    blobs inside bootstrap scripts, apply optional bootstrap metadata and
    expose the opcode map discovered during bootstrap analysis.

The original project shipped only a placeholder skeleton which triggered
import errors during test collection.  The implementation below mirrors the
behaviour of the higher level :mod:`src.versions.luraph_v14_4_1` helpers but is
careful to avoid circular imports.
"""

from __future__ import annotations

import base64
import logging
import re
import string
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

import codecs
import json

from . import OpSpec

from ..vm.opcode_constants import MANDATORY_CONFIDENCE_THRESHOLD
from .initv4 import InitV4Bootstrap
from .luraph_v14_2_json import LuraphV142JSON

LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Alphabet helpers

DEFAULT_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)
_DEFAULT_DECODE: Dict[str, int] = {symbol: index for index, symbol in enumerate(DEFAULT_ALPHABET)}
_DEFAULT_BASE = len(DEFAULT_ALPHABET)

_PRINTABLE = re.escape(DEFAULT_ALPHABET)
_PAYLOAD_RE = re.compile(rf'(["\'])([{_PRINTABLE}]{{32,}})\1')
_HEX_ESCAPE_SEQUENCE_RE = re.compile(r'(?:\\x[0-9A-Fa-f]{2}){16,}')
_HEX_LITERAL_RE = re.compile(r'(["\'])(?:\\x[0-9A-Fa-f]{2}){16,}\1')
_STRING_CHAR_TOKEN_RE = re.compile(r'string\.char', re.IGNORECASE)
_NUMBER_TOKEN_RE = re.compile(r'0x[0-9A-Fa-f]+|\d+')
_NUMERIC_ARRAY_CLEAN_RE = re.compile(r'[\s,;]')
_MIN_PACKED_SEQUENCE = 32
_SCRIPT_KEY_LITERAL_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


def _is_alphabet(candidate: str) -> bool:
    return len(candidate) >= 85 and len(set(candidate)) == len(candidate)


def _prepare_alphabet(override: Optional[str]) -> Tuple[str, Dict[str, int], int]:
    if override and _is_alphabet(override):
        table = {symbol: index for index, symbol in enumerate(override)}
        return override, table, len(override)
    return DEFAULT_ALPHABET, _DEFAULT_DECODE, _DEFAULT_BASE


# ---------------------------------------------------------------------------
# Decoding helpers

def _decode_base91(blob: str, *, alphabet: Optional[str] = None) -> bytes:
    alphabet, table, base = _prepare_alphabet(alphabet)

    value = -1
    buffer = 0
    bits = 0
    output = bytearray()

    for char in blob:
        if char.isspace():
            continue
        if char not in table:
            raise ValueError(f"invalid initv4 symbol: {char!r}")
        symbol = table[char]
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


def _xor_with_key(data: bytes, key_bytes: bytes) -> bytes:
    if not key_bytes:
        return data
    key_len = len(key_bytes)
    return bytes(value ^ key_bytes[index % key_len] for index, value in enumerate(data))


def _xor_with_index(data: bytes) -> bytes:
    if not data:
        return data
    return bytes(value ^ (index & 0xFF) for index, value in enumerate(data))


def decode_blob(
    blob: str,
    alphabet: Optional[str] = None,
    key_bytes: Optional[bytes] = None,
) -> bytes:
    """Decode a single initv4 payload blob.

    ``alphabet`` may be ``None`` (to use the default) or a custom alphabet with
    at least 85 unique printable characters.  ``key_bytes`` may be either a
    ``bytes`` object or ``None``.  The routine mirrors the bootstrapper by first
    decoding the basE91 payload and then applying the script-key XOR followed by
    the index XOR.
    """

    if isinstance(key_bytes, str):  # type: ignore[unreachable]
        key_bytes = key_bytes.encode("utf-8")

    decoded = _decode_base91(blob, alphabet=alphabet)
    if key_bytes:
        decoded = _xor_with_key(decoded, key_bytes)
    return _xor_with_index(decoded)


# ---------------------------------------------------------------------------
# Opcode table helpers

_BASE_OPCODE_SPECS = LuraphV142JSON().opcode_table()
_DEFAULT_OPCODE_MAP: Dict[int, str] = {
    opcode: spec.mnemonic for opcode, spec in _BASE_OPCODE_SPECS.items()
}
_DEFAULT_OPCODE_MAP.update(
    {
        0x00: "NOP",
        0x11: "LOADKX",
        0x16: "FORITER",
        0x17: "TFORCALL",
        0x22: "CONCAT",
        0x2B: "TFORLOOP",
        0x2C: "SETLIST",
        0x2D: "CLOSE",
        0x2E: "EXTRAARG",
    }
)


def _normalise_opcode_map(mapping: Mapping[Any, Any]) -> Dict[int, str]:
    result: Dict[int, str] = {}
    for key, value in mapping.items():
        opcode: Optional[int] = None
        name: Optional[str] = None

        try:
            opcode = int(key, 0) if isinstance(key, str) else int(key)
        except (TypeError, ValueError):
            opcode = None
        else:
            name = str(value).strip()

        if opcode is None:
            try:
                opcode = int(value, 0) if isinstance(value, str) else int(value)
            except (TypeError, ValueError):
                continue
            name = str(key).strip()

        if not name:
            continue
        result[opcode] = name.upper()
    return result


# ---------------------------------------------------------------------------
# Decoder implementation

@dataclass
class InitV4Decoder:
    """Utility wrapper used by the pipeline and tests."""

    ctx: Any
    bootstrap: Optional[InitV4Bootstrap] = None

    def __post_init__(self) -> None:
        self.extracted_script_key: Optional[str] = None
        self._manual_override_alphabet = False
        self._manual_override_opcode_map = False
        self._alphabet: Optional[str] = None
        self._alphabet_source = "default"
        self._opcode_table: Dict[int, str] = dict(_DEFAULT_OPCODE_MAP)
        self.opcode_map: Dict[int, str] = {}
        self._custom_opcodes = False
        self._bootstrap_summary: Dict[str, Any] = {}

        script_key = getattr(self.ctx, "script_key", "") or ""
        if isinstance(script_key, bytes):
            self._script_key_bytes = script_key
        else:
            self._script_key_bytes = str(script_key).encode("utf-8") if script_key else b""

        manual_alphabet = getattr(self.ctx, "manual_alphabet", None)
        if isinstance(manual_alphabet, str) and _is_alphabet(manual_alphabet.strip()):
            self._alphabet = manual_alphabet.strip()
            self._alphabet_source = "manual_override"
            self._manual_override_alphabet = True

        manual_opcode_map = getattr(self.ctx, "manual_opcode_map", None)
        if isinstance(manual_opcode_map, Mapping):
            parsed = _normalise_opcode_map(manual_opcode_map)
            if parsed:
                self.opcode_map = dict(sorted(parsed.items()))
                self._opcode_table.update(self.opcode_map)
                self._manual_override_opcode_map = True
                self._custom_opcodes = True

        if self.bootstrap is None:
            bootstrap_path = getattr(self.ctx, "bootstrapper_path", None)
            if bootstrap_path:
                try:
                    self.bootstrap = InitV4Bootstrap.load(bootstrap_path)
                except Exception as exc:  # pragma: no cover - defensive
                    LOG.debug("failed to load bootstrapper %s: %s", bootstrap_path, exc)
        if self.bootstrap is not None:
            self._consume_bootstrap(self.bootstrap)

        if self._alphabet is None:
            self._alphabet = DEFAULT_ALPHABET

        if not self._script_key_bytes and self.extracted_script_key:
            try:
                self._script_key_bytes = self.extracted_script_key.encode("utf-8")
            except Exception:  # pragma: no cover - defensive
                self._script_key_bytes = b""

    # ------------------------------------------------------------------
    @property
    def alphabet(self) -> Optional[str]:
        return self._alphabet

    # ------------------------------------------------------------------
    def has_custom_opcodes(self) -> bool:
        return self._custom_opcodes

    # ------------------------------------------------------------------
    def opcode_table(self) -> Dict[int, str]:
        return dict(self._opcode_table)

    # ------------------------------------------------------------------
    _OPCODE_ASSIGN_RE = re.compile(
        r"\[(0x[0-9A-Fa-f]+|\d+)\]\s*=\s*['\"]([A-Za-z0-9_]+)['\"]"
    )

    def _extract_opcodes(self, text: str) -> Dict[int, str]:
        """Parse ``text`` for ``[index] = 'NAME'`` style entries."""

        mapping: Dict[int, str] = {}
        for match in self._OPCODE_ASSIGN_RE.finditer(text or ""):
            raw_index, name = match.groups()
            try:
                index = int(raw_index, 0)
            except ValueError:
                continue
            mapping[index] = name.upper()
        return mapping

    # ------------------------------------------------------------------
    def locate_payload(self, text: str) -> List[str]:
        if not text:
            return []

        candidates: List[Tuple[int, str]] = []
        seen: set[str] = set()

        for match in _PAYLOAD_RE.finditer(text):
            candidates.append((match.start(), match.group(0)))
        for match in _HEX_LITERAL_RE.finditer(text):
            candidates.append((match.start(), match.group(0)))
        for start, literal in _iter_string_char_literals(text):
            candidates.append((start, literal))
        for start, literal in _iter_numeric_array_literals(text):
            candidates.append((start, literal))

        candidates.sort(key=lambda item: item[0])

        payloads: List[str] = []
        for _, literal in candidates:
            if literal not in seen:
                seen.add(literal)
                payloads.append(literal)

        return payloads

    # ------------------------------------------------------------------
    def extract_bytecode(self, literal: str) -> bytes:
        blob = normalise_payload_literal(literal)
        return decode_blob(blob, alphabet=self.alphabet, key_bytes=self._script_key_bytes)

    # ------------------------------------------------------------------
    def _consume_bootstrap(self, bootstrap: InitV4Bootstrap) -> None:
        debug = bool(getattr(self.ctx, "debug_bootstrap", False))
        debug_log = getattr(self.ctx, "bootstrap_debug_log", None)
        try:
            alphabet, mapping, table, summary = bootstrap.extract_metadata(
                _BASE_OPCODE_SPECS,
                debug=debug,
                debug_log=debug_log,
            )
        except Exception as exc:  # pragma: no cover - defensive
            LOG.debug("bootstrap metadata extraction failed: %s", exc)
            return

        summary_dict = dict(summary) if isinstance(summary, Mapping) else {}

        bootstrap_summary: Dict[str, Any] = {}
        bootstrap_path = getattr(bootstrap, "path", None)
        if bootstrap_path:
            bootstrap_summary["path"] = str(bootstrap_path)
        for key in (
            "alphabet_length",
            "opcode_table_entries",
            "opcode_table_trusted",
            "opcode_table_mandatory_missing",
            "opcode_map_entries",
            "constant_entries",
        ):
            value = summary_dict.get(key)
            if value:
                bootstrap_summary[key] = value
        self._bootstrap_summary = bootstrap_summary

        extraction = summary_dict.get("extraction") if isinstance(summary_dict, Mapping) else {}
        meta: Dict[str, Any] = {}
        if isinstance(extraction, Mapping):
            meta.update(extraction)
        else:
            extraction = {}

        literal_key = self._extract_script_key_literal(bootstrap.text)
        if literal_key:
            self.extracted_script_key = literal_key
            self._bootstrap_summary.setdefault("script_key_literal", literal_key)
            self._bootstrap_summary.setdefault("script_key_length", len(literal_key))
            meta.setdefault("script_key_literal", literal_key)
            meta.setdefault("script_key_length", len(literal_key))
            meta.setdefault("script_key_source", "bootstrap")

        if not self._manual_override_alphabet and alphabet and _is_alphabet(alphabet):
            self._alphabet = alphabet
            self._alphabet_source = "bootstrap"
        elif self._alphabet is None:
            self._alphabet = DEFAULT_ALPHABET

        dispatch_info = (
            extraction.get("opcode_dispatch") if isinstance(extraction, Mapping) else {}
        )
        if not isinstance(dispatch_info, Mapping):
            dispatch_info = {}
        dispatch_map = (
            dispatch_info.get("mapping") if isinstance(dispatch_info, Mapping) else {}
        )

        allowed_keys: Optional[set[int]] = None
        opcode_table: Dict[int, str] = {}

        if isinstance(dispatch_map, Mapping) and dispatch_map:
            allowed_keys = set()
            for key, name in dispatch_map.items():
                try:
                    opcode_id = int(key, 0) if isinstance(key, str) else int(key)
                except (TypeError, ValueError):
                    continue
                mnemonic = str(name).strip()
                if not mnemonic:
                    continue
                opcode_table[opcode_id] = mnemonic.upper()
                allowed_keys.add(opcode_id)
            if allowed_keys:
                self._custom_opcodes = True

        bootstrap_opcodes: Dict[int, str] = {}
        if isinstance(table, Mapping):
            for opcode, spec in table.items():
                if not isinstance(spec, OpSpec):
                    continue
                bootstrap_opcodes[opcode] = spec.mnemonic.upper()

        opcode_map = _normalise_opcode_map(mapping)
        if opcode_map:
            self.opcode_map = dict(sorted(opcode_map.items()))
            self._custom_opcodes = True
        elif not self._manual_override_opcode_map:
            self.opcode_map = {}

        if opcode_map:
            for opcode_id, mnemonic in opcode_map.items():
                if allowed_keys is not None and opcode_id not in allowed_keys:
                    continue
                opcode_table[opcode_id] = mnemonic.upper()
        elif bootstrap_opcodes:
            for opcode_id, mnemonic in bootstrap_opcodes.items():
                if allowed_keys is not None and opcode_id not in allowed_keys:
                    continue
                opcode_table.setdefault(opcode_id, mnemonic)

        if not opcode_table:
            for opcode_id, mnemonic in _DEFAULT_OPCODE_MAP.items():
                opcode_table[opcode_id] = mnemonic
        else:
            if allowed_keys is not None:
                for opcode_id in allowed_keys:
                    if opcode_id not in opcode_table and opcode_id in _DEFAULT_OPCODE_MAP:
                        opcode_table[opcode_id] = _DEFAULT_OPCODE_MAP[opcode_id]
            else:
                existing_names = {name.upper() for name in opcode_table.values()}
                if "CONCAT" not in existing_names:
                    fallback = _DEFAULT_OPCODE_MAP.get(0x22) or "CONCAT"
                    opcode_table[0x22] = fallback
                    existing_names.add("CONCAT")
                if "CALL" not in existing_names:
                    opcode_table.setdefault(0x1C, "CALL")
                if "RETURN" not in existing_names:
                    opcode_table.setdefault(0x1D, "RETURN")

        self._opcode_table = dict(sorted(opcode_table.items()))

        opcode_table_meta = (
            extraction.get("opcode_table") if isinstance(extraction, Mapping) else {}
        )
        missing_ops = []
        if isinstance(opcode_table_meta, Mapping):
            raw_missing = opcode_table_meta.get("mandatory_missing")
            if isinstance(raw_missing, Iterable):
                missing_ops = sorted({str(name).upper() for name in raw_missing if name})
            threshold_value = opcode_table_meta.get("mandatory_threshold")
        else:
            threshold_value = None
        if self._alphabet:
            meta.setdefault("alphabet_length", len(self._alphabet))
            meta.setdefault("alphabet_source", self._alphabet_source)
        if self.opcode_map:
            meta.setdefault("opcode_map_count", len(self.opcode_map))
            meta.setdefault("opcode_map", dict(self.opcode_map))
        if (
            self._alphabet is DEFAULT_ALPHABET
            and self.bootstrap is not None
            and "alphabet_length" not in meta
        ):
            fallback_alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
            meta.setdefault("alphabet_length", len(fallback_alphabet))
            meta.setdefault("alphabet_preview", fallback_alphabet[:32] + ("..." if len(fallback_alphabet) > 32 else ""))
            meta.setdefault("alphabet_source", "bootstrap")
            meta.setdefault("alphabet_fallback", fallback_alphabet)
        if meta:
            existing = getattr(self.ctx, "bootstrapper_metadata", None)
            if isinstance(existing, Mapping):
                combined = dict(existing)
                combined.update(meta)
                setattr(self.ctx, "bootstrapper_metadata", combined)
            else:
                setattr(self.ctx, "bootstrapper_metadata", dict(meta))

        if summary.get("has_metatable_flow"):
            vm_meta = getattr(self.ctx, "vm_metadata", None)
            if isinstance(vm_meta, dict):
                lifter_meta = vm_meta.setdefault("lifter", {})
                if isinstance(lifter_meta, dict):
                    lifter_meta.setdefault("has_metatable_flow", True)
                    handlers = summary.get("metatable_handlers")
                    if isinstance(handlers, Mapping):
                        lifter_meta.setdefault("metatable_handlers", dict(handlers))
                    setmeta_calls = summary.get("setmetatable_calls")
                    if isinstance(setmeta_calls, int):
                        lifter_meta.setdefault("setmetatable_calls", setmeta_calls)

        if missing_ops:
            try:
                meta.setdefault("mandatory_missing_ops", missing_ops)
            except Exception:  # pragma: no cover - defensive
                pass
            vm_meta = getattr(self.ctx, "vm_metadata", None)
            if isinstance(vm_meta, dict):
                errors_bucket = vm_meta.setdefault("errors", [])
                for name in missing_ops:
                    message = f"missing/low-trust: {name}"
                    if message not in errors_bucket:
                        errors_bucket.append(message)
                if threshold_value is None:
                    threshold_value = MANDATORY_CONFIDENCE_THRESHOLD
                vm_meta.setdefault("mandatory_threshold", threshold_value)

        if literal_key:
            try:
                setattr(self.ctx, "extracted_script_key", literal_key)
            except Exception:  # pragma: no cover - defensive
                pass

    # ------------------------------------------------------------------
    @staticmethod
    def _extract_script_key_literal(text: str) -> Optional[str]:
        if not text:
            return None
        match = _SCRIPT_KEY_LITERAL_RE.search(text)
        if not match:
            return None
        candidate = match.group(1).strip()
        return candidate or None


# ---------------------------------------------------------------------------
# Convenience helpers for other modules/tests

def decode_blob_with_metadata(
    blob: str,
    script_key: Optional[str],
    *,
    alphabet: Optional[str] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    key_bytes = script_key.encode("utf-8") if isinstance(script_key, str) else b""
    if alphabet and not _is_alphabet(alphabet):
        alphabet = None

    attempts: List[Dict[str, Any]] = []
    try:
        data = decode_blob(blob, alphabet=alphabet, key_bytes=key_bytes)
        attempts.append({
            "method": "base91",
            "alphabet_source": "override" if alphabet else "default",
            "decoded": True,
        })
        return data, {
            "decode_method": "base91",
            "alphabet_source": attempts[-1]["alphabet_source"],
            "index_xor": True,
            "attempts": attempts,
        }
    except Exception as exc:
        attempts.append({"method": "base91", "error": str(exc)})

    try:
        raw = base64.b64decode(blob, validate=True)
    except Exception as exc:
        attempts.append({"method": "base64", "error": str(exc)})
        raise ValueError("failed to decode initv4 blob") from exc

    data = _xor_with_index(_xor_with_key(raw, key_bytes))
    attempts.append({"method": "base64", "decoded": True})
    return data, {
        "decode_method": "base64",
        "alphabet_source": "base64",
        "index_xor": True,
        "attempts": attempts,
    }


# ---------------------------------------------------------------------------
# Payload helpers


def _find_balanced(text: str, start: int, open_char: str, close_char: str) -> int:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _parse_numeric_sequence(body: str) -> Optional[List[int]]:
    tokens = _NUMBER_TOKEN_RE.findall(body)
    if len(tokens) < _MIN_PACKED_SEQUENCE:
        return None

    scrubbed = _NUMBER_TOKEN_RE.sub('', body)
    scrubbed = _NUMERIC_ARRAY_CLEAN_RE.sub('', scrubbed)
    if scrubbed.strip():
        return None

    values: List[int] = []
    for token in tokens:
        try:
            number = int(token, 0)
        except ValueError:
            return None
        values.append(number & 0xFF)
    return values


def _decode_numeric_values(values: Sequence[int]) -> str:
    return bytes(int(value) & 0xFF for value in values).decode('latin-1')


def _iter_string_char_literals(text: str) -> Iterator[Tuple[int, str]]:
    lower = text.lower()
    search = 0
    while True:
        match = _STRING_CHAR_TOKEN_RE.search(lower, search)
        if not match:
            break
        call_start = match.start()
        paren_index = lower.find('(', match.end())
        if paren_index == -1:
            break
        close_index = _find_balanced(text, paren_index, '(', ')')
        if close_index == -1:
            break
        body = text[paren_index + 1 : close_index]
        values = _parse_numeric_sequence(body)
        if values:
            yield call_start, text[call_start : close_index + 1]
        search = close_index + 1


def _iter_numeric_array_literals(text: str) -> Iterator[Tuple[int, str]]:
    lower = text
    search = 0
    while True:
        brace_index = lower.find('{', search)
        if brace_index == -1:
            break
        close_index = _find_balanced(lower, brace_index, '{', '}')
        if close_index == -1:
            break
        body = lower[brace_index + 1 : close_index]
        values = _parse_numeric_sequence(body)
        if values:
            yield brace_index, text[brace_index : close_index + 1]
        search = close_index + 1


def _decode_hex_escapes(value: str) -> Optional[str]:
    if not _HEX_ESCAPE_SEQUENCE_RE.search(value):
        return None
    try:
        decoded = codecs.decode(value, 'unicode_escape')
    except Exception:  # pragma: no cover - defensive
        return None
    return decoded


def normalise_payload_literal(literal: str) -> str:
    stripped = literal.strip()
    if not stripped:
        return stripped

    if stripped.startswith('"') and stripped.endswith('"'):
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError:
            inner = stripped[1:-1]
            hex_decoded = _decode_hex_escapes(inner)
            return hex_decoded if hex_decoded is not None else inner
        else:
            candidate = _decode_hex_escapes(decoded)
            return candidate if candidate is not None else decoded

    if stripped.startswith("'") and stripped.endswith("'"):
        inner = stripped[1:-1]
        decoded = _decode_hex_escapes(inner)
        return decoded if decoded is not None else inner

    hex_decoded = _decode_hex_escapes(stripped)
    if hex_decoded is not None:
        return hex_decoded

    char_match = _STRING_CHAR_TOKEN_RE.match(stripped)
    if char_match:
        open_index = stripped.find('(', char_match.end())
        if open_index != -1:
            close_index = _find_balanced(stripped, open_index, '(', ')')
            if close_index != -1:
                values = _parse_numeric_sequence(stripped[open_index + 1 : close_index])
                if values:
                    return _decode_numeric_values(values)

    if stripped.startswith('{') and stripped.endswith('}'):
        values = _parse_numeric_sequence(stripped[1:-1])
        if values:
            return _decode_numeric_values(values)

    return stripped


__all__ = [
    "DEFAULT_ALPHABET",
    "InitV4Decoder",
    "decode_blob",
    "decode_blob_with_metadata",
    "normalise_payload_literal",
]
