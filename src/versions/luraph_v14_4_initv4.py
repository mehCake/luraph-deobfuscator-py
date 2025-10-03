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
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

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
        try:
            opcode = int(key, 0) if isinstance(key, str) else int(key)
        except (TypeError, ValueError):
            continue
        name = str(value).strip()
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
        return [match.group(0) for match in _PAYLOAD_RE.finditer(text)]

    # ------------------------------------------------------------------
    def extract_bytecode(self, literal: str) -> bytes:
        stripped = literal.strip()
        if len(stripped) >= 2 and stripped[0] in {'"', "'"} and stripped[0] == stripped[-1]:
            blob = stripped[1:-1]
        else:
            blob = stripped
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

        self._bootstrap_summary = dict(summary)

        if not self._manual_override_alphabet and alphabet:
            self._alphabet = alphabet
            self._alphabet_source = "bootstrapper"

        table_map = {opcode: spec.mnemonic for opcode, spec in table.items()}
        if table_map:
            self._opcode_table.update(table_map)

        opcode_map = _normalise_opcode_map(mapping)
        if opcode_map:
            self.opcode_map = dict(sorted(opcode_map.items()))
            self._opcode_table.update(self.opcode_map)
            self._custom_opcodes = True

        # Ensure canonical operations remain present even if the bootstrap
        # emits a reduced or reordered table.  Some stripped bootstrappers drop
        # rarely used opcodes (such as ``CONCAT``) from the dispatch metadata;
        # the pipeline relies on their presence when rebuilding bytecode, so we
        # re-introduce the defaults when necessary.
        existing_names = {name.upper() for name in self._opcode_table.values()}
        if "CONCAT" not in existing_names:
            fallback = _DEFAULT_OPCODE_MAP.get(0x22) or "CONCAT"
            self._opcode_table[0x22] = fallback
            existing_names.add("CONCAT")
        if "CALL" not in existing_names:
            self._opcode_table.setdefault(0x1C, "CALL")
        if "RETURN" not in existing_names:
            self._opcode_table.setdefault(0x1D, "RETURN")

        extraction = summary.get("extraction") if isinstance(summary, dict) else {}
        meta: Dict[str, Any] = {}
        if isinstance(extraction, Mapping):
            meta.update(extraction)
        if self._alphabet:
            meta.setdefault("alphabet_length", len(self._alphabet))
            meta.setdefault("alphabet_source", self._alphabet_source)
        if self.opcode_map:
            meta.setdefault("opcode_map_count", len(self.opcode_map))
            meta.setdefault("opcode_map", dict(self.opcode_map))
        if meta:
            existing = getattr(self.ctx, "bootstrapper_metadata", None)
            if isinstance(existing, Mapping):
                combined = dict(existing)
                combined.update(meta)
                setattr(self.ctx, "bootstrapper_metadata", combined)
            else:
                setattr(self.ctx, "bootstrapper_metadata", dict(meta))


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


__all__ = ["DEFAULT_ALPHABET", "InitV4Decoder", "decode_blob", "decode_blob_with_metadata"]
