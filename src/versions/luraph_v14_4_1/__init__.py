"""Compatibility-focused helpers for the Luraph v14.4.1 (``initv4``) bootstrap."""

from __future__ import annotations

import base64
import logging
import os
import re
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .. import OpSpec, PayloadInfo, VersionHandler, register_handler
from ..luraph_v14_4_initv4 import (
    DEFAULT_ALPHABET,
    _decode_base91,
    _prepare_alphabet,
    _xor_with_index,
    _xor_with_key,
    InitV4Decoder,
    normalise_payload_literal,
)
from ..initv4 import InitV4Bootstrap

LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Opcode table compatibility
# ---------------------------------------------------------------------------

_LUA51_BASE_TABLE: Dict[int, str] = {
    0x00: "MOVE",
    0x01: "LOADK",
    0x02: "LOADBOOL",
    0x03: "LOADNIL",
    0x04: "GETUPVAL",
    0x05: "GETGLOBAL",
    0x06: "GETTABLE",
    0x07: "SETGLOBAL",
    0x08: "SETUPVAL",
    0x09: "SETTABLE",
    0x0A: "NEWTABLE",
    0x0B: "SELF",
    0x0C: "ADD",
    0x0D: "SUB",
    0x0E: "MUL",
    0x0F: "DIV",
    0x10: "MOD",
    0x11: "POW",
    0x12: "UNM",
    0x13: "NOT",
    0x14: "LEN",
    0x15: "CONCAT",
    0x16: "JMP",
    0x17: "EQ",
    0x18: "LT",
    0x19: "LE",
    0x1A: "TEST",
    0x1B: "TESTSET",
    0x1C: "CALL",
    0x1D: "TAILCALL",
    0x1E: "RETURN",
    0x1F: "FORLOOP",
    0x20: "FORPREP",
    0x21: "TFORLOOP",
    0x22: "SETLIST",
    0x23: "CLOSE",
    0x24: "CLOSURE",
    0x25: "VARARG",
}

# Historical alias required by the legacy CLI/tests.
_BASE_OPCODE_TABLE: Dict[int, OpSpec] = {
    opcode: OpSpec(mnemonic=name) for opcode, name in _LUA51_BASE_TABLE.items()
}
_INITV4_ALPHABET = DEFAULT_ALPHABET

_SCRIPT_KEY_LITERAL_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_PAYLOAD_ASSIGN_RE = re.compile(r"local\s+payload\s*=\s*(.+)")
_CHUNK_ASSIGN_RE = re.compile(
    r"local\s+(chunk_(\d+))\s*=\s*([\s\S]*?)(?:\n|$)",
    re.IGNORECASE,
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*")
_OVERRIDE_TOKEN = "_script_key_override"


def _normalise_opcode_names(mapping: Mapping[int, OpSpec]) -> Dict[int, OpSpec]:
    table: Dict[int, OpSpec] = {}
    for opcode, spec in mapping.items():
        if not isinstance(opcode, int):
            continue
        name = spec.mnemonic if isinstance(spec, OpSpec) else str(spec)
        if not name:
            continue
        table[opcode] = spec if isinstance(spec, OpSpec) else OpSpec(str(name))
    return table or dict(_BASE_OPCODE_TABLE)


def decode_blob(
    blob: str,
    script_key: str | bytes | None = None,
    *,
    alphabet: Optional[str] = None,
) -> bytes:
    data, _ = decode_blob_with_metadata(blob, script_key, alphabet=alphabet)
    return data


def decode_blob_with_metadata(
    blob: str,
    script_key: str | bytes | None,
    *,
    alphabet: Optional[str] = None,
) -> tuple[bytes, Dict[str, Any]]:
    cleaned = "".join(char for char in (blob or "") if not char.isspace())
    key_bytes = b""
    if isinstance(script_key, bytes):
        key_bytes = script_key
    elif isinstance(script_key, str):
        key_bytes = script_key.encode("utf-8")

    alphabet_value, _, _ = _prepare_alphabet(alphabet)
    alphabet_source = (
        "bootstrap" if alphabet and alphabet_value != DEFAULT_ALPHABET else "heuristic"
    )
    attempts: List[Dict[str, Any]] = []

    try:
        encoded = _decode_base91(cleaned, alphabet=alphabet_value)
        round_trip = _encode_base91(encoded, alphabet_value)
        if round_trip != cleaned:
            raise ValueError("base91 round-trip mismatch")
    except Exception as exc:
        attempts.append(
            {
                "method": "base91",
                "alphabet_source": alphabet_source,
                "error": str(exc),
            }
        )
    else:
        data = _xor_with_index(_xor_with_key(encoded, key_bytes))
        attempts.append(
            {
                "method": "base91",
                "alphabet_source": alphabet_source,
                "decoded": True,
            }
        )
        return data, {
            "decode_method": "base91",
            "alphabet_source": alphabet_source,
            "index_xor": True,
            "attempts": attempts,
            "decode_attempts": attempts,
        }

    if alphabet and alphabet_value != DEFAULT_ALPHABET:
        try:
            encoded = _decode_base91(cleaned, alphabet=DEFAULT_ALPHABET)
            round_trip = _encode_base91(encoded, DEFAULT_ALPHABET)
            if round_trip != cleaned:
                raise ValueError("base91 round-trip mismatch")
        except Exception as exc:
            attempts.append(
                {
                    "method": "base91",
                    "alphabet_source": "heuristic",
                    "error": str(exc),
                }
            )
        else:
            data = _xor_with_index(_xor_with_key(encoded, key_bytes))
            attempts.append(
                {
                    "method": "base91",
                    "alphabet_source": "heuristic",
                    "decoded": True,
                }
            )
            return data, {
                "decode_method": "base91",
                "alphabet_source": "heuristic",
                "index_xor": True,
                "attempts": attempts,
                "decode_attempts": attempts,
            }

    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except Exception as exc:
        attempts.append({"method": "base64", "error": str(exc)})
    else:
        data = _xor_with_index(_xor_with_key(decoded, key_bytes))
        attempts.append({"method": "base64", "decoded": True})
        return data, {
            "decode_method": "base64",
            "alphabet_source": "base64",
            "index_xor": True,
            "attempts": attempts,
            "decode_attempts": attempts,
        }

    try:
        decoded = base64.b64decode(cleaned, validate=False)
    except Exception as exc:
        attempts.append({"method": "base64-relaxed", "error": str(exc)})
        raise ValueError("failed to decode initv4 blob") from exc
    else:
        data = _xor_with_index(_xor_with_key(decoded, key_bytes))
        attempts.append({"method": "base64-relaxed", "decoded": True})
        return data, {
            "decode_method": "base64-relaxed",
            "alphabet_source": "base64",
            "index_xor": True,
            "attempts": attempts,
            "decode_attempts": attempts,
        }


def _encode_base91(data: bytes, alphabet: Optional[str] = None) -> str:
    """Encode ``data`` using the initv4 basE91 alphabet."""

    alphabet = alphabet or DEFAULT_ALPHABET
    if not data:
        return ""

    alphabet, _table, base = _prepare_alphabet(alphabet)
    buffer = 0
    bits = 0
    output: list[str] = []

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
            output.append(alphabet[value % base])
            output.append(alphabet[value // base])

    if bits:
        output.append(alphabet[buffer % base])
        if bits > 7 or buffer // base:
            output.append(alphabet[buffer // base])

    return "".join(output)


def _apply_script_key_transform(data: bytes, key_bytes: bytes) -> bytes:
    """Mirror the bootstrapper's script-key/index XOR pipeline."""

    if isinstance(key_bytes, str):  # pragma: no cover - defensive
        key_bytes = key_bytes.encode("utf-8")
    transformed = _xor_with_key(data, key_bytes or b"")
    return _xor_with_index(transformed)


# ---------------------------------------------------------------------------
# Version handler implementation
# ---------------------------------------------------------------------------


class InitV4_2Handler(VersionHandler):
    """Handler providing opcode information for initv4 payloads."""

    name = "luraph_v14_4_1"
    priority = 90

    def __init__(self) -> None:
        super().__init__()
        self.bootstrap_metadata: Dict[str, Any] = {}

    @staticmethod
    def version_name() -> str:
        return "luraph_v14_4_1"

    @staticmethod
    def match_banner(src: str) -> bool:
        lowered = src.lower()
        return "initv4" in lowered or "luarmor v4" in lowered

    @classmethod
    def build_opcode_table(cls, bootstrap_metadata: Dict[str, Any]) -> Dict[int, str]:
        table = dict(_LUA51_BASE_TABLE)
        if bootstrap_metadata:
            for key, value in bootstrap_metadata.get("opcode_map", {}).items():
                try:
                    opcode_id = int(key, 0)
                except Exception:
                    try:
                        opcode_id = int(key)
                    except Exception:
                        continue
                table[opcode_id] = str(value)

        if len({opcode for opcode in table}) < 30:
            LOG.warning(
                "initv4 opcode map contains only %d entries; expected full Lua 5.1 coverage",
                len({opcode for opcode in table}),
            )
        return table

    def matches(self, text: str) -> bool:  # pragma: no cover - thin wrapper
        return self.match_banner(text)

    def opcode_table(self) -> Dict[int, OpSpec]:
        mapping = self.build_opcode_table(self.bootstrap_metadata)
        return {opcode: OpSpec(mnemonic=name) for opcode, name in mapping.items()}

    def update_bootstrap_metadata(self, metadata: Dict[str, Any]) -> None:
        if metadata:
            self.bootstrap_metadata.update(metadata)


register_handler(InitV4_2Handler)
LEGACY_HANDLER = InitV4_2Handler()


class LuraphV1441(VersionHandler):
    """Feature-complete handler for legacy initv4 bootstrappers."""

    name = "luraph_v14_4_initv4"
    priority = 120

    def __init__(self) -> None:
        super().__init__()
        self._script_key: Optional[str] = None
        self._alphabet: Optional[str] = DEFAULT_ALPHABET
        self._alphabet_source = "heuristic"
        self._bootstrapper_path: Optional[Path] = None
        self._bootstrap_summary: Dict[str, Any] = {}
        self._bootstrap_metadata: Dict[str, Any] = {}
        self._opcode_table: Dict[int, OpSpec] = dict(_BASE_OPCODE_TABLE)
        self.allow_lua_run = False

    # ------------------------------------------------------------------
    @property
    def script_key(self) -> Optional[str]:  # pragma: no cover - simple accessor
        return self._script_key

    @script_key.setter
    def script_key(self, value: Optional[str]) -> None:  # pragma: no cover - simple setter
        if isinstance(value, str):
            cleaned = value.strip()
            self._script_key = cleaned or None
        else:
            self._script_key = None

    # ------------------------------------------------------------------
    @staticmethod
    def version_name() -> str:
        return "luraph_v14_4_1"

    # ------------------------------------------------------------------
    def matches(self, text: str) -> bool:
        if not text:
            return False
        lowered = text.lower()
        return "luraph v14.4" in lowered or "initv4" in lowered or "luarmor v4" in lowered

    # ------------------------------------------------------------------
    def _detect_script_key(self, text: str) -> Optional[str]:
        match = _SCRIPT_KEY_LITERAL_RE.search(text)
        if not match:
            return None
        return match.group(1)

    # ------------------------------------------------------------------
    def _chunk_map(self, text: str) -> Dict[int, str]:
        chunks: Dict[int, str] = {}
        for name, index, literal in _CHUNK_ASSIGN_RE.findall(text):
            try:
                chunk_index = int(index)
            except ValueError:
                continue
            literal_value = literal.strip()
            if not literal_value:
                continue
            chunks.setdefault(chunk_index, literal_value)
        return chunks

    # ------------------------------------------------------------------
    def _payload_expression(self, text: str) -> Optional[re.Match[str]]:
        return _PAYLOAD_ASSIGN_RE.search(text)

    # ------------------------------------------------------------------
    def _resolve_chunk_order(
        self, expression: str, chunk_map: Mapping[int, str]
    ) -> Optional[List[str]]:
        identifiers = [token.group(0) for token in _IDENTIFIER_RE.finditer(expression)]
        ordered: List[str] = []
        for token in identifiers:
            if not token.lower().startswith("chunk_"):
                continue
            try:
                index = int(token.split("_")[-1])
            except ValueError:
                continue
            literal = chunk_map.get(index)
            if literal is None:
                continue
            ordered.append(literal)
        if ordered:
            return ordered
        return None

    # ------------------------------------------------------------------
    def locate_payload(self, text: str) -> PayloadInfo | None:
        if not text:
            return None

        metadata: Dict[str, Any] = {}
        literal_script_key = self._detect_script_key(text)
        if literal_script_key:
            metadata["script_key"] = literal_script_key

        chunk_map = self._chunk_map(text)
        payload_match = self._payload_expression(text)

        decoder = InitV4Decoder(SimpleNamespace(script_key=literal_script_key or ""))
        payload_literals = decoder.locate_payload(text)

        payload_literal = payload_literals[0] if payload_literals else None
        if payload_match:
            expr = payload_match.group(1).strip()
            chunk_order = self._resolve_chunk_order(expr, chunk_map)
            if chunk_order:
                metadata["chunk_count"] = len(chunk_order)
                metadata["chunks"] = list(chunk_order)
                metadata["_chunks"] = list(chunk_order)
                payload_literal = chunk_order[0]
        if payload_literal is None and payload_literals:
            payload_literal = payload_literals[0]

        if payload_literal is None:
            return None

        raw_literal = payload_literal
        normalised_literal = normalise_payload_literal(raw_literal)
        start = text.find(raw_literal)
        end = start + len(payload_literal) if start != -1 else len(payload_literal)
        if start == -1:
            start = 0

        metadata.setdefault("_literal", raw_literal)
        metadata.setdefault("alphabet_source", self._alphabet_source)

        return PayloadInfo(text=normalised_literal, start=start, end=end, metadata=metadata)

    # ------------------------------------------------------------------
    def _resolve_script_key(self, payload: PayloadInfo) -> tuple[str, str]:
        metadata = payload.metadata
        override = metadata.get(_OVERRIDE_TOKEN)
        if isinstance(override, str) and override.strip():
            return override.strip(), "override"
        if isinstance(self._script_key, str) and self._script_key.strip():
            return self._script_key.strip(), "handler"
        literal = metadata.get("script_key")
        if isinstance(literal, str) and literal.strip():
            return literal.strip(), "literal"
        env_key = os.environ.get("LURAPH_SCRIPT_KEY", "")
        if env_key.strip():
            return env_key.strip(), "environment"
        raise RuntimeError("script key required to decode initv4 payload")

    # ------------------------------------------------------------------
    def _decode_single_blob(self, blob: str, script_key: str) -> tuple[bytes, Dict[str, Any]]:
        normalised = normalise_payload_literal(blob)
        if self._alphabet_source in {"bootstrap", "manual_override"}:
            alphabet_override = self._alphabet
        else:
            alphabet_override = None
        data, meta = decode_blob_with_metadata(
            normalised,
            script_key,
            alphabet=alphabet_override,
        )
        source = meta.get("alphabet_source")
        if source in {"base64", "base64-relaxed"}:
            pass
        elif self._alphabet_source != "heuristic":
            meta["alphabet_source"] = self._alphabet_source
        elif source in {"default", "override", None}:
            meta["alphabet_source"] = self._alphabet_source
        return data, meta

    # ------------------------------------------------------------------
    def extract_bytecode(self, payload: PayloadInfo) -> bytes:
        script_key, provider = self._resolve_script_key(payload)
        metadata = payload.metadata
        metadata["script_key_provider"] = provider
        metadata.setdefault("script_key", script_key)
        metadata.setdefault("script_key_length", len(script_key))

        if isinstance(metadata.get("chunks"), list) and metadata.get("_chunks"):
            return self._extract_chunked(payload, script_key)

        blob = payload.text
        data, meta = self._decode_single_blob(blob, script_key)
        metadata.update(meta)
        metadata["alphabet_source"] = meta.get("alphabet_source", self._alphabet_source)
        if self._alphabet:
            metadata.setdefault("alphabet_length", len(self._alphabet))
        metadata.pop("_literal", None)
        if self._bootstrap_summary:
            metadata.setdefault("bootstrapper", dict(self._bootstrap_summary))
        if self._bootstrap_metadata:
            extraction = self._bootstrap_metadata.get("extraction") if isinstance(self._bootstrap_metadata, Mapping) else None
            if isinstance(extraction, Mapping):
                metadata.setdefault("bootstrapper_metadata", dict(extraction))
            else:
                metadata.setdefault("bootstrapper_metadata", dict(self._bootstrap_metadata))
        return data

    # ------------------------------------------------------------------
    def _extract_chunked(self, payload: PayloadInfo, script_key: str) -> bytes:
        metadata = payload.metadata
        chunk_literals = list(metadata.get("_chunks", []))
        if not chunk_literals:
            chunk_literals = list(metadata.get("chunks") or [])

        decoded_parts: List[bytes] = []
        chunk_lengths: List[int] = []
        decoded_lengths: List[int] = []
        attempts: List[Dict[str, Any]] = []

        for index, literal in enumerate(chunk_literals):
            data, meta = self._decode_single_blob(literal, script_key)
            decoded_parts.append(data)
            decoded_lengths.append(len(data))
            encoded_length = len(normalise_payload_literal(literal))
            chunk_lengths.append(encoded_length)
            attempt_record = dict(meta)
            attempt_record["chunk_index"] = index
            attempt_record["chunk_length"] = encoded_length
            attempts.append(attempt_record)

        combined = b"".join(decoded_parts)

        metadata["chunk_count"] = len(chunk_literals)
        metadata["chunk_lengths"] = chunk_lengths
        metadata["chunk_decoded_bytes"] = decoded_lengths
        metadata["chunk_success_count"] = len(decoded_parts)
        metadata["chunk_encoded_lengths"] = chunk_lengths
        metadata["decode_attempts"] = attempts
        if attempts:
            first_attempt = attempts[0]
            metadata["decode_method"] = first_attempt.get("decode_method", "base91")
            source = first_attempt.get("alphabet_source")
            if source in {"base64", "base64-relaxed"}:
                pass
            elif self._alphabet_source != "heuristic":
                source = self._alphabet_source
            elif source in {"default", "override", None}:
                source = self._alphabet_source
            metadata["alphabet_source"] = source
            metadata["index_xor"] = first_attempt.get("index_xor", True)
        else:
            metadata.setdefault("decode_method", "base91")
            metadata.setdefault("alphabet_source", self._alphabet_source)
            metadata.setdefault("index_xor", True)
        metadata.pop("_chunks", None)
        if self._alphabet:
            metadata.setdefault("alphabet_length", len(self._alphabet))

        if self._bootstrap_summary:
            metadata.setdefault("bootstrapper", dict(self._bootstrap_summary))
        if self._bootstrap_metadata:
            extraction = self._bootstrap_metadata.get("extraction") if isinstance(self._bootstrap_metadata, Mapping) else None
            if isinstance(extraction, Mapping):
                metadata.setdefault("bootstrapper_metadata", dict(extraction))
            else:
                metadata.setdefault("bootstrapper_metadata", dict(self._bootstrap_metadata))
        metadata.pop("_literal", None)

        return combined

    # ------------------------------------------------------------------
    def set_bootstrapper(self, candidate: Path | str) -> Dict[str, Any]:
        bootstrap = InitV4Bootstrap.load(candidate)
        self._bootstrapper_path = bootstrap.path
        alphabet, mapping, table, summary = bootstrap.extract_metadata(_BASE_OPCODE_TABLE)

        metadata: Dict[str, Any] = {"path": str(bootstrap.path)}

        if alphabet and isinstance(alphabet, str) and len(alphabet) >= 85:
            self._alphabet = alphabet
            self._alphabet_source = "bootstrap"
            metadata["alphabet_length"] = len(alphabet)
        else:
            self._alphabet = DEFAULT_ALPHABET
            self._alphabet_source = "bootstrap"

        if mapping:
            metadata["opcode_map"] = dict(mapping)

        if isinstance(summary, Mapping):
            self._bootstrap_metadata = dict(summary)
            extraction = summary.get("extraction") if isinstance(summary.get("extraction"), Mapping) else {}
            metadata["extraction"] = dict(extraction)
        else:
            self._bootstrap_metadata = {}

        self._bootstrap_summary = metadata.copy()
        self._bootstrap_summary.pop("extraction", None)

        opcode_table: Dict[int, OpSpec] = {}
        use_base_table = isinstance(table, Mapping)
        extraction_info = summary.get("extraction") if isinstance(summary, Mapping) else {}
        dispatch_info = (
            extraction_info.get("opcode_dispatch")
            if isinstance(extraction_info, Mapping)
            else {}
        )
        dispatch_map = (
            dispatch_info.get("mapping") if isinstance(dispatch_info, Mapping) else {}
        )
        if isinstance(dispatch_map, Mapping) and dispatch_map:
            dispatch_table: Dict[int, OpSpec] = {}
            for key, name in dispatch_map.items():
                try:
                    opcode_id = int(key, 0) if isinstance(key, str) else int(key)
                except (TypeError, ValueError):
                    continue
                dispatch_table[opcode_id] = OpSpec(str(name).upper())
            opcode_table.update(dispatch_table)
            use_base_table = False
            allowed_keys = set(dispatch_table.keys())
        elif not opcode_table and use_base_table:
            for opcode, spec in table.items():
                if isinstance(spec, OpSpec):
                    opcode_table.setdefault(opcode, spec)
        elif not opcode_table:
            opcode_table = dict(_BASE_OPCODE_TABLE)
        if mapping:
            normalised_map: Dict[int, str] = {}
            for name, value in mapping.items():
                try:
                    opcode_id = int(value, 0) if isinstance(value, str) else int(value)
                except (TypeError, ValueError):
                    continue
                normalised_map[opcode_id] = str(name).upper()
            for opcode_id, mnemonic in normalised_map.items():
                opcode_table[opcode_id] = OpSpec(mnemonic)
        if not opcode_table and use_base_table:
            for opcode, spec in table.items():
                if isinstance(spec, OpSpec):
                    opcode_table.setdefault(opcode, spec)
        if not opcode_table:
            opcode_table = dict(_BASE_OPCODE_TABLE)
        elif 'allowed_keys' in locals():
            opcode_table = {
                opcode: spec for opcode, spec in opcode_table.items() if opcode in allowed_keys
            }
        self._opcode_table = opcode_table

        return metadata

    # ------------------------------------------------------------------
    def apply_manual_bootstrap_overrides(
        self,
        *,
        alphabet: Optional[str] = None,
        opcode_map: Optional[Mapping[int, str]] = None,
    ) -> None:
        if isinstance(alphabet, str) and len(alphabet) >= 85:
            self._alphabet = alphabet
            self._alphabet_source = "bootstrap"

        if isinstance(opcode_map, Mapping):
            parsed: Dict[int, OpSpec] = {}
            for key, value in opcode_map.items():
                try:
                    opcode = int(key, 0) if isinstance(key, str) else int(key)
                except (TypeError, ValueError):
                    continue
                mnemonic = str(value).strip()
                if not mnemonic:
                    continue
                parsed[opcode] = OpSpec(mnemonic.upper())
            if parsed:
                base = dict(_BASE_OPCODE_TABLE)
                base.update(parsed)
                self._opcode_table = base

    # ------------------------------------------------------------------
    def opcode_table(self) -> Dict[int, OpSpec]:
        return dict(self._opcode_table)

    # ------------------------------------------------------------------
    def const_decoder(self) -> Optional["ConstDecoder"]:
        return None


class LuraphV1441Alias(LuraphV1441):
    name = "v14.4.1"


register_handler(LuraphV1441)
register_handler(LuraphV1441Alias)
HANDLER = LuraphV1441()


def looks_like_vm_bytecode(
    blob: Sequence[int] | bytes,
    *,
    opcode_map: Mapping[int, Any] | None = None,
) -> bool:
    """Heuristic check for decoded VM bytecode buffers."""

    if not blob:
        return False

    data = bytes(blob)
    if len(data) < 16 or len(data) % 4:
        return False

    opcodes = []
    printable = 0
    for index in range(0, len(data), 4):
        chunk = data[index : index + 4]
        if len(chunk) < 4:
            break
        opcodes.append(chunk[0])
        printable += sum(1 for b in chunk if 32 <= b < 127)

    unique_opcodes = {op for op in opcodes}
    if len(unique_opcodes) < 4:
        return False

    if printable > len(data) // 2:
        return False

    probe = opcode_map

    if probe:
        try:
            probe_keys = {
                int(key, 0) if isinstance(key, str) else int(key)
                for key in probe.keys()
            }
        except Exception:
            probe_keys = set()
        if probe_keys:
            overlap = len(unique_opcodes & probe_keys)
            if overlap < max(3, len(probe_keys) // 8):
                return False

    return True


# ---------------------------------------------------------------------------
# Legacy compatibility exports
# ---------------------------------------------------------------------------

try:  # pragma: no cover - optional legacy wrapper
    luraph_deobfuscator = import_module("luraph_deobfuscator")
except Exception:  # pragma: no cover - when stub not available
    luraph_deobfuscator = None


__all__ = [
    "InitV4_2Handler",
    "LEGACY_HANDLER",
    "LuraphV1441",
    "LuraphV1441Alias",
    "HANDLER",
    "_INITV4_ALPHABET",
    "_BASE_OPCODE_TABLE",
    "_apply_script_key_transform",
    "_decode_base91",
    "_encode_base91",
    "decode_blob",
    "decode_blob_with_metadata",
    "looks_like_vm_bytecode",
    "luraph_deobfuscator",
]

if DEFAULT_ALPHABET:  # pragma: no cover - constant defined at import time
    __all__.append("DEFAULT_ALPHABET")
