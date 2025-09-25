"""Initv4 decoder helpers specialised for the Luraph v14.4 family."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from .initv4 import (
    InitV4Bootstrap,
    _BASE_OPCODE_NAMES,
    _BASE_OPCODE_SPECS,
    _PAYLOAD_RE,
    _S8W_PAYLOAD_RE,
    _is_probably_alphabet,
)
from ..bootstrap_decoder import BootstrapDecoder, BootstrapperExtractionResult

LOG = logging.getLogger(__name__)


def _bootstrap_log(level: int, message: str, *args: object) -> None:
    LOG.log(level, "[BOOTSTRAP] " + message, *args)

DEFAULT_ALPHABET = (
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)


def decode_blob(blob_str: str, alphabet: Optional[str], key_bytes: bytes) -> bytes:
    """Decode an initv4 payload chunk using *alphabet* and *key_bytes*.

    The bootstrapper ships payloads encoded with a base91-like alphabet; once
    decoded, every byte is XORed with the repeating script key and the current
    byte index.  This helper mirrors that behaviour so tests and lightweight
    decoding contexts can share a small, dependency-free implementation.
    """

    effective_alphabet = alphabet or DEFAULT_ALPHABET
    decode_map = {symbol: index for index, symbol in enumerate(effective_alphabet)}
    base = len(effective_alphabet)

    value = -1
    buffer = 0
    bits = 0
    output = bytearray()
    key_len = len(key_bytes) if key_bytes else 0
    out_index = 0

    for char in blob_str:
        if char.isspace():
            continue
        symbol = decode_map.get(char, 0)
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
            byte = buffer & 0xFF
            buffer >>= 8
            bits -= 8
            if key_len:
                byte ^= key_bytes[out_index % key_len]
            byte ^= out_index & 0xFF
            output.append(byte & 0xFF)
            out_index += 1

        value = -1

    if value + 1:
        buffer |= value << bits
        byte = buffer & 0xFF
        if key_len:
            byte ^= key_bytes[out_index % key_len]
        byte ^= out_index & 0xFF
        output.append(byte & 0xFF)

    return bytes(output)


class InitV4Decoder:
    """Lightweight helper mirroring the initv4 bootstrap decode flow."""

    _DEFAULT_OPCODE_TABLE: Dict[int, str] = dict(_BASE_OPCODE_NAMES)

    def __init__(
        self,
        ctx: object,
        *,
        bootstrap: Optional[InitV4Bootstrap] = None,
        default_opcodes: Optional[Mapping[int, str]] = None,
    ) -> None:
        self.ctx = ctx
        raw_key = getattr(ctx, "script_key", None)
        if isinstance(raw_key, str):
            raw_key = raw_key.strip()
        self.script_key: Optional[str] = raw_key if raw_key else None
        self.alphabet: Optional[str] = None
        self.opcode_map: Dict[int, str] = {}
        self.constants: Dict[str, int] = {}
        self.bootstrap_metadata: Dict[str, object] = {}
        self._raw_matches: Dict[str, object] | None = None
        self._bootstrap_decoder_result: Optional[BootstrapperExtractionResult] = None
        self._bootstrap_decoder_metadata: Dict[str, Any] = {}
        self._bootstrap_decoder_errors: List[str] = []
        self._bootstrap_decoder_blobs: List[Dict[str, Any]] = []
        self._bootstrap_decoder_success = False
        self._bootstrap_needs_emulation = False
        self._bootstrap_warnings: List[str] = []
        self._debug_bootstrap = bool(getattr(ctx, "debug_bootstrap", False))
        raw_log = getattr(ctx, "bootstrap_debug_log", None)
        try:
            self._bootstrap_debug_log: Optional[Path] = Path(raw_log) if raw_log else None
        except TypeError:
            self._bootstrap_debug_log = None
        self._has_custom_opcodes = False
        self._bootstrap = bootstrap
        self._bootstrap_path: Optional[Path] = None
        self._bootstrap_source: Optional[str] = None
        self._script_key_bytes: bytes = (
            self.script_key.encode("utf-8") if isinstance(self.script_key, str) else b""
        )
        self._default_opcodes: Dict[int, str] = dict(
            default_opcodes or self._DEFAULT_OPCODE_TABLE
        )

        candidate = getattr(ctx, "bootstrapper_path", None)
        path_for_decoder: Optional[str] = None
        if self._bootstrap is None and candidate:
            try:
                self._bootstrap = InitV4Bootstrap.load(candidate)
            except Exception as exc:
                _bootstrap_log(logging.WARNING, "Failed to load bootstrapper: %s", exc)
                self._bootstrap_warnings.append("bootstrap_load_failed")
            else:
                self._bootstrap_path = self._bootstrap.path
                path_for_decoder = str(self._bootstrap.path)
                self._bootstrap_source = path_for_decoder
        elif self._bootstrap is not None:
            self._bootstrap_path = self._bootstrap.path
            path_for_decoder = str(self._bootstrap.path)
            self._bootstrap_source = path_for_decoder

        if path_for_decoder is None and isinstance(candidate, (str, Path)):
            path_for_decoder = str(candidate)
            self._bootstrap_source = path_for_decoder

        if path_for_decoder and self._script_key_bytes:
            self._run_bootstrap_decoder(path_for_decoder)
        elif path_for_decoder and not self._script_key_bytes:
            _bootstrap_log(
                logging.WARNING,
                "Script key missing; bootstrap decoder cannot run.",
            )
            self._bootstrap_warnings.append("script_key_missing")

        if self._bootstrap is not None:
            text = self._bootstrap.text or ""
            if text and not self.alphabet:
                match = re.search(r'alphabet\s*=\s*"([^"]+)"', text)
                if match and _is_probably_alphabet(match.group(1)):
                    self.alphabet = match.group(1)
            self._prepare_from_bootstrap(self._bootstrap)

        self._finalise_bootstrap_metadata()

    # ------------------------------------------------------------------
    def _run_bootstrap_decoder(self, bootstrap_path: str) -> None:
        script_key = self.script_key or ""
        decoder = BootstrapDecoder(self.ctx, bootstrap_path, script_key)

        try:
            result = decoder.run_full_extraction()
        except Exception as exc:  # pragma: no cover - defensive
            _bootstrap_log(logging.ERROR, "Bootstrap decoder crashed: %s", exc)
            self._bootstrap_warnings.append("decoder_exception")
            return

        self._bootstrap_decoder_result = result
        self._bootstrap_decoder_success = bool(result.success)
        self._bootstrap_needs_emulation = bool(result.needs_emulation)
        self._bootstrap_decoder_errors = list(result.errors)

        if result.raw_matches:
            self._raw_matches = {"bootstrap_decoder": result.raw_matches}

        metadata = result.bootstrapper_metadata or {}
        if isinstance(metadata, dict):
            self._bootstrap_decoder_metadata = dict(metadata)
            blobs = metadata.get("blobs")
            if isinstance(blobs, list):
                self._bootstrap_decoder_blobs = [
                    dict(entry) for entry in blobs if isinstance(entry, dict)
                ]
            self._ingest_bootstrap_metadata(metadata)
            if result.raw_matches and self._debug_bootstrap:
                raw_section = metadata.setdefault("raw_matches", {})
                if isinstance(raw_section, Mapping):
                    raw_section = dict(raw_section)
                else:
                    raw_section = {}
                raw_section.setdefault("bootstrap_decoder", result.raw_matches)
                metadata["raw_matches"] = raw_section

        if not result.success:
            if not self.alphabet:
                self.alphabet = DEFAULT_ALPHABET
            warning = "bootstrap_decoder_incomplete"
            self._bootstrap_warnings.append(warning)
            if result.errors:
                _bootstrap_log(
                    logging.WARNING,
                    "Bootstrap decoder failed: %s",
                    "; ".join(str(err) for err in result.errors if err),
                )
        else:
            decoded_count = len(result.decoded_blobs)
            _bootstrap_log(
                logging.INFO,
                "Bootstrap decoder recovered %d blob(s).",
                decoded_count,
            )

    # ------------------------------------------------------------------
    def _ingest_bootstrap_metadata(self, metadata: Mapping[str, Any]) -> None:
        alphabet = metadata.get("alphabet")
        if isinstance(alphabet, str) and alphabet.strip():
            self.alphabet = alphabet

        opcode_map = metadata.get("opcode_map")
        if isinstance(opcode_map, Mapping):
            normalised: Dict[int, str] = {}
            for key, name in opcode_map.items():
                try:
                    opcode = int(key)
                except (TypeError, ValueError):
                    continue
                cleaned = str(name).strip().upper()
                if cleaned:
                    normalised[opcode] = cleaned
            if normalised:
                if not self.opcode_map:
                    self.opcode_map = {}
                self.opcode_map.update(normalised)
                self._has_custom_opcodes = True

        constants = metadata.get("constants")
        if isinstance(constants, Mapping):
            for key, value in constants.items():
                try:
                    numeric = int(value)
                except (TypeError, ValueError):
                    continue
                self.constants[str(key)] = numeric

    def _prepare_from_bootstrap(self, bootstrap: InitV4Bootstrap) -> None:
        opcode_map: Dict[int, str] = dict(self.opcode_map)

        alphabet = bootstrap.alphabet()
        if alphabet:
            self.alphabet = alphabet

        text = bootstrap.text
        if text:
            # Look for explicit alphabet assignment first in case the helper
            # did not detect it via :meth:`alphabet`.
            if self.alphabet is None:
                match = re.search(r'alphabet\s*=\s*"([^"]+)"', text)
                if match and _is_probably_alphabet(match.group(1)):
                    self.alphabet = match.group(1)
            extracted_map = self._extract_opcodes(text)
            if extracted_map:
                self._has_custom_opcodes = True
                for opcode, name in extracted_map.items():
                    opcode_map.setdefault(opcode, name)

        mapping = bootstrap.opcode_mapping(_BASE_OPCODE_SPECS)
        if mapping:
            self._has_custom_opcodes = True
            for name, value in mapping.items():
                opcode_map.setdefault(value, name.upper())

        table = bootstrap.build_opcode_table(_BASE_OPCODE_SPECS)
        if table:
            for opcode, spec in table.items():
                opcode_map.setdefault(opcode, spec.mnemonic)

        if opcode_map:
            if not self._has_custom_opcodes:
                base_names = _BASE_OPCODE_NAMES
                if any(base_names.get(code) != name for code, name in opcode_map.items()):
                    self._has_custom_opcodes = True
            self.opcode_map = dict(sorted(opcode_map.items()))

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    def _finalise_bootstrap_metadata(self) -> None:
        alphabet = self.alphabet
        opcode_map = dict(self.opcode_map)
        constants = dict(self.constants)

        warnings: List[str] = list(self._bootstrap_warnings)
        has_bootstrap = bool(self._bootstrap_path) or bool(self._bootstrap_decoder_result)
        if not alphabet and has_bootstrap:
            warnings.append("alphabet_not_found")
        if opcode_map and len(opcode_map) < 16:
            warnings.append("opcode_mapping_incomplete")
        if not opcode_map and has_bootstrap:
            warnings.append("opcode_mapping_not_found")

        preview_len = 32
        if alphabet:
            preview = alphabet[:preview_len]
            suffix = "..." if len(alphabet) > preview_len else ""
            _bootstrap_log(
                logging.INFO,
                "Extracted alphabet (len=%d): %s%s",
                len(alphabet),
                preview,
                suffix,
            )
        elif has_bootstrap:
            _bootstrap_log(
                logging.WARNING,
                "Alphabet missing; default alphabet will be used.",
            )

        if opcode_map:
            total = len(opcode_map)
            preview_count = min(10, total)
            _bootstrap_log(
                logging.INFO,
                "Extracted %d opcode mappings. First %d:",
                total,
                preview_count,
            )
            for opcode, name in list(sorted(opcode_map.items()))[:preview_count]:
                LOG.info("  0x%02X -> %s", opcode, name)
            if total < 16:
                _bootstrap_log(
                    logging.WARNING,
                    "Only %d opcode mappings extracted; results may be incomplete.",
                    total,
                )
        elif has_bootstrap:
            _bootstrap_log(logging.WARNING, "Opcode dispatch table not discovered.")

        if constants:
            items = list(sorted(constants.items()))
            preview_items = items[:5]
            summary = ", ".join(f"{name}={value}" for name, value in preview_items)
            if len(items) > len(preview_items):
                summary += ", ..."
            _bootstrap_log(
                logging.INFO,
                "Extracted %d constants: %s",
                len(constants),
                summary,
            )
        elif has_bootstrap:
            _bootstrap_log(logging.INFO, "No bootstrapper constants discovered.")

        raw_matches: Optional[Dict[str, Any]] = None
        if self._debug_bootstrap:
            if self._raw_matches:
                raw_matches = dict(self._raw_matches)
        if raw_matches:
            try:
                pretty = json.dumps(raw_matches, indent=2, sort_keys=True)
            except TypeError:  # pragma: no cover - safety
                pretty = repr(raw_matches)
            LOG.debug("[BOOTSTRAP] Raw matches:%s%s", "\n", pretty)

        decoder_summary: Dict[str, Any] = {
            "success": self._bootstrap_decoder_success,
            "needs_emulation": self._bootstrap_needs_emulation,
        }
        if self._bootstrap_decoder_errors:
            decoder_summary["errors"] = list(self._bootstrap_decoder_errors)
        if self._bootstrap_decoder_blobs:
            decoder_summary["blobs"] = [dict(entry) for entry in self._bootstrap_decoder_blobs]

        dispatch_map = {f"0x{opcode:02X}": name for opcode, name in sorted(opcode_map.items())}
        metadata: Dict[str, object] = {
            "alphabet": {
                "value": alphabet,
                "length": len(alphabet) if alphabet else 0,
                "sample": alphabet[:64] if alphabet else "",
                "source": "bootstrapper" if alphabet else "default",
            },
            "opcode_dispatch": {
                "count": len(opcode_map),
                "mapping": dispatch_map,
            },
            "constants": constants,
            "decoder": decoder_summary,
            "needs_emulation": self._bootstrap_needs_emulation,
        }
        if self._bootstrap_path is not None:
            metadata["path"] = str(self._bootstrap_path)
        elif self._bootstrap_source:
            metadata["source"] = self._bootstrap_source
        if warnings:
            metadata["warnings"] = warnings
        if self._bootstrap_decoder_blobs:
            metadata["blobs"] = [dict(entry) for entry in self._bootstrap_decoder_blobs]
        if self._bootstrap_decoder_metadata and self._debug_bootstrap:
            metadata.setdefault("decoder", {}).setdefault(
                "metadata", dict(self._bootstrap_decoder_metadata)
            )
        merged_raw_matches: Optional[Dict[str, Any]] = None
        existing_raw = metadata.get("raw_matches")
        if isinstance(existing_raw, Mapping):
            merged_raw_matches = dict(existing_raw)
        if raw_matches:
            if merged_raw_matches is None:
                merged_raw_matches = {}
            merged_raw_matches.update(raw_matches)
        if merged_raw_matches:
            metadata["raw_matches"] = merged_raw_matches

        preview = [
            {"opcode": f"0x{opcode:02X}", "mnemonic": name}
            for opcode, name in list(sorted(opcode_map.items()))[:10]
        ]
        dump_payload = {
            "path": str(self._bootstrap_path) if self._bootstrap_path else None,
            "warnings": warnings,
            "opcode_preview": preview,
            "alphabet": {
                "length": len(alphabet) if alphabet else 0,
                "sample": alphabet[:64] if alphabet else "",
            },
            "decoder": decoder_summary,
        }
        if merged_raw_matches:
            dump_payload["raw_matches"] = merged_raw_matches

        if raw_matches and self._bootstrap_debug_log is not None and self._debug_bootstrap:
            try:
                self._bootstrap_debug_log.parent.mkdir(parents=True, exist_ok=True)
                self._bootstrap_debug_log.write_text(
                    json.dumps(dump_payload, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                _bootstrap_log(
                    logging.INFO,
                    "Raw matches dumped to %s",
                    self._bootstrap_debug_log,
                )
            except Exception:  # pragma: no cover - best effort
                _bootstrap_log(
                    logging.WARNING,
                    "Failed to write raw matches to %s",
                    self._bootstrap_debug_log,
                )
                LOG.debug(
                    "Failed to write bootstrap debug log", exc_info=True
                )

        if has_bootstrap or alphabet or opcode_map or constants or raw_matches:
            self.bootstrap_metadata = metadata
            try:
                setattr(self.ctx, "bootstrapper_metadata", dict(metadata))
            except Exception:  # pragma: no cover - defensive
                pass
        else:
            self.bootstrap_metadata = {}

    # ------------------------------------------------------------------
    def _extract_opcodes(self, src: str) -> Dict[int, str]:
        opcode_map: Dict[int, str] = {}

        def _record(opcode: str, name: str) -> None:
            try:
                value = int(opcode, 0)
            except ValueError:
                return
            cleaned = name.strip().upper()
            if cleaned:
                opcode_map.setdefault(value, cleaned)

        # [0xNN] = "OPCODE"
        for match in re.finditer(
            r"\[(0x[0-9A-Fa-f]+|\d+)\]\s*=\s*['\"]([A-Za-z0-9_]+)['\"]",
            src,
        ):
            _record(match.group(1), match.group(2))

        # table[0xNN] = function(...) -- OPCODE
        for match in re.finditer(
            r"\[(0x[0-9A-Fa-f]+|\d+)\]\s*=\s*function[^\n]*?--\s*([A-Za-z0-9_]+)",
            src,
        ):
            _record(match.group(1), match.group(2))

        # dispatch[0xNN] = function ... end -- OPCODE style assignments.
        for match in re.finditer(
            r"([A-Za-z_][A-Za-z0-9_]*)\[(0x[0-9A-Fa-f]+|\d+)\]\s*=\s*function(.*?)(?:--\s*([A-Za-z0-9_]+))",
            src,
            flags=re.DOTALL,
        ):
            if match.group(4):
                _record(match.group(2), match.group(4))

        # case 0xNN: -- OPCODE (switch style bootstrappers)
        for match in re.finditer(
            r"case\s*(0x[0-9A-Fa-f]+|\d+)\s*:[^\n]*?--\s*([A-Za-z0-9_]+)",
            src,
        ):
            _record(match.group(1), match.group(2))

        return opcode_map

    # ------------------------------------------------------------------
    def locate_payload(self, source: str) -> List[str]:
        blobs: List[str] = []

        for match in _S8W_PAYLOAD_RE.finditer(source):
            blobs.append(match.group(0))

        if blobs:
            return blobs

        for match in _PAYLOAD_RE.finditer(source):
            blobs.append(match.group(0))

        return blobs

    # ------------------------------------------------------------------
    def extract_bytecode(self, blob: str) -> bytes:
        if not self.script_key:
            raise ValueError("script key required to decode initv4 payloads")
        cleaned = blob.strip()
        if cleaned.startswith('"') and cleaned.endswith('"'):
            cleaned = cleaned[1:-1]

        key_bytes = self.script_key.encode("utf-8")
        alphabet = self.alphabet or DEFAULT_ALPHABET
        return decode_blob(cleaned, alphabet, key_bytes)

    # ------------------------------------------------------------------
    def opcode_table(self) -> Dict[int, str]:
        if self.opcode_map:
            return dict(self.opcode_map)
        return dict(self._default_opcodes)

    # ------------------------------------------------------------------
    def iter_opcodes(self) -> Iterable[Tuple[int, str]]:
        table = self.opcode_table()
        for opcode, name in sorted(table.items()):
            yield opcode, name

    # ------------------------------------------------------------------
    def has_custom_opcodes(self) -> bool:
        return self._has_custom_opcodes


__all__ = ["DEFAULT_ALPHABET", "InitV4Decoder", "decode_blob"]
