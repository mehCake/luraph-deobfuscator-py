"""Initv4 decoder helpers specialised for the Luraph v14.4 family."""

from __future__ import annotations

from pathlib import Path
import re
from typing import Dict, Iterable, List, Mapping, Optional, Tuple
from .initv4 import (
    InitV4Bootstrap,
    _BASE_OPCODE_NAMES,
    _BASE_OPCODE_SPECS,
    _PAYLOAD_RE,
    _S8W_PAYLOAD_RE,
    _is_probably_alphabet,
)

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
        self.opcode_map: Dict[int, str] | None = None
        self._has_custom_opcodes = False
        self._bootstrap = bootstrap
        self._bootstrap_path: Optional[Path] = None
        self._default_opcodes: Dict[int, str] = dict(
            default_opcodes or self._DEFAULT_OPCODE_TABLE
        )

        if self._bootstrap is None:
            candidate = getattr(ctx, "bootstrapper_path", None)
            if candidate:
                self._bootstrap = InitV4Bootstrap.load(candidate)
        if self._bootstrap is not None:
            self._bootstrap_path = self._bootstrap.path
            self._prepare_from_bootstrap(self._bootstrap)

    # ------------------------------------------------------------------
    def _prepare_from_bootstrap(self, bootstrap: InitV4Bootstrap) -> None:
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
            opcode_map = self._extract_opcodes(text)
            if opcode_map:
                self._has_custom_opcodes = True
            else:
                opcode_map = {}

        else:
            opcode_map = {}

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
            self.opcode_map = opcode_map

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
