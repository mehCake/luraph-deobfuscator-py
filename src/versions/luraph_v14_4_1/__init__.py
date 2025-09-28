"""Compatibility-focused helpers for the Luraph v14.4.1 (``initv4``) bootstrap."""

from __future__ import annotations

import logging
from importlib import import_module
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from .. import OpSpec, VersionHandler, register_handler
from ..luraph_v14_4_initv4 import (
    DEFAULT_ALPHABET,
    _decode_base91,
    _prepare_alphabet,
    _xor_with_index,
    _xor_with_key,
    decode_blob,
    decode_blob_with_metadata,
)

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
HANDLER = InitV4_2Handler()


def looks_like_vm_bytecode(
    blob: Sequence[int] | bytes,
    opcode_probe: Mapping[int, Any] | None = None,
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

    if opcode_probe:
        try:
            probe_keys = {
                int(key, 0) if isinstance(key, str) else int(key)
                for key in opcode_probe.keys()
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
    "HANDLER",
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
