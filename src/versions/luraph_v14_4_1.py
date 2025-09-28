"""Version handler for the Luraph v14.4.1 (``initv4``) bootstrap."""

from __future__ import annotations

import logging
from typing import Any, Dict

from . import OpSpec, VersionHandler, register_handler
from .luraph_v14_4_initv4 import decode_blob, decode_blob_with_metadata

LOG = logging.getLogger(__name__)


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
                    opcode_id = int(key)
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

__all__ = [
    "InitV4_2Handler",
    "HANDLER",
    "decode_blob",
    "decode_blob_with_metadata",
]
