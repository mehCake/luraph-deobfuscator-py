"""Regex-driven extraction of init bootstrapper metadata."""

from __future__ import annotations

import logging
import re
from types import SimpleNamespace
from typing import Any, Dict, Optional

LOG = logging.getLogger(__name__)

_PRINTABLE = r"!\x22#$%&'()*+,\-./0-9:;<=>?@A-Z\\[\\]^_`a-z{|}~"


def _parse_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return int(value, 10)


class BootstrapExtractor:
    """Simple regex-based bootstrapper metadata extraction."""

    def __init__(self, ctx: Any | None = None) -> None:
        if ctx is None:
            ctx = SimpleNamespace(debug_bootstrap=False)
        self.ctx = ctx
        self.alphabet: Optional[str] = None
        self.opcode_map: Dict[int, str] = {}
        self.constants: Dict[str, int] = {}
        self.raw_matches: Dict[str, list[Any]] = {
            "alphabets": [],
            "opcodes": [],
            "constants": [],
        }

    # ------------------------------------------------------------------
    def extract(self, text: str) -> Dict[str, Any]:
        """Extract alphabet, opcode map, and constants from ``text``."""

        self._extract_alphabet(text)
        self._extract_opcodes(text)
        self._extract_constants(text)

        debug_enabled = bool(getattr(self.ctx, "debug_bootstrap", False))

        if debug_enabled and self.opcode_map:
            preview = sorted(self.opcode_map.items())[:10]
            for opcode, name in preview:
                LOG.info("  opcode 0x%02X -> %s", opcode, name)

        return {
            "alphabet": self.alphabet,
            "opcode_map": dict(sorted(self.opcode_map.items())),
            "constants": dict(sorted(self.constants.items())),
            "raw_matches": dict(self.raw_matches) if debug_enabled else None,
        }

    # ------------------------------------------------------------------
    def _extract_alphabet(self, text: str) -> None:
        pattern = re.compile(r'alphabet\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"')
        for match in pattern.finditer(text):
            candidate = match.group(1)
            self.raw_matches["alphabets"].append(candidate)
        long_string_pattern = re.compile(rf"\"([{_PRINTABLE}]{{80,120}})\"")
        for match in long_string_pattern.finditer(text):
            self.raw_matches["alphabets"].append(match.group(1))
        if self.raw_matches["alphabets"]:
            self.alphabet = max(self.raw_matches["alphabets"], key=len)
        else:
            LOG.warning("No alphabet found in bootstrapper, using default.")
            self.alphabet = None

    # ------------------------------------------------------------------
    def _extract_opcodes(self, text: str) -> None:
        for match in re.finditer(
            r"\[\s*(0x[0-9A-Fa-f]+)\s*\]\s*=\s*function\s*\([^)]*\)\s*--\s*([A-Za-z0-9_]+)",
            text,
        ):
            opcode = int(match.group(1), 16)
            name = match.group(2).upper()
            self.opcode_map.setdefault(opcode, name)
            self.raw_matches["opcodes"].append(match.group(0))
        for match in re.finditer(
            r"case\s*(0x[0-9A-Fa-f]+)\s*:\s*--\s*([A-Za-z0-9_]+)",
            text,
        ):
            opcode = int(match.group(1), 16)
            name = match.group(2).upper()
            self.opcode_map.setdefault(opcode, name)
            self.raw_matches["opcodes"].append(match.group(0))
        for match in re.finditer(
            r'opcodes\["([A-Za-z0-9_]+)"\]\s*=\s*(0x[0-9A-Fa-f]+|\d+)',
            text,
        ):
            name = match.group(1).upper()
            opcode = _parse_int(match.group(2))
            self.opcode_map.setdefault(opcode, name)
            self.raw_matches["opcodes"].append(match.group(0))

        if len(self.opcode_map) < 16:
            LOG.warning("Opcode map extraction found fewer than 16 entries. Incomplete mapping?")

    # ------------------------------------------------------------------
    def _extract_constants(self, text: str) -> None:
        for match in re.finditer(r"([A-Z][A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)", text):
            name = match.group(1)
            value = _parse_int(match.group(2))
            self.constants.setdefault(name, value)
            self.raw_matches["constants"].append(match.group(0))
        if self.constants and bool(getattr(self.ctx, "debug_bootstrap", False)):
            LOG.info("Discovered %d bootstrapper constants", len(self.constants))


__all__ = ["BootstrapExtractor"]
