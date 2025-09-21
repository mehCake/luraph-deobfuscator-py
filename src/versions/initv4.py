"""Helpers for parsing Luraph ``initv4`` bootstrap stubs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Dict, Iterator, List, Mapping, MutableMapping, Optional, Tuple

from . import OpSpec

_PRINTABLE85 = re.escape(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)

_ALPHABET_RE = re.compile(rf"[\"']([{_PRINTABLE85}]{{85,}})[\"']")
_NAMED_VALUE_RE = re.compile(
    r"\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\]\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)",
)
_VALUE_NAMED_RE = re.compile(
    r"\[(0[xX][0-9A-Fa-f]+|\d+)\]\s*=\s*['\"]([A-Z][A-Z0-9_]*)['\"]",
)
_FUNC_ASSIGN_RE = re.compile(
    r"\[(0[xX][0-9A-Fa-f]+|\d+)\]\s*=\s*function",
)
_GLOBAL_ASSIGN_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]*)\s*=\s*(0[xX][0-9A-Fa-f]+|\d+)",
)


def _normalise_path(path: Path | str | None) -> Path:
    if path is None:
        raise FileNotFoundError("no bootstrap path provided")
    if isinstance(path, Path):
        candidate = path
    else:
        candidate = Path(path)
    return candidate.expanduser()


def _is_probably_alphabet(candidate: str) -> bool:
    if len(candidate) < 85:
        return False
    unique = set(candidate)
    return len(unique) >= 70 and all(33 <= ord(ch) <= 126 for ch in candidate)


def _to_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        return int(value)


@dataclass
class InitV4Bootstrap:
    """Best-effort parser for initv4 loader scripts."""

    path: Path
    text: str
    metadata: MutableMapping[str, object] = field(default_factory=dict)

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, candidate: Path | str) -> "InitV4Bootstrap":
        base = _normalise_path(candidate)
        if base.is_dir():
            resolved = cls._select_from_directory(base)
        else:
            resolved = base
        if not resolved.exists():
            raise FileNotFoundError(resolved)
        text = resolved.read_text(encoding="utf-8", errors="ignore")
        return cls(resolved, text)

    # ------------------------------------------------------------------
    @staticmethod
    def _select_from_directory(directory: Path) -> Path:
        preferred = [
            directory / "initv4.lua",
            directory / "init.lua",
            directory / "init.lua.txt",
            directory / "bootstrap.lua",
        ]
        for path in preferred:
            if path.exists():
                return path
        lua_files = [entry for entry in directory.iterdir() if entry.is_file() and entry.suffix.lower() == ".lua"]
        if lua_files:
            return sorted(lua_files)[0]
        # Fall back to any text-like file to avoid failing silently.
        text_files = [
            entry
            for entry in directory.iterdir()
            if entry.is_file() and entry.suffix.lower() in {".txt", ".dat"}
        ]
        if text_files:
            return sorted(text_files)[0]
        raise FileNotFoundError("no bootstrapper candidates discovered")

    # ------------------------------------------------------------------
    def alphabet(self) -> Optional[str]:
        match = _ALPHABET_RE.search(self.text)
        if not match:
            return None
        candidate = match.group(1)
        if _is_probably_alphabet(candidate):
            self.metadata.setdefault("alphabet_length", len(candidate))
            return candidate
        return None

    # ------------------------------------------------------------------
    def opcode_mapping(self, base_table: Mapping[int, OpSpec]) -> Dict[str, int]:
        mapping: Dict[str, int] = {}
        for name, value in _NAMED_VALUE_RE.findall(self.text):
            mapping.setdefault(name.upper(), _to_int(value))
        for value, name in _VALUE_NAMED_RE.findall(self.text):
            mapping.setdefault(name.upper(), _to_int(value))
        for name, value in _GLOBAL_ASSIGN_RE.findall(self.text):
            if len(name) >= 3 and name.isupper():
                mapping.setdefault(name.upper(), _to_int(value))

        base_order: List[Tuple[int, OpSpec]] = sorted(base_table.items())
        if len(mapping) < len(base_order):
            sequence = self._opcode_sequence()
            if sequence:
                for (_, spec), opcode in zip(base_order, sequence):
                    mapping.setdefault(spec.mnemonic.upper(), opcode)

        if mapping:
            self.metadata.setdefault("opcode_map_entries", len(mapping))
        return mapping

    # ------------------------------------------------------------------
    def _opcode_sequence(self) -> List[int]:
        seen: set[int] = set()
        sequence: List[int] = []
        for value in _FUNC_ASSIGN_RE.findall(self.text):
            raw = _to_int(value)
            if raw in seen:
                continue
            seen.add(raw)
            sequence.append(raw)
        if sequence:
            self.metadata.setdefault("opcode_sequence", len(sequence))
        return sequence

    # ------------------------------------------------------------------
    def build_opcode_table(self, base_table: Mapping[int, OpSpec]) -> Dict[int, OpSpec]:
        mapping = self.opcode_mapping(base_table)
        if not mapping:
            return dict(base_table)

        reverse: Dict[int, OpSpec] = {}
        used: set[int] = set()
        for _, spec in sorted(base_table.items()):
            target = mapping.get(spec.mnemonic.upper())
            if target is None:
                continue
            if target in used:
                continue
            reverse[target] = spec
            used.add(target)

        # Ensure base opcodes that were not remapped remain available.
        for opcode, spec in base_table.items():
            if opcode in used:
                continue
            reverse.setdefault(opcode, spec)

        return dict(sorted(reverse.items()))

    # ------------------------------------------------------------------
    def iter_metadata(self) -> Iterator[Tuple[str, object]]:
        yield from self.metadata.items()


__all__ = ["InitV4Bootstrap"]

