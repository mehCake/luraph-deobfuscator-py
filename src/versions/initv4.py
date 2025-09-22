"""Helpers for parsing Luraph ``initv4`` bootstrap stubs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Tuple

from . import OpSpec
from .luraph_v14_2_json import LuraphV142JSON

_BASE_OPCODE_SPECS: Dict[int, OpSpec] = LuraphV142JSON().opcode_table()
_BASE_OPCODE_NAMES: Dict[int, str] = {
    opcode: spec.mnemonic for opcode, spec in _BASE_OPCODE_SPECS.items()
}

_ADDITIONAL_SPECS: Tuple[OpSpec, ...] = (
    OpSpec("NOT", ("a", "b")),
    OpSpec("LEN", ("a", "b")),
    OpSpec("CONCAT", ("a", "b", "c")),
    OpSpec("TFORLOOP", ("a", "offset", "c")),
)

_existing = {spec.mnemonic.upper() for spec in _BASE_OPCODE_SPECS.values()}
_next_opcode = max(_BASE_OPCODE_SPECS.keys(), default=0) + 1
for _spec in _ADDITIONAL_SPECS:
    name = _spec.mnemonic.upper()
    if name in _existing:
        continue
    _BASE_OPCODE_SPECS[_next_opcode] = _spec
    _BASE_OPCODE_NAMES[_next_opcode] = _spec.mnemonic
    _existing.add(name)
    _next_opcode += 1

_PRINTABLE85 = re.escape(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)

_ALPHABET_RE = re.compile(rf"[\"']([{_PRINTABLE85}]{{85,}})[\"']")
_PAYLOAD_RE = re.compile(rf'([\"\'])([{_PRINTABLE85}]{{40,}})\1')
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


class InitV4Decoder:
    """Lightweight helper that mirrors the initv4 bootstrap decode flow."""

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
        from .luraph_v14_4_1 import decode_blob  # local import to avoid cycles

        return decode_blob(cleaned, self.script_key, alphabet=self.alphabet)

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


__all__ = ["InitV4Bootstrap", "InitV4Decoder"]

