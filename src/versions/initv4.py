"""Helpers for parsing Luraph ``initv4`` bootstrap stubs."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Tuple

from . import OpSpec
from .luraph_v14_2_json import LuraphV142JSON
from ..bootstrap_extractor import BootstrapExtractor

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
_S8W_PAYLOAD_RE = re.compile(r"([\"\'])(s8W-[!-~]{40,})\1")
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
_TABLE_ASSIGN_RE = re.compile(
    r"(?:local\s+)?([A-Z][A-Z0-9_]*)\s*=\s*{(.*?)}",
    re.DOTALL,
)


LOG = logging.getLogger(__name__)


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
        text = resolved.read_text(encoding="utf-8-sig", errors="ignore")
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
    def extract_metadata(
        self,
        base_table: Mapping[int, OpSpec],
        *,
        debug: bool = False,
        debug_log: Path | None = None,
    ) -> Tuple[Optional[str], Dict[str, int], Dict[int, OpSpec], Dict[str, object]]:
        warnings: List[str] = []
        raw_matches: Dict[str, object] = {}

        extractor = BootstrapExtractor(SimpleNamespace(debug_bootstrap=debug))
        extracted = extractor.extract(self.text)
        alphabet: Optional[str] = extracted.get("alphabet")
        opcode_name_map = extracted.get("opcode_map") or {}
        constants: Dict[str, int] = dict(extracted.get("constants") or {})

        if debug:
            raw = extracted.get("raw_matches")
            if isinstance(raw, dict) and raw:
                raw_matches["bootstrap_extractor"] = raw

        alphabet_candidates = [match.group(1) for match in _ALPHABET_RE.finditer(self.text)]
        if alphabet_candidates:
            raw_matches["alphabet_candidates"] = list(alphabet_candidates)

        if alphabet is None:
            for candidate in alphabet_candidates:
                if _is_probably_alphabet(candidate):
                    alphabet = candidate
                    break

        if alphabet:
            LOG.info("Bootstrapper alphabet length: %d", len(alphabet))
            self.metadata.setdefault("alphabet_length", len(alphabet))
        else:
            warning = (
                "Bootstrapper alphabet not detected; falling back to default alphabet"
            )
            LOG.warning(warning)
            warnings.append(warning)

        named_value_matches = list(_NAMED_VALUE_RE.findall(self.text))
        if named_value_matches:
            raw_matches["opcode_named_values"] = [
                (name.upper(), value) for name, value in named_value_matches
            ]

        value_named_matches = list(_VALUE_NAMED_RE.findall(self.text))
        if value_named_matches:
            raw_matches["opcode_value_aliases"] = [
                (value, name.upper()) for value, name in value_named_matches
            ]

        func_assign_matches = list(_FUNC_ASSIGN_RE.findall(self.text))
        if func_assign_matches:
            raw_matches["function_assignments"] = list(func_assign_matches)

        global_assign_matches = [
            (name.upper(), value)
            for name, value in _GLOBAL_ASSIGN_RE.findall(self.text)
            if len(name) >= 3 and name.isupper()
        ]
        if global_assign_matches:
            raw_matches["global_assignments"] = list(global_assign_matches)

        for name, value in global_assign_matches:
            constants.setdefault(name, _to_int(value))
        if constants:
            LOG.info("Discovered %d numeric bootstrapper constants", len(constants))

        mapping = self.opcode_mapping(base_table)
        if opcode_name_map:
            for opcode, mnemonic in opcode_name_map.items():
                mapping.setdefault(mnemonic.upper(), opcode)
        if mapping:
            LOG.info("Discovered %d opcode name remappings", len(mapping))

        table = self.build_opcode_table(base_table)
        dispatch_items = [(opcode, spec.mnemonic) for opcode, spec in sorted(table.items())]
        dispatch_count = len(dispatch_items)
        LOG.info("Bootstrapper opcode dispatch entries: %d", dispatch_count)
        if dispatch_count < 16:
            warning = (
                f"Only {dispatch_count} opcode mapping(s) extracted; bootstrapper parsing may be incomplete"
            )
            LOG.warning(warning)
            warnings.append(warning)

        for opcode, mnemonic in dispatch_items[:10]:
            LOG.info("  opcode 0x%02X -> %s", opcode, mnemonic)

        helper_structures: List[Dict[str, object]] = []
        helper_dump: Dict[str, str] = {}
        for match in _TABLE_ASSIGN_RE.finditer(self.text):
            name = match.group(1)
            body = match.group(2)
            cleaned = body.strip()
            if not cleaned:
                continue
            if len(cleaned) > 100_000:
                continue
            if not name.isupper() or len(name) < 3:
                continue
            entries = [part.strip() for part in cleaned.split(",") if part.strip()]
            preview = ", ".join(entries[:5])
            helper_structures.append(
                {
                    "name": name,
                    "entry_count": len(entries),
                    "preview": preview[:200],
                }
            )
            if name not in helper_dump:
                helper_dump[name] = cleaned

        if helper_structures:
            LOG.info(
                "Discovered %d helper structure definition(s) in bootstrapper", len(helper_structures)
            )

        dispatch_map = {f"0x{opcode:02X}": mnemonic for opcode, mnemonic in dispatch_items}

        extraction: Dict[str, object] = {
            "alphabet": {
                "value": alphabet,
                "length": len(alphabet) if alphabet else 0,
                "source": "bootstrapper" if alphabet else "default",
            },
            "opcode_dispatch": {
                "count": dispatch_count,
                "mapping": dispatch_map,
            },
            "named_opcode_map": dict(sorted(mapping.items())),
            "constants": constants,
            "helper_structures": helper_structures,
        }

        if warnings:
            extraction["warnings"] = list(warnings)

        if debug:
            raw_matches.setdefault("helper_structures", [
                {"name": name, "body": text} for name, text in helper_dump.items()
            ])
            extraction["raw_matches"] = raw_matches

        summary: Dict[str, object] = {
            "path": str(self.path),
            "opcode_table_entries": dispatch_count,
            "extraction": extraction,
        }
        if alphabet:
            summary["alphabet_length"] = len(alphabet)
        if mapping:
            summary["opcode_map_entries"] = len(mapping)
        if constants:
            summary["constant_entries"] = len(constants)
        if helper_structures:
            summary["helper_structures"] = [entry["name"] for entry in helper_structures]
        if warnings:
            summary["warnings"] = list(warnings)

        for key, value in summary.items():
            if key == "extraction":
                continue
            if value is not None:
                self.metadata.setdefault(key, value)
        self.metadata["extraction"] = extraction

        if debug and raw_matches:
            dump_payload = {
                "path": str(self.path),
                "raw_matches": raw_matches,
                "warnings": warnings,
                "opcode_preview": [
                    {"opcode": f"0x{opcode:02X}", "mnemonic": mnemonic}
                    for opcode, mnemonic in dispatch_items[:10]
                ],
            }
            if debug_log is not None:
                try:
                    log_path = Path(debug_log)
                except TypeError:
                    log_path = None
                if log_path is not None:
                    try:
                        log_path.parent.mkdir(parents=True, exist_ok=True)
                        log_path.write_text(
                            json.dumps(dump_payload, indent=2, sort_keys=True),
                            encoding="utf-8",
                        )
                    except Exception:  # pragma: no cover - best effort
                        LOG.debug("Failed to write bootstrap debug log to %s", log_path, exc_info=True)

        return alphabet, mapping, table, summary

    # ------------------------------------------------------------------
    def iter_metadata(self) -> Iterator[Tuple[str, object]]:
        yield from self.metadata.items()


__all__ = ["InitV4Bootstrap"]

from .luraph_v14_4_initv4 import InitV4Decoder  # noqa: E402,F401

__all__.append("InitV4Decoder")

