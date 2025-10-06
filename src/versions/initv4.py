"""Helpers for parsing Luraph ``initv4`` bootstrap stubs."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from src.utils import write_json
from src.vm.opcode_utils import opcode_table_merge

from . import OpSpec
from .luraph_v14_2_json import LuraphV142JSON
from ..bootstrap_extractor import BootstrapExtractor, BootstrapParser

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


def _is_identifier_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _matches_keyword(text: str, index: int, keyword: str) -> bool:
    end = index + len(keyword)
    if end > len(text) or text[index:end] != keyword:
        return False
    if index > 0 and _is_identifier_char(text[index - 1]):
        return False
    if end < len(text) and _is_identifier_char(text[end]):
        return False
    return True


def _skip_string_literal(text: str, index: int) -> int:
    quote = text[index]
    index += 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            index += 1
            break
        index += 1
    return index


def _skip_long_bracket(text: str, index: int) -> int:
    start = index
    index += 1
    equals = 0
    while index < len(text) and text[index] == "=":
        equals += 1
        index += 1
    if index >= len(text) or text[index] != "[":
        return start + 1
    closing = "]" + "=" * equals + "]"
    index += 1
    end_index = text.find(closing, index)
    if end_index == -1:
        return len(text)
    return end_index + len(closing)


def _skip_comment(text: str, index: int) -> int:
    if index + 1 < len(text) and text[index + 1] == "-":
        index += 2
        if index < len(text) and text[index] == "[":
            return _skip_long_bracket(text, index)
        while index < len(text) and text[index] not in "\n\r":
            index += 1
        return index
    return index + 1


def _consume_lua_block(text: str, start: int) -> int:
    depth = 1
    index = start
    length = len(text)
    repeat_stack: List[str] = []
    while index < length:
        char = text[index]
        if char in {"'", '"'}:
            index = _skip_string_literal(text, index)
            continue
        if char == "-" and index + 1 < length and text[index + 1] == "-":
            index = _skip_comment(text, index)
            continue
        if char == "[":
            peek = text[index:index + 2]
            if peek == "[[" or peek == "[=" or (len(peek) == 2 and peek[1] == "="):
                index = _skip_long_bracket(text, index)
                continue
        if _matches_keyword(text, index, "function"):
            depth += 1
            index += len("function")
            continue
        if _matches_keyword(text, index, "if"):
            depth += 1
            index += len("if")
            continue
        if _matches_keyword(text, index, "for"):
            depth += 1
            index += len("for")
            continue
        if _matches_keyword(text, index, "while"):
            depth += 1
            index += len("while")
            continue
        if _matches_keyword(text, index, "do"):
            depth += 1
            index += len("do")
            continue
        if _matches_keyword(text, index, "repeat"):
            repeat_stack.append("repeat")
            index += len("repeat")
            continue
        if _matches_keyword(text, index, "until"):
            if repeat_stack:
                repeat_stack.pop()
            index += len("until")
            continue
        if _matches_keyword(text, index, "end"):
            depth -= 1
            index += len("end")
            if depth <= 0 and not repeat_stack:
                return index
            continue
        index += 1
    return length


def _skip_horizontal_whitespace(text: str, index: int, limit: int | None = None) -> int:
    if limit is None:
        limit = len(text)
    while index < limit and text[index] in {" ", "\t"}:
        index += 1
    return index


def _skip_whitespace(text: str, index: int, limit: int | None = None) -> int:
    if limit is None:
        limit = len(text)
    while index < limit and text[index] in {" ", "\t", "\r", "\n"}:
        index += 1
    return index


def _read_line(text: str, index: int, limit: int | None = None) -> Tuple[str, int]:
    if limit is None:
        limit = len(text)
    end = text.find("\n", index, limit)
    if end == -1:
        end = limit
    return text[index:end], end


def _read_string_literal(text: str, index: int, limit: int | None = None) -> Tuple[str, int]:
    if limit is None:
        limit = len(text)
    quote = text[index]
    index += 1
    value: List[str] = []
    while index < limit:
        char = text[index]
        if char == "\\" and index + 1 < limit:
            value.append(text[index + 1])
            index += 2
            continue
        if char == quote:
            index += 1
            break
        value.append(char)
        index += 1
    return "".join(value), index


def _line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _operand_model(mnemonic: Optional[str]) -> Optional[str]:
    if not mnemonic:
        return None
    name = mnemonic.upper()
    if name in {"LOADK", "LOADKX", "GETGLOBAL", "SETGLOBAL", "CLOSURE", "EXTRAARG"}:
        return "A,Bx"
    return "A,B,C"


def _infer_mnemonic(body: str) -> Optional[str]:
    checks = [
        ("ADD", re.compile(r"\+")),
        ("SUB", re.compile(r"-")),
        ("MUL", re.compile(r"\*")),
        ("DIV", re.compile(r"/")),
        ("EQ", re.compile(r"==")),
        ("LT", re.compile(r"<")),
        ("LE", re.compile(r"<=")),
    ]
    for name, pattern in checks:
        if pattern.search(body):
            return name
    return None


def _find_table_blocks(text: str, name: str) -> List[Tuple[int, int]]:
    pattern = re.compile(rf"\b{name}\s*=\s*{{")
    blocks: List[Tuple[int, int]] = []
    for match in pattern.finditer(text):
        start = match.end()
        index = start
        depth = 1
        while index < len(text):
            char = text[index]
            if char in {"'", '"'}:
                index = _skip_string_literal(text, index)
                continue
            if char == "-" and index + 1 < len(text) and text[index + 1] == "-":
                index = _skip_comment(text, index)
                continue
            if char == "[":
                peek = text[index:index + 2]
                if peek == "[[" or peek == "[=" or (len(peek) == 2 and peek[1] == "="):
                    index = _skip_long_bracket(text, index)
                    continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((start, index))
                    break
            index += 1
    return blocks


def _merge_dispatch_entry(target: MutableMapping[int, Dict[str, object]], opcode: int, entry: Dict[str, object]) -> None:
    existing = target.get(opcode)
    if existing is None:
        target[opcode] = dict(entry)
        return
    for key in ("table", "handler", "mnemonic", "comment", "body_preview"):
        value = entry.get(key)
        if value and not existing.get(key):
            existing[key] = value
    params = entry.get("params")
    if isinstance(params, int) and params > 0:
        if not isinstance(existing.get("params"), int) or existing.get("params", 0) <= 0:
            existing["params"] = params
    bytecode_len = entry.get("bytecode_length")
    if isinstance(bytecode_len, int):
        current = existing.get("bytecode_length")
        if not isinstance(current, int) or bytecode_len > current:
            existing["bytecode_length"] = bytecode_len
    if "line" not in existing and "line" in entry:
        existing["line"] = entry["line"]


def _parse_function_value(text: str, start: int, limit: int) -> Tuple[Dict[str, object], int]:
    cursor = start + len("function")
    cursor = _skip_whitespace(text, cursor, limit)
    func_name: Optional[str] = None
    if cursor < limit and text[cursor] != "(":
        name_start = cursor
        while cursor < limit and text[cursor] not in {"(", "\n", "\r"}:
            cursor += 1
        func_name = text[name_start:cursor].strip() or None
    cursor = _skip_whitespace(text, cursor, limit)
    params_text = ""
    if cursor < limit and text[cursor] == "(":
        depth = 1
        cursor += 1
        param_start = cursor
        while cursor < limit and depth > 0:
            char = text[cursor]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    params_text = text[param_start:cursor]
                    cursor += 1
                    break
            elif char in {"'", '"'}:
                cursor = _skip_string_literal(text, cursor)
                continue
            cursor += 1
    body_start = cursor
    comment_text = None
    trailing = _skip_horizontal_whitespace(text, body_start, limit)
    if trailing < limit and text[trailing:trailing + 2] == "--":
        captured, comment_end = _read_line(text, trailing + 2, limit)
        comment_text = captured.strip()
        body_start = _skip_whitespace(text, comment_end, limit)
    else:
        body_start = _skip_whitespace(text, body_start, limit)
    end_index = _consume_lua_block(text, body_start)
    body_end = max(body_start, end_index - len("end"))
    body_text = text[body_start:body_end].rstrip()
    param_count = len([item for item in params_text.split(",") if item.strip()])
    preview_lines = [line.strip() for line in body_text.splitlines() if line.strip()]
    preview = "\n".join(preview_lines[:3])
    entry: Dict[str, object] = {
        "handler": func_name or "inline",
        "params": param_count,
        "bytecode_length": len(body_text.encode("utf-8")),
    }
    if preview:
        entry["body_preview"] = preview
    mnemonic = _infer_mnemonic(body_text)
    if mnemonic:
        entry["mnemonic"] = mnemonic
    if comment_text:
        entry["comment"] = comment_text
        if not entry.get("mnemonic"):
            entry["mnemonic"] = comment_text.split()[0].upper()
    return entry, end_index


def _parse_dispatch_value(text: str, start: int, limit: int) -> Tuple[Dict[str, object], int]:
    index = _skip_whitespace(text, start, limit)
    entry: Dict[str, object] = {
        "handler": None,
        "mnemonic": None,
        "params": 0,
        "bytecode_length": 0,
    }
    if index >= limit:
        return entry, index
    char = text[index]
    if char in {"'", '"'}:
        literal, new_pos = _read_string_literal(text, index, limit)
        entry["mnemonic"] = literal.strip().upper()
        return entry, new_pos
    if text.startswith("function", index):
        func_entry, new_pos = _parse_function_value(text, index, limit)
        entry.update(func_entry)
        return entry, new_pos
    expr_start = index
    while index < limit:
        char = text[index]
        if char in {",", "\n", "\r", "}"}:
            break
        if char == "-" and text[index:index + 2] == "--":
            break
        index += 1
    expression = text[expr_start:index].strip()
    if expression:
        entry["handler"] = expression
    mnemonic = _infer_mnemonic(expression)
    if mnemonic and not entry.get("mnemonic"):
        entry["mnemonic"] = mnemonic
    return entry, index


def _parse_dispatch_block(
    store: MutableMapping[int, Dict[str, object]],
    text: str,
    start: int,
    end: int,
    table_name: str,
) -> None:
    index = start
    while index < end:
        char = text[index]
        if char in {" ", "\t", "\r", "\n", ","}:
            index += 1
            continue
        if char != "[":
            index += 1
            continue
        closing = text.find("]", index, end)
        if closing == -1:
            break
        key = text[index + 1 : closing].strip()
        try:
            opcode = _to_int(key)
        except Exception:
            index = closing + 1
            continue
        index = closing + 1
        index = _skip_whitespace(text, index, end)
        if index >= end or text[index] != "=":
            continue
        index += 1
        value_entry, next_index = _parse_dispatch_value(text, index, end)
        comment = None
        comment_index = _skip_horizontal_whitespace(text, next_index, end)
        if comment_index < end and text[comment_index] == ",":
            comment_index += 1
        comment_index = _skip_horizontal_whitespace(text, comment_index, end)
        if comment_index < end and text[comment_index:comment_index + 2] == "--":
            comment_text, line_end = _read_line(text, comment_index + 2, end)
            comment = comment_text.strip()
            index = line_end
        else:
            index = comment_index
        index = _skip_whitespace(text, index, end)
        if comment and not value_entry.get("comment"):
            value_entry["comment"] = comment
        if not value_entry.get("mnemonic") and comment:
            value_entry["mnemonic"] = comment.split()[0].upper()
        value_entry.setdefault("table", table_name)
        value_entry.setdefault("line", _line_number(text, index))
        if value_entry.get("mnemonic"):
            value_entry["mnemonic"] = str(value_entry["mnemonic"]).upper()
        if "body_preview" in value_entry and not value_entry.get("mnemonic"):
            inferred = _infer_mnemonic(value_entry["body_preview"])
            if inferred:
                value_entry["mnemonic"] = inferred
        _merge_dispatch_entry(store, opcode, value_entry)


def _parse_dispatch_assignments(
    store: MutableMapping[int, Dict[str, object]],
    text: str,
    table_names: Iterable[str],
    skip_ranges: Sequence[Tuple[int, int]],
) -> None:
    table_pattern = "|".join(re.escape(name) for name in table_names)
    pattern = re.compile(rf"({table_pattern})\s*\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]\s*=")
    limit = len(text)
    for match in pattern.finditer(text):
        start = match.start()
        if any(block_start <= start <= block_end for block_start, block_end in skip_ranges):
            continue
        table = match.group(1)
        opcode = _to_int(match.group(2))
        value_entry, next_index = _parse_dispatch_value(text, match.end(), limit)
        comment = None
        comment_index = _skip_horizontal_whitespace(text, next_index, limit)
        if comment_index < limit and text[comment_index] == ",":
            comment_index += 1
        comment_index = _skip_horizontal_whitespace(text, comment_index, limit)
        if comment_index < limit and text[comment_index:comment_index + 2] == "--":
            comment_text, line_end = _read_line(text, comment_index + 2, limit)
            comment = comment_text.strip()
            next_index = line_end
        else:
            next_index = comment_index
        if comment and not value_entry.get("comment"):
            value_entry["comment"] = comment
        if not value_entry.get("mnemonic") and comment:
            value_entry["mnemonic"] = comment.split()[0].upper()
        value_entry.setdefault("table", table)
        value_entry.setdefault("line", _line_number(text, match.start()))
        if value_entry.get("mnemonic"):
            value_entry["mnemonic"] = str(value_entry["mnemonic"]).upper()
        if "body_preview" in value_entry and not value_entry.get("mnemonic"):
            inferred = _infer_mnemonic(value_entry["body_preview"])
            if inferred:
                value_entry["mnemonic"] = inferred
        _merge_dispatch_entry(store, opcode, value_entry)


def _parse_dispatch_tables(text: str) -> List[Dict[str, object]]:
    entries: MutableMapping[int, Dict[str, object]] = {}
    processed_ranges: List[Tuple[int, int]] = []
    for table_name in ("dispatch", "opcode_map"):
        blocks = _find_table_blocks(text, table_name)
        processed_ranges.extend(blocks)
        for start, end in blocks:
            _parse_dispatch_block(entries, text, start, end, table_name)
    _parse_dispatch_assignments(entries, text, ("dispatch", "case_dispatch", "opcode_map"), processed_ranges)
    result: List[Dict[str, object]] = []
    for opcode in sorted(entries):
        entry = entries[opcode]
        mnemonic = entry.get("mnemonic")
        if isinstance(mnemonic, str):
            entry["mnemonic"] = mnemonic.upper()
        operands = _operand_model(entry.get("mnemonic"))
        if operands:
            entry["operands"] = operands
        entry.setdefault("params", 0)
        entry.setdefault("bytecode_length", 0)
        entry.setdefault("handler", None)
        entry.setdefault("line", _line_number(text, 0))
        entry["opcode"] = opcode
        entry["opcode_hex"] = f"0x{opcode:02X}"
        result.append(dict(entry))
    return result

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
        opcode_entries: List[Dict[str, object]] = []
        detail_lookup: Dict[int, Dict[str, object]] = {}
        trusted_high = 0
        merged_canonical: Dict[int, Dict[str, object]] = {}

        parser_result = None
        try:
            parser = BootstrapParser()
            parser_result = parser.parse(self.text)
        except Exception:  # pragma: no cover - defensive
            LOG.debug("Bootstrap parser failed", exc_info=True)

        if parser_result and parser_result.opcode_table:
            for opcode, handler in sorted(parser_result.opcode_table.items()):
                mnemonic = handler.mnemonic.upper()
                operands_value = handler.operands or ""
                if operands_value:
                    operand_tuple = tuple(
                        part.strip()
                        for part in re.split(r"[\s,]+", operands_value)
                        if part.strip()
                    )
                else:
                    operand_tuple = ()
                existing = table.get(opcode)
                if existing is None or existing.mnemonic.upper() != mnemonic or (
                    operand_tuple and existing and operand_tuple != existing.operands
                ):
                    table[opcode] = OpSpec(mnemonic, operand_tuple or (existing.operands if existing else ()))

                entry = {
                    "opcode": opcode,
                    "opcode_hex": f"0x{opcode:02X}",
                    "mnemonic": mnemonic,
                    "operands": operands_value,
                    "trust": handler.trust,
                    "offset": handler.offset,
                    "keyword_counts": dict(sorted(handler.keyword_counts.items())),
                    "source_snippet": handler.source_snippet,
                }
                opcode_entries.append(entry)
            merged_canonical = opcode_table_merge(parser_result.opcode_table, table)
            if merged_canonical:
                for opcode, info in merged_canonical.items():
                    mnemonic_value = info.get("mnemonic")
                    if not isinstance(mnemonic_value, str) or not mnemonic_value:
                        continue
                    operands_value = info.get("operands")
                    if isinstance(operands_value, str):
                        operand_tuple = tuple(part for part in operands_value.split() if part)
                    elif isinstance(operands_value, (list, tuple)):
                        operand_tuple = tuple(str(part) for part in operands_value if str(part))
                    else:
                        operand_tuple = ()
                    existing = table.get(opcode)
                    existing_operands = existing.operands if existing else ()
                    description = existing.description if existing else None
                    table[opcode] = OpSpec(
                        mnemonic_value,
                        operand_tuple or existing_operands,
                        description,
                    )
            detail_lookup = {entry["opcode"]: entry for entry in opcode_entries}
            trusted_high = sum(1 for entry in opcode_entries if entry.get("trust") == "high")
        else:
            fallback_details = _parse_dispatch_tables(self.text)
            for entry in fallback_details:
                opcode = entry.get("opcode")
                if not isinstance(opcode, int):
                    continue
                mnemonic = entry.get("mnemonic")
                if not isinstance(mnemonic, str) or not mnemonic:
                    continue
                operands_value = entry.get("operands")
                operand_tuple: Tuple[str, ...] = ()
                if isinstance(operands_value, str):
                    operand_tuple = tuple(
                        part.strip()
                        for part in re.split(r"[\s,]+", operands_value)
                        if part.strip()
                    )
                elif isinstance(operands_value, (list, tuple)):
                    operand_tuple = tuple(str(part) for part in operands_value if str(part))
                existing = table.get(opcode)
                if existing is None or existing.mnemonic.upper() != mnemonic.upper() or (
                    operand_tuple and existing and operand_tuple != existing.operands
                ):
                    table[opcode] = OpSpec(mnemonic.upper(), operand_tuple or (existing.operands if existing else ()))
                normalised_entry = dict(entry)
                normalised_entry.setdefault("opcode_hex", f"0x{opcode:02X}")
                opcode_entries.append(normalised_entry)
            detail_lookup = {
                entry["opcode"]: entry
                for entry in opcode_entries
                if isinstance(entry.get("opcode"), int)
            }
            trusted_high = sum(1 for entry in opcode_entries if entry.get("trust") == "high")

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
        if opcode_entries:
            for opcode, detail in detail_lookup.items():
                mnemonic = detail.get("mnemonic")
                if isinstance(mnemonic, str) and mnemonic:
                    dispatch_map[f"0x{opcode:02X}"] = mnemonic

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

        canonical_entries: List[Dict[str, object]] = []
        if merged_canonical:
            for opcode, info in sorted(merged_canonical.items()):
                canonical_entries.append(
                    {
                        "opcode": opcode,
                        "opcode_hex": f"0x{opcode:02X}",
                        "mnemonic": info.get("mnemonic"),
                        "operands": info.get("operands"),
                        "trust": info.get("trust"),
                        "source": info.get("source"),
                    }
                )

        if opcode_entries:
            extraction["opcode_table"] = {
                "count": len(opcode_entries),
                "trusted": trusted_high >= 30,
                "trusted_entries": trusted_high,
                "entries": opcode_entries,
            }
            if canonical_entries:
                extraction["opcode_table"]["canonical_entries"] = canonical_entries
        elif canonical_entries:
            extraction["opcode_table"] = {
                "count": len(canonical_entries),
                "trusted": trusted_high >= 30,
                "trusted_entries": trusted_high,
                "canonical_entries": canonical_entries,
            }

        if warnings:
            extraction["warnings"] = list(warnings)

        if debug:
            raw_matches.setdefault("helper_structures", [
                {"name": name, "body": text} for name, text in helper_dump.items()
            ])
            extraction["raw_matches"] = raw_matches

        detail_count = len(opcode_entries)
        summary: Dict[str, object] = {
            "path": str(self.path),
            "opcode_table_entries": detail_count or dispatch_count,
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
        if opcode_entries:
            summary["opcode_table_trusted"] = trusted_high >= 30
        if warnings:
            summary["warnings"] = list(warnings)

        for key, value in summary.items():
            if key == "extraction":
                continue
            if value is not None:
                self.metadata.setdefault(key, value)
        self.metadata["extraction"] = extraction
        if opcode_entries:
            table_meta = self.metadata.setdefault(
                "opcode_table",
                {
                    "count": detail_count,
                    "trusted": trusted_high >= 30,
                    "trusted_entries": trusted_high,
                },
            )
            if isinstance(table_meta, dict):
                table_meta.setdefault("entries", opcode_entries)
                if canonical_entries:
                    table_meta.setdefault("canonical_entries", canonical_entries)
        elif canonical_entries:
            table_meta = self.metadata.setdefault(
                "opcode_table",
                {
                    "count": len(canonical_entries),
                    "trusted": trusted_high >= 30,
                    "trusted_entries": trusted_high,
                },
            )
            if isinstance(table_meta, dict):
                table_meta.setdefault("canonical_entries", canonical_entries)

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
                        write_json(
                            log_path,
                            dump_payload,
                            sort_keys=True,
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

