"""Utilities for canonicalising VM opcode metadata."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import for type checking only
    from src.bootstrap_extractor.bootstrap_parser import OpcodeHandler
    from src.versions import OpSpec

from .opcode_constants import is_mandatory_mnemonic, normalise_trust, trust_score

__all__ = [
    "normalize_mnemonic",
    "normalize_operand_model",
    "operand_model_from_handler",
    "opcode_table_merge",
]


# Canonical Lua 5.1 mnemonics and the textual forms frequently encountered in
# bootstrappers or metadata comments.  The lookup uses sanitised (alphanumeric)
# strings so callers can pass values containing punctuation or mixed case.
_MNEMONIC_SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "MOVE": ("MOVE", "MOV", "COPY", "SETREG"),
    "LOADK": ("LOADK", "LOADCONST", "LOAD_CONST", "PUSHK", "PUSHCONST"),
    "LOADBOOL": ("LOADBOOL", "LOADB", "LOAD_BOOL"),
    "LOADNIL": ("LOADNIL", "LOAD_NIL"),
    "GETUPVAL": ("GETUPVAL", "GET_UPVAL", "GETUPVALUE"),
    "SETUPVAL": ("SETUPVAL", "SET_UPVAL", "SETUPVALUE"),
    "GETGLOBAL": ("GETGLOBAL", "GET_GLOBAL"),
    "SETGLOBAL": ("SETGLOBAL", "SET_GLOBAL"),
    "GETTABLE": ("GETTABLE", "GET_TABLE", "INDEX", "TABLEGET"),
    "SETTABLE": ("SETTABLE", "SET_TABLE", "TABLESET"),
    "NEWTABLE": ("NEWTABLE", "NEW_TABLE", "MAKETABLE"),
    "SELF": ("SELF", "SELFIDX"),
    "ADD": ("ADD", "PLUS", "SUM"),
    "SUB": ("SUB", "MINUS"),
    "MUL": ("MUL", "MULT"),
    "DIV": ("DIV", "DIVIDE"),
    "MOD": ("MOD", "MODULO"),
    "POW": ("POW", "POWER"),
    "UNM": ("UNM", "NEG", "NEGATE"),
    "NOT": ("NOT", "LOGNOT"),
    "LEN": ("LEN", "LENGTH"),
    "CONCAT": ("CONCAT", "CONCATENATE"),
    "JMP": ("JMP", "JUMP"),
    "EQ": ("EQ", "ISEQ", "ISEQUAL"),
    "LT": ("LT", "LESS"),
    "LE": ("LE", "LESSEQ", "LTE"),
    "TEST": ("TEST", "CHK"),
    "TESTSET": ("TESTSET", "TEST_SET"),
    "CALL": ("CALL", "INVOKE", "CALLFN", "CALLFUNC"),
    "TAILCALL": ("TAILCALL", "TAIL_CALL"),
    "RETURN": ("RETURN", "RET", "RETURNA"),
    "FORLOOP": ("FORLOOP", "FOR_LOOP"),
    "FORPREP": ("FORPREP", "FOR_PREP"),
    "TFORLOOP": ("TFORLOOP", "T_FORLOOP"),
    "SETLIST": ("SETLIST", "SET_LIST"),
    "CLOSE": ("CLOSE", "CLOSEUP", "CLOSE_UP"),
    "CLOSURE": ("CLOSURE", "MAKECLOSURE"),
    "VARARG": ("VARARG", "VAR_ARG", "VARIADIC"),
}

_CANONICAL_MNEMONICS = tuple(_MNEMONIC_SYNONYMS.keys())


def _sanitize(text: str | None) -> str:
    if not text:
        return ""
    return re.sub(r"[^A-Z0-9]", "", str(text).upper())


def normalize_mnemonic(mnemonic: str | None) -> str:
    """Return the canonical Lua 5.1 mnemonic for *mnemonic*."""

    cleaned = _sanitize(mnemonic)
    if not cleaned:
        return ""

    for canonical, variants in _MNEMONIC_SYNONYMS.items():
        for variant in variants:
            alias = _sanitize(variant)
            if alias and cleaned == alias:
                return canonical

    for canonical, variants in _MNEMONIC_SYNONYMS.items():
        canonical_key = _sanitize(canonical)
        if canonical_key and cleaned == canonical_key:
            return canonical
        for variant in variants:
            alias = _sanitize(variant)
            if alias and alias in cleaned:
                return canonical

    return cleaned


def _expand_operand_token(token: str) -> List[str]:
    upper = token.upper()
    mapping = {
        "ABX": ["A", "Bx"],
        "ASBX": ["A", "sBx"],
        "ABC": ["A", "B", "C"],
        "RK": ["RK"],
    }
    direct = mapping.get(upper)
    if direct:
        return direct.copy()
    alias_map = {
        "BX": "Bx",
        "SBX": "sBx",
        "AX": "Ax",
        "RA": "A",
        "RB": "B",
        "RC": "C",
        "RKB": "B",
        "RKC": "C",
    }
    converted = alias_map.get(upper)
    if converted:
        return [converted]
    return [token.strip()]


def _normalise_operand_model(value: Any) -> str:
    if value is None:
        return ""
    tokens: List[str]
    if isinstance(value, str):
        tokens = [part for part in re.split(r"[\s,]+", value) if part]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        tokens = [str(part) for part in value if str(part)]
    else:
        return str(value)

    expanded: List[str] = []
    for token in tokens:
        expanded.extend(_expand_operand_token(token))

    canonical: List[str] = []
    for token in expanded:
        stripped = token.strip()
        if not stripped:
            continue
        if stripped in canonical:
            continue
        canonical.append(stripped)
    return " ".join(canonical)


def normalize_operand_model(value: Any) -> str:
    """Public helper that normalises operand descriptors."""

    return _normalise_operand_model(value)


def operand_model_from_handler(source_snippet: str | None) -> Optional[str]:
    """Infer an operand model (``A B C``/``A Bx``/...) from *source_snippet*."""

    if not source_snippet:
        return None
    match = re.search(r"function\s*\(([^)]*)\)", source_snippet)
    if not match:
        return None
    raw_args = [part.strip() for part in match.group(1).split(",") if part.strip()]
    if len(raw_args) <= 1:
        return None

    operands = raw_args[1:]
    lowered = [arg.lower() for arg in operands]

    if any(name in {"sbx", "offset", "jmp", "jump"} for name in lowered):
        return _normalise_operand_model(["A", "sBx"] if len(operands) > 1 else ["sBx"])
    if any("bx" in name for name in lowered):
        base = ["A", "Bx"] if len(operands) > 1 else ["Bx"]
        return _normalise_operand_model(base)
    if len(operands) >= 3:
        return _normalise_operand_model(["A", "B", "C"])
    if len(operands) == 2:
        return _normalise_operand_model(["A", "B"])
    return _normalise_operand_model(["Ax"])


def opcode_table_merge(
    bootstrap_table: Mapping[int, "OpcodeHandler"] | None,
    heuristic_table: Mapping[int, "OpSpec"] | Mapping[int, Mapping[str, Any]] | None,
) -> Dict[int, Dict[str, Any]]:
    """Merge bootstrap-derived handlers with heuristic opcode specs."""

    merged: Dict[int, Dict[str, Any]] = {}

    def _entry(opcode: int) -> Dict[str, Any]:
        data = merged.setdefault(opcode, {"opcode": opcode})
        return data

    if heuristic_table:
        for opcode, spec in heuristic_table.items():
            entry = _entry(int(opcode))
            mnemonic: Optional[str]
            operands: Any
            trust_value = entry.get("trust")
            if hasattr(spec, "mnemonic"):
                mnemonic = getattr(spec, "mnemonic")
                operands = getattr(spec, "operands", ())
                mandatory = getattr(spec, "mandatory", False)
            elif isinstance(spec, Mapping):
                mnemonic = spec.get("mnemonic") or spec.get("op")
                operands = spec.get("operands")
                trust_value = spec.get("trust", trust_value)
                mandatory = bool(spec.get("mandatory"))
            else:
                mnemonic = str(spec)
                operands = None
                mandatory = False
            canonical = normalize_mnemonic(mnemonic)
            if canonical:
                entry["mnemonic"] = canonical
                entry["op"] = canonical
            operand_model = _normalise_operand_model(operands)
            if operand_model:
                entry["operands"] = operand_model
            label = normalise_trust(trust_value)
            entry.setdefault("trust", label)
            entry.setdefault("source", entry.get("source") or "heuristic")
            entry.setdefault("confidence", trust_score(label))
            if mandatory:
                entry["mandatory"] = True

    if bootstrap_table:
        for opcode, handler in bootstrap_table.items():
            entry = _entry(int(opcode))
            canonical = normalize_mnemonic(getattr(handler, "mnemonic", ""))
            operand_model = operand_model_from_handler(getattr(handler, "source_snippet", ""))
            if not operand_model:
                operand_model = _normalise_operand_model(getattr(handler, "operands", ""))
            handler_trust = normalise_trust(getattr(handler, "trust", ""))
            handler_confidence = trust_score(handler_trust)

            if handler_trust == "high" or "mnemonic" not in entry:
                if canonical:
                    entry["mnemonic"] = canonical
                    entry["op"] = canonical
            elif canonical and not entry.get("mnemonic"):
                entry["mnemonic"] = canonical
                entry["op"] = canonical

            existing_confidence = trust_score(entry.get("trust"))
            if handler_confidence >= existing_confidence:
                entry["trust"] = handler_trust or entry.get("trust") or "heuristic"
                entry["confidence"] = handler_confidence
                entry["source"] = "bootstrap"
            else:
                if canonical and not entry.get("mnemonic"):
                    entry["mnemonic"] = canonical
                    entry["op"] = canonical
                entry.setdefault("source", "bootstrap")
                if handler_trust and entry.get("trust", "heuristic") == "heuristic":
                    entry["trust"] = handler_trust
                    entry.setdefault("confidence", handler_confidence)

            if operand_model:
                if handler_trust == "high" or not entry.get("operands"):
                    entry["operands"] = operand_model
            if getattr(handler, "source_snippet", None):
                entry.setdefault("source_snippet", handler.source_snippet)

    for data in merged.values():
        data.setdefault("trust", "heuristic")
        data["trust"] = normalise_trust(data.get("trust"))
        data["confidence"] = trust_score(data.get("trust"))
        mnemonic_value = data.get("mnemonic")
        if mnemonic_value and is_mandatory_mnemonic(mnemonic_value):
            data["mandatory"] = True
        data.setdefault("mandatory", False)
        data.setdefault("source", "heuristic")

    return merged
