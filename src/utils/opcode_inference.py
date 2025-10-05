"""Opcode inference helpers for ``unpackedData`` tables."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Sequence

from .luraph_vm import canonicalise_opcode_name, rebuild_vm_bytecode

DEFAULT_OPCODE_NAMES: Dict[int, str] = {
    0: "MOVE",
    1: "LOADK",
    2: "LOADBOOL",
    3: "LOADNIL",
    4: "GETUPVAL",
    5: "GETGLOBAL",
    6: "GETTABLE",
    7: "SETGLOBAL",
    8: "SETUPVAL",
    9: "SETTABLE",
    10: "NEWTABLE",
    11: "SELF",
    12: "ADD",
    13: "SUB",
    14: "MUL",
    15: "DIV",
    16: "MOD",
    17: "POW",
    18: "UNM",
    19: "NOT",
    20: "LEN",
    21: "CONCAT",
    22: "JMP",
    23: "EQ",
    24: "LT",
    25: "LE",
    26: "TEST",
    27: "TESTSET",
    28: "CALL",
    29: "TAILCALL",
    30: "RETURN",
    31: "FORLOOP",
    32: "FORPREP",
    33: "TFORLOOP",
    34: "SETLIST",
    35: "CLOSE",
    36: "CLOSURE",
    37: "VARARG",
}

_METADATA_KEYS: Sequence[str] = (
    "opcode_map",
    "opcode_dispatch",
    "opcode_table",
    "named_opcode_map",
    "opcodeLookup",
    "opcode_lookup",
)


def _coerce_opcode(value: Any) -> int | None:
    if isinstance(value, int):
        return value & 0x3F
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.lower().startswith("0x"):
                return int(text, 16) & 0x3F
            return int(text, 10) & 0x3F
        except ValueError:
            return None
    return None


def _normalise_opcode_entries(candidate: Any) -> Dict[int, str]:
    normalised: Dict[int, str] = {}

    if isinstance(candidate, Mapping):
        mapping: MutableMapping[Any, Any] = dict(candidate)
        array = mapping.get("array")
        nested_map = mapping.get("map")
        if isinstance(nested_map, Mapping):
            mapping = dict(nested_map)
        elif isinstance(array, Sequence):
            for index, item in enumerate(array):
                name = None
                if isinstance(item, str):
                    name = item
                elif isinstance(item, Mapping):
                    name = (
                        item.get("mnemonic")
                        or item.get("name")
                        or item.get("op")
                        or item.get("value")
                    )
                if name:
                    normalised[index] = name
            return normalised

        for key, value in mapping.items():
            opcode = _coerce_opcode(key)
            if opcode is None:
                continue
            name = None
            if isinstance(value, str):
                name = value
            elif isinstance(value, Mapping):
                name = (
                    value.get("mnemonic")
                    or value.get("name")
                    or value.get("op")
                    or value.get("value")
                )
            elif isinstance(value, Sequence):
                if value and isinstance(value[0], str):
                    name = value[0]
            if name:
                normalised[opcode] = name
        return normalised

    if isinstance(candidate, Sequence) and not isinstance(candidate, (bytes, bytearray, str)):
        for index, item in enumerate(candidate):
            name = None
            if isinstance(item, str):
                name = item
            elif isinstance(item, Mapping):
                name = (
                    item.get("mnemonic")
                    or item.get("name")
                    or item.get("op")
                    or item.get("value")
                )
            if name:
                normalised[index] = name
    return normalised


def _opcode_map_from_metadata(
    metadata: Mapping[str, object] | Sequence[object] | None,
) -> Dict[int, str]:
    if metadata is None:
        return {}

    found: Dict[int, str] = {}
    stack: list[Any] = [metadata]
    seen: set[int] = set()

    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            for key in _METADATA_KEYS:
                if key in item and id(item[key]) not in seen:
                    seen.add(id(item[key]))
                    mapping = _normalise_opcode_entries(item[key])
                    if mapping:
                        for opcode, name in mapping.items():
                            canonical = canonicalise_opcode_name(name)
                            if canonical:
                                found[opcode] = canonical
            stack.extend(item.values())
        elif isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray, str)):
            stack.extend(item)

    return found


def _normalise_instruction(instr: Mapping[str, object] | Sequence[object]) -> Dict[str, int]:
    if isinstance(instr, Mapping):
        sequence = instr.get("array") if "array" in instr else None
        if isinstance(sequence, Sequence):
            opnum = sequence[2] if len(sequence) > 2 else None
            a = sequence[5] if len(sequence) > 5 else None
            b = sequence[6] if len(sequence) > 6 else None
            c = sequence[7] if len(sequence) > 7 else None
        else:
            opnum = instr.get("opnum")
            if opnum is None:
                opnum = instr.get("opcode")
            if opnum is None:
                opnum = instr.get(3)
            a = instr.get("A")
            if a is None:
                a = instr.get(6)
            b = instr.get("B")
            if b is None:
                b = instr.get(7)
            c = instr.get("C")
            if c is None:
                c = instr.get(8)
    else:
        opnum = instr[2] if len(instr) > 2 else None
        a = instr[5] if len(instr) > 5 else None
        b = instr[6] if len(instr) > 6 else None
        c = instr[7] if len(instr) > 7 else None
    return {
        "opnum": int(opnum) if opnum is not None else -1,
        "A": int(a) if a is not None else 0,
        "B": int(b) if b is not None else 0,
        "C": int(c) if c is not None else 0,
    }


def _score_candidates(features: Dict[str, int]) -> Dict[str, float]:
    scores: Dict[str, float] = defaultdict(float)
    a = features.get("A", 0)
    b = features.get("B", 0)
    c = features.get("C", 0)
    if b and not c:
        scores["MOVE"] += 1.0
        scores["LOADK"] += 0.8
    if b and c:
        scores["ADD"] += 0.5
        scores["SUB"] += 0.5
        scores["MUL"] += 0.5
        scores["DIV"] += 0.5
        scores["CALL"] += 1.2
        scores["GETTABLE"] += 0.4
    if (b or 0) == 0 and (c or 0) == 0:
        if a:
            scores["LOADK"] += 1.5
        else:
            scores["RETURN"] += 1.5
    return scores


def infer_opcode_map(
    unpacked: Mapping[str, object] | Sequence[object],
    *,
    bootstrap_metadata: Mapping[str, object] | None = None,
) -> Dict[int, str]:
    """Return a best-effort mapping of opcode numbers to Lua 5.1 mnemonics."""

    metadata_map = _opcode_map_from_metadata(bootstrap_metadata)
    if not metadata_map:
        metadata_map = _opcode_map_from_metadata(unpacked)
    if metadata_map:
        return metadata_map

    try:
        rebuild = rebuild_vm_bytecode(unpacked)
        instructions: Iterable[Mapping[str, object]] = rebuild.instructions
    except Exception:  # pragma: no cover - defensive
        return dict(DEFAULT_OPCODE_NAMES)

    inferred: Dict[int, str] = {}
    for instr in instructions:
        features = _normalise_instruction(instr)
        opnum = features["opnum"]
        if opnum in inferred:
            continue
        scores = _score_candidates(features)
        if not scores:
            continue
        name = max(scores.items(), key=lambda item: item[1])[0]
        canonical = canonicalise_opcode_name(name)
        if canonical:
            inferred[opnum] = canonical
    return inferred


__all__ = ["infer_opcode_map", "DEFAULT_OPCODE_NAMES"]

