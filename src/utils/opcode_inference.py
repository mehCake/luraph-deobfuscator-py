"""Opcode inference helpers for ``unpackedData`` tables."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, Mapping, Sequence

from .luraph_vm import rebuild_vm_bytecode

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


def _normalise_instruction(instr: Mapping[str, object] | Sequence[object]) -> Dict[str, int]:
    if isinstance(instr, Mapping):
        opnum = instr.get("opnum") or instr.get("opcode") or instr.get(3)
        a = instr.get("A") or instr.get(6) or 0
        b = instr.get("B") or instr.get(7)
        c = instr.get("C") or instr.get(8)
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
    if features.get("opnum", -1) in DEFAULT_OPCODE_NAMES:
        scores[DEFAULT_OPCODE_NAMES[features["opnum"]]] += 5.0
    return scores


def infer_opcode_map(unpacked: Mapping[str, object] | Sequence[object]) -> Dict[int, str]:
    """Return a best-effort mapping of opcode numbers to Lua 5.1 mnemonics."""

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
        if opnum in DEFAULT_OPCODE_NAMES:
            inferred[opnum] = DEFAULT_OPCODE_NAMES[opnum]
            continue
        scores = _score_candidates(features)
        if not scores:
            continue
        name = max(scores.items(), key=lambda item: item[1])[0]
        inferred[opnum] = name
    return inferred


__all__ = ["infer_opcode_map", "DEFAULT_OPCODE_NAMES"]

