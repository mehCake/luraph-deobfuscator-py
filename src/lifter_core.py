"""Core lifting helpers for translating unpacked Luraph data to an IR.

This module provides a very small subset of the functionality required for
the full pipeline.  It parses the ``unpackedData`` structure emitted by the
bootstrapper, normalises the Lua-style tables into Python lists/dicts, builds
an intermediate representation (IR) for each instruction, and records some
lightweight statistics that downstream stages can use for heuristic opcode
identification.

The implementation intentionally keeps the heuristics conservative – the
verification stage is responsible for proving the opcode semantics.  The
lifter's job here is simply to expose enough structure for later tooling to
reason about.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, MutableMapping

# Opcodes for vanilla Lua 5.1 – used as suggestions when generating the
# candidate list.  The final verified opcode map is produced by
# ``opcode_verifier`` once it has executed its checks.
from src.versions.luraph_v14_4_1 import _BASE_OPCODE_TABLE


@dataclass
class InstructionIR:
    """Small container describing a single VM instruction."""

    pc: int
    opnum: int | None
    A: int | None
    B: int | None
    C: int | None
    Bx: int | None
    sBx: int | None
    raw: Any

    def as_dict(self) -> Dict[str, Any]:
        return {
            "pc": self.pc,
            "opnum": self.opnum,
            "A": self.A,
            "B": self.B,
            "C": self.C,
            "Bx": self.Bx,
            "sBx": self.sBx,
            "raw": self.raw,
        }


def _read_json(path: str | os.PathLike[str]) -> Any:
    with open(path, "rb") as handle:
        return json.load(handle)


def _normalise(value: Any) -> Any:
    """Collapse the ``array`` wrappers used by some Lua JSON encoders."""

    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, MutableMapping):
        # Typical pattern: {"array": [...]} – treat it as a positional list.
        if set(value.keys()) == {"array"} and isinstance(value["array"], list):
            return [_normalise(v) for v in value["array"]]
        return {k: _normalise(v) for k, v in value.items()}
    return value


def _lua_index(container: Any, index: int) -> Any:
    """Return the ``index``th element using Lua's 1-based indexing rules."""

    if isinstance(container, list):
        py_index = index - 1
        if 0 <= py_index < len(container):
            return container[py_index]
        return None
    if isinstance(container, MutableMapping):
        # Accept both string and integer keys for robustness.
        return container.get(str(index), container.get(index))
    return None


def _coerce_int(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _to_lua_literal(py: Any) -> str:
    """Convert a Python object into a compact Lua literal string."""

    if isinstance(py, str):
        escaped = py.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if isinstance(py, bool):
        return "true" if py else "false"
    if py is None:
        return "nil"
    if isinstance(py, (int, float)):
        return str(py)
    if isinstance(py, list):
        return "{" + ",".join(_to_lua_literal(v) for v in py) + "}"
    if isinstance(py, dict):
        parts: List[str] = []
        for key, val in py.items():
            if isinstance(key, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                parts.append(f"{key}={_to_lua_literal(val)}")
            else:
                parts.append(f"[{_to_lua_literal(key)}]={_to_lua_literal(val)}")
        return "{" + ",".join(parts) + "}"
    return '"<unsupported>"'


def _gather_stats(ir: Iterable[InstructionIR], const_count: int) -> Dict[int, Dict[str, Any]]:
    stats: Dict[int, Dict[str, Any]] = {}
    for item in ir:
        opnum = item.opnum
        if not isinstance(opnum, int):
            continue
        bucket = stats.setdefault(
            opnum,
            {
                "count": 0,
                "a_int": 0,
                "b_int": 0,
                "c_int": 0,
                "b_const": 0,
                "c_const": 0,
                "b_none": 0,
                "c_none": 0,
                "sample_pcs": [],
            },
        )
        bucket["count"] += 1
        bucket["sample_pcs"].append(item.pc)
        if isinstance(item.A, int):
            bucket["a_int"] += 1
        if isinstance(item.B, int):
            bucket["b_int"] += 1
            if 1 <= item.B <= const_count:
                bucket["b_const"] += 1
        elif item.B is None:
            bucket["b_none"] += 1
        if isinstance(item.C, int):
            bucket["c_int"] += 1
            if 1 <= item.C <= const_count:
                bucket["c_const"] += 1
        elif item.C is None:
            bucket["c_none"] += 1
    return stats


def _candidate_names(stats: Dict[str, Any], opnum: int) -> List[str]:
    scores: Dict[str, float] = {}
    count = max(1, stats.get("count", 0) or 1)

    def bump(name: str, weight: float) -> None:
        scores[name] = scores.get(name, 0.0) + weight

    b_const_ratio = stats.get("b_const", 0) / count
    c_const_ratio = stats.get("c_const", 0) / count
    b_int_ratio = stats.get("b_int", 0) / count
    c_int_ratio = stats.get("c_int", 0) / count
    b_none_ratio = stats.get("b_none", 0) / count
    c_none_ratio = stats.get("c_none", 0) / count
    a_int_ratio = stats.get("a_int", 0) / count

    if b_const_ratio > 0.6:
        bump("LOADK", 5.0)
        bump("GETGLOBAL", 3.5)
        bump("SETGLOBAL", 3.5)
    elif b_const_ratio > 0.3:
        bump("LOADK", 2.0)

    if b_int_ratio > 0.6 and b_const_ratio < 0.2:
        bump("MOVE", 4.5)
        bump("CALL", 2.5)
        bump("RETURN", 1.5)

    if c_const_ratio > 0.5:
        bump("SETTABLE", 3.5)
        bump("GETTABLE", 3.5)
    if c_int_ratio > 0.6 and c_const_ratio < 0.2:
        bump("EQ", 2.5)
        bump("LT", 2.5)
        bump("LE", 2.0)

    if b_none_ratio > 0.25 or c_none_ratio > 0.25:
        bump("RETURN", 2.5)
        bump("VARARG", 2.0)

    if a_int_ratio > 0.7 and b_int_ratio > 0.5:
        bump("MOVE", 1.5)

    base_spec = _BASE_OPCODE_TABLE.get(opnum)
    if base_spec:
        mnemonic = getattr(base_spec, "mnemonic", None) or str(base_spec)
        bump(str(mnemonic), 0.5)

    placeholder = f"OP_{opnum}"
    if placeholder not in scores:
        scores[placeholder] = 0.0

    ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    return [name for name, _ in ordered]


def run_lifter(unpacked_path: str | os.PathLike[str], out_dir: str | os.PathLike[str]) -> Dict[str, Any]:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    data = _normalise(_read_json(unpacked_path))

    def slot(idx: int) -> Any:
        return _normalise(_lua_index(data, idx))

    instrs = slot(4)
    consts = slot(5)

    if not isinstance(instrs, list) or not instrs:
        return {"status": "error", "message": "data[4] not a non-empty instruction array"}

    if not isinstance(consts, list):
        consts = []

    ir: List[InstructionIR] = []
    unknown: set[int | str] = set()

    for pc, raw in enumerate(instrs, start=1):
        if isinstance(raw, list):
            opnum = raw[2] if len(raw) >= 3 and isinstance(raw[2], int) else None
            A = raw[5] if len(raw) >= 6 else None
            B = raw[6] if len(raw) >= 7 else None
            C = raw[7] if len(raw) >= 8 else None
            Bx = raw[8] if len(raw) >= 9 and isinstance(raw[8], int) else None
            sBx = raw[9] if len(raw) >= 10 and isinstance(raw[9], int) else None
        elif isinstance(raw, dict):
            opnum = raw.get("3") if isinstance(raw.get("3"), int) else raw.get(3)
            opnum = opnum if isinstance(opnum, int) else None
            A = raw.get("6", raw.get(6))
            B = raw.get("7", raw.get(7))
            C = raw.get("8", raw.get(8))
            Bx = raw.get("9", raw.get(9))
            sBx = raw.get("10", raw.get(10))
        else:
            opnum = None
            A = B = C = None
            Bx = sBx = None

        if not isinstance(opnum, int):
            unknown.add("<non-int-op>")

        ir.append(
            InstructionIR(
                pc=pc,
                opnum=opnum,
                A=_coerce_int(A),
                B=_coerce_int(B),
                C=_coerce_int(C),
                Bx=_coerce_int(Bx),
                sBx=_coerce_int(sBx),
                raw=raw,
            )
        )

    stats = _gather_stats(ir, len(consts))
    opcode_candidates: Dict[str, Any] = {}
    for opnum, info in stats.items():
        info = dict(info)
        candidates = _candidate_names(info, opnum)
        opcode_candidates[str(opnum)] = {
            "opnum": opnum,
            "candidates": candidates,
            "stats": {k: v for k, v in info.items() if k != "opnum"},
            "sample_pcs": info.get("sample_pcs", [])[:5],
        }

    # Serialise IR to Lua + JSON for downstream tooling.
    lua_ir = "return " + _to_lua_literal([item.as_dict() for item in ir])
    (out_path / "lift_ir.lua").write_text(lua_ir, encoding="utf-8")
    (out_path / "lift_ir.json").write_text(
        json.dumps([item.as_dict() for item in ir], indent=2),
        encoding="utf-8",
    )

    (out_path / "opcode_candidates.json").write_text(
        json.dumps(opcode_candidates, indent=2),
        encoding="utf-8",
    )

    unique_opnums = sorted({i.opnum for i in ir if isinstance(i.opnum, int)})
    report_lines = [
        f"instructions={len(ir)}",
        f"unique_opnums={len(unique_opnums)}",
        f"unknown_entries={sorted(unknown)}",
        "candidate_summary:",
    ]
    for opnum in unique_opnums:
        cand = opcode_candidates.get(str(opnum), {})
        names = ", ".join(cand.get("candidates", [])) or "<none>"
        report_lines.append(f"  - op {opnum}: {names}")

    (out_path / "lift_report.txt").write_text("\n".join(report_lines), encoding="utf-8")

    return {
        "status": "ok",
        "instructions": len(ir),
        "unique_opnums": len(unique_opnums),
        "opcode_candidates": len(opcode_candidates),
    }


def cluster_candidate_rankings(reports: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Aggregate candidate rankings across multiple runs.

    Each ``report`` should contain the JSON payload produced by
    ``opcode_candidates.json``. The return value maps opcode numbers to candidate
    lists ordered by descending aggregate weight.
    """

    aggregate: Dict[str, Dict[str, float]] = {}
    for report in reports:
        if not isinstance(report, MutableMapping):
            continue
        for opnum, meta in report.items():
            if not isinstance(meta, MutableMapping):
                continue
            candidates = meta.get("candidates")
            if not isinstance(candidates, list):
                continue
            bucket = aggregate.setdefault(str(opnum), {})
            total = len(candidates)
            for rank, name in enumerate(candidates):
                weight = float(max(total - rank, 1))
                bucket[str(name)] = bucket.get(str(name), 0.0) + weight

    clustered: Dict[str, List[str]] = {}
    for opnum, score_map in aggregate.items():
        ordered = sorted(
            score_map.items(),
            key=lambda item: (
                -item[1],
                item[0].startswith("OP_"),
                item[0],
            ),
        )
        clustered[opnum] = [name for name, _ in ordered]
    return clustered


__all__ = ["run_lifter", "cluster_candidate_rankings"]

