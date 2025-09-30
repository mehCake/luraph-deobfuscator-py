"""Minimal opcode verification helpers.

The goal is to provide lightweight sanity checks that exercise the most common
instruction patterns.  The emulator logic here is intentionally simple – it
does not attempt to fully re-implement the VM.  Instead it validates a handful
of opcodes (currently ``LOADK`` and ``MOVE``) using real samples taken from the
captured instruction stream.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, MutableMapping, Tuple


def _read_json(path: str | os.PathLike[str]) -> Any:
    with open(path, "rb") as handle:
        return json.load(handle)


def _write_json(path: str | os.PathLike[str], payload: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _normalise(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, MutableMapping):
        if set(value.keys()) == {"array"} and isinstance(value["array"], list):
            return [_normalise(v) for v in value["array"]]
        return {k: _normalise(v) for k, v in value.items()}
    return value


def _lua_index(container: Any, index: int) -> Any:
    if isinstance(container, list):
        idx = index - 1
        if 0 <= idx < len(container):
            return container[idx]
        return None
    if isinstance(container, MutableMapping):
        return container.get(str(index), container.get(index))
    return None


def _normalise_instruction(raw: Any) -> Tuple[int | None, int | None, int | None, int | None]:
    """Extract ``(opnum, A, B, C)`` from *raw* instruction representations."""

    if isinstance(raw, list):
        op = raw[2] if len(raw) >= 3 else None
        A = raw[5] if len(raw) >= 6 else None
        B = raw[6] if len(raw) >= 7 else None
        C = raw[7] if len(raw) >= 8 else None
        return op, A, B, C
    if isinstance(raw, dict):
        op = raw.get("3", raw.get(3))
        A = raw.get("6", raw.get(6))
        B = raw.get("7", raw.get(7))
        C = raw.get("8", raw.get(8))
        return op, A, B, C
    return None, None, None, None


def _collect_samples(instrs: Iterable[Any]) -> Dict[int, List[Dict[str, Any]]]:
    samples: Dict[int, List[Dict[str, Any]]] = {}
    for pc, raw in enumerate(instrs, start=1):
        op, A, B, C = _normalise_instruction(raw)
        if not isinstance(op, int):
            continue
        samples.setdefault(op, []).append({"pc": pc, "A": A, "B": B, "C": C, "raw": raw})
    return samples


def _detect_loadk(
    samples: List[Dict[str, Any]], const_count: int
) -> Tuple[bool, List[Dict[str, Any]]]:
    hits: List[Dict[str, Any]] = []
    for sample in samples:
        b = sample.get("B")
        raw = sample.get("raw")
        candidate = None
        matches = []
        if isinstance(b, int) and 1 <= b <= const_count:
            matches.append(b)
        if isinstance(raw, list):
            for value in raw:
                if isinstance(value, int) and 1 <= value <= const_count:
                    matches.append(value)
        if matches:
            unique_matches = {m for m in matches}
            if len(unique_matches) == 1 and isinstance(sample.get("A"), int):
                candidate = next(iter(unique_matches))
        if candidate is not None:
            hits.append(sample)
    return len(hits) >= 1, hits[:5]


def _detect_move(samples: List[Dict[str, Any]]) -> Tuple[bool, List[Dict[str, Any]]]:
    hits = [
        s
        for s in samples
        if isinstance(s.get("A"), int) and isinstance(s.get("B"), int) and s.get("C") in (None, 0)
    ]
    return len(hits) >= 1, hits[:5]


def run_verification(unpacked_json_path: str | os.PathLike[str], out_dir: str | os.PathLike[str]) -> Dict[str, Any]:
    """Run heuristic opcode validation and emit summary artefacts."""

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    data = _normalise(_read_json(unpacked_json_path))
    instrs = _lua_index(data, 4)
    consts = _lua_index(data, 5)

    if not isinstance(instrs, list) or not isinstance(consts, list):
        return {"status": "error", "message": "malformed unpackedData (instructions/constants)"}

    samples = _collect_samples(instrs)
    evidence_dir = out_path / "tests" / "opcode_validation"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    verified: Dict[int, Dict[str, Any]] = {}
    high_conf = 0

    for opnum, bucket in samples.items():
        mnemonic = f"OP_{opnum}"
        confidence = 0.3
        evidence: List[str] = []

        loadk_ok, loadk_hits = _detect_loadk(bucket, len(consts))
        if loadk_ok:
            mnemonic = "LOADK"
            confidence = 0.9
            evidence.append(f"LOADK-like samples={len(loadk_hits)}")
            _write_json(evidence_dir / f"op_{opnum}_loadk.json", loadk_hits)
        else:
            move_ok, move_hits = _detect_move(bucket)
            if move_ok:
                mnemonic = "MOVE"
                confidence = 0.8
                evidence.append(f"MOVE-like samples={len(move_hits)}")
                _write_json(evidence_dir / f"op_{opnum}_move.json", move_hits)

        if confidence >= 0.8:
            high_conf += 1

        verified[opnum] = {
            "mnemonic": mnemonic,
            "confidence": round(confidence, 2),
            "evidence": evidence,
        }

    json_payload = {str(k): v for k, v in sorted(verified.items())}
    _write_json(out_path / "opcode_map.v14_4_1.verified.json", json_payload)

    lift_report_path = out_path / "lift_report.txt"
    with lift_report_path.open("a", encoding="utf-8") as handle:
        handle.write("\nverification_summary:\n")
        for opnum, meta in sorted(verified.items()):
            handle.write(f"- {opnum}: {meta['mnemonic']} (conf={meta['confidence']})\n")

    return {
        "status": "ok",
        "verified": len(verified),
        "high_confidence": high_conf,
    }


__all__ = ["run_verification"]

