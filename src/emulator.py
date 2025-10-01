"""Opcode verification harness built on top of :mod:`src.opcode_emulator`."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, MutableMapping, Tuple

from .opcode_emulator import ExecutionContext, Instruction, OpcodeEmulator


@dataclass
class SampleResult:
    """Represents the outcome of emulating a single instruction sample."""

    pc: int
    mnemonic: str
    passed: bool | None
    reason: str

    def as_dict(self) -> Dict[str, Any]:  # pragma: no cover - simple serialiser
        return {
            "pc": self.pc,
            "mnemonic": self.mnemonic,
            "passed": self.passed,
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Helpers for decoding Lua shaped tables
# ---------------------------------------------------------------------------


def _read_json(path: str | Path) -> Any:
    with Path(path).open("rb") as handle:
        return json.load(handle)


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
        py_index = index - 1
        if 0 <= py_index < len(container):
            return container[py_index]
        return None
    if isinstance(container, MutableMapping):
        return container.get(str(index), container.get(index))
    return None


def _normalised_constants(unpacked: Any) -> List[Any]:
    slot = _normalise(_lua_index(unpacked, 5))
    if isinstance(slot, list):
        return slot
    return []


# ---------------------------------------------------------------------------
# Instruction sampling utilities
# ---------------------------------------------------------------------------


def _group_by_opnum(ir_entries: Iterable[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    grouped: Dict[int, List[Dict[str, Any]]] = {}
    for entry in ir_entries:
        opnum = entry.get("opnum")
        if isinstance(opnum, int):
            grouped.setdefault(opnum, []).append(entry)
    return grouped


def _guess_constant_index(sample: Dict[str, Any], const_count: int) -> int | None:
    if const_count <= 0:
        return None

    bx = sample.get("Bx")
    if isinstance(bx, int) and 0 <= bx < const_count:
        return bx

    b = sample.get("B")
    if isinstance(b, int) and 0 <= b < const_count:
        return b

    raw = sample.get("raw")
    if isinstance(raw, list):
        for value in raw:
            if isinstance(value, int) and 1 <= value <= const_count:
                return value - 1
    elif isinstance(raw, dict):
        for value in raw.values():
            if isinstance(value, int) and 1 <= value <= const_count:
                return value - 1
    return None


# ---------------------------------------------------------------------------
# Candidate evaluation helpers
# ---------------------------------------------------------------------------


def _prepare_registers(size: int) -> List[Any]:
    return [f"r{i}" for i in range(size)]


def _evaluate_move(sample: Dict[str, Any], constants: List[Any], emulator: OpcodeEmulator) -> Tuple[bool | None, SampleResult]:
    A = sample.get("A")
    B = sample.get("B")
    pc = int(sample.get("pc", 0))
    if not isinstance(A, int) or not isinstance(B, int):
        return None, SampleResult(pc, "MOVE", None, "requires integer registers")

    max_reg = max(A, B) + 2
    registers = _prepare_registers(max_reg)
    source_value = f"value_from_R{B}"
    registers[B] = source_value
    registers[A] = f"orig_R{A}"
    ctx = ExecutionContext(registers=registers, constants=list(constants))
    instruction = Instruction("MOVE", a=A, b=B, opnum=sample.get("opnum"), line=pc)
    emulator.execute(instruction, ctx)
    success = ctx.registers[A] == source_value
    reason = "copied" if success else f"expected {source_value!r}, got {ctx.registers[A]!r}"
    return success, SampleResult(pc, "MOVE", success, reason)


def _evaluate_loadk(sample: Dict[str, Any], constants: List[Any], emulator: OpcodeEmulator) -> Tuple[bool | None, SampleResult]:
    A = sample.get("A")
    pc = int(sample.get("pc", 0))
    if not isinstance(A, int):
        return None, SampleResult(pc, "LOADK", None, "register A missing")

    const_index = _guess_constant_index(sample, len(constants))
    if const_index is None or const_index < 0:
        return None, SampleResult(pc, "LOADK", None, "unable to infer constant index")
    if const_index >= len(constants):
        return None, SampleResult(pc, "LOADK", None, "constant index outside range")

    registers = _prepare_registers(A + 2)
    ctx = ExecutionContext(registers=registers, constants=list(constants))
    ctx.ensure_constant(const_index)
    expected = ctx.constants[const_index]
    instruction = Instruction("LOADK", a=A, bx=const_index, opnum=sample.get("opnum"), line=pc)
    emulator.execute(instruction, ctx)
    success = ctx.registers[A] == expected
    reason = "loaded constant" if success else f"expected {expected!r}, got {ctx.registers[A]!r}"
    return success, SampleResult(pc, "LOADK", success, reason)


_CHECKS: Dict[str, Callable[[Dict[str, Any], List[Any], OpcodeEmulator], Tuple[bool | None, SampleResult]]] = {
    "MOVE": _evaluate_move,
    "LOADK": _evaluate_loadk,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_verification(
    ir_path: str | Path,
    unpacked_json_path: str | Path,
    candidates_path: str | Path,
    out_dir: str | Path,
) -> Dict[str, Any]:
    """Validate opcode candidates using the small emulator."""

    ir_entries = _read_json(ir_path)
    if not isinstance(ir_entries, list):
        return {"status": "error", "message": "lift_ir.json must contain a list"}

    unpacked = _normalise(_read_json(unpacked_json_path))
    constants = _normalised_constants(unpacked)

    try:
        candidate_map = _read_json(candidates_path)
    except FileNotFoundError:
        candidate_map = {}

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    evidence_dir = out_path / "tests" / "opcode_validation"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    emulator = OpcodeEmulator()
    grouped = _group_by_opnum(ir_entries)

    results: Dict[int, Dict[str, Any]] = {}
    high_conf = 0

    for opnum, samples in sorted(grouped.items()):
        candidate_info = candidate_map.get(str(opnum), {})
        raw_candidates = candidate_info.get("candidates", []) if isinstance(candidate_info, dict) else []
        candidates: List[str] = []
        for cand in raw_candidates:
            cand_upper = str(cand).upper()
            if cand_upper in emulator.supported_mnemonics and cand_upper not in candidates:
                candidates.append(cand_upper)
        if not candidates:
            candidates = []

        best_mnemonic = f"OP_{opnum}"
        best_confidence = 0.0
        best_status = "unverified"
        best_evidence: List[str] = []
        failure_notes: List[str] = []

        for candidate in candidates:
            check = _CHECKS.get(candidate)
            if check is None:
                failure_notes.append(f"{candidate} not implemented in emulator checks")
                continue

            successes = 0
            attempts = 0
            sample_results: List[SampleResult] = []
            for sample in samples[:5]:
                passed, outcome = check(sample, constants, emulator)
                sample_results.append(outcome)
                if passed is None:
                    continue
                attempts += 1
                if passed:
                    successes += 1

            if attempts == 0:
                failure_notes.append(f"{candidate} lacks suitable samples for verification")
                continue

            confidence = successes / attempts
            if sample_results:
                out_file = evidence_dir / f"op_{opnum}_{candidate.lower()}.json"
                out_file.write_text(
                    json.dumps([item.as_dict() for item in sample_results], indent=2),
                    encoding="utf-8",
                )

            if confidence > best_confidence:
                best_confidence = confidence
                if confidence >= 0.8:
                    best_mnemonic = candidate
                    best_status = "verified"
                    best_evidence = [
                        f"pc {item.pc}: {item.reason}" for item in sample_results if item.passed
                    ]
                else:
                    best_mnemonic = f"OP_{opnum}"
                    best_status = "unverified"
                    best_evidence = [
                        f"pc {item.pc}: {item.reason}" for item in sample_results if item.passed
                    ]

        if best_status == "verified":
            high_conf += 1
        if not best_evidence and failure_notes:
            best_evidence = failure_notes[:3]

        results[opnum] = {
            "mnemonic": best_mnemonic,
            "confidence": round(best_confidence, 2),
            "status": best_status,
            "evidence": best_evidence,
        }
        if failure_notes:
            results[opnum]["notes"] = failure_notes

    payload = {str(k): v for k, v in sorted(results.items())}
    (out_path / "opcode_map.v14_4_1.verified.json").write_text(
        json.dumps(payload, indent=2),
        encoding="utf-8",
    )

    report_path = out_path / "lift_report.txt"
    with report_path.open("a", encoding="utf-8") as handle:
        handle.write("\nemulator_verification:\n")
        for opnum, meta in sorted(results.items()):
            handle.write(
                f"- {opnum}: {meta['mnemonic']} (conf={meta['confidence']}, status={meta['status']})\n"
            )

    summary = {
        "status": "ok",
        "verified": len(results),
        "high_confidence": high_conf,
    }
    (out_path / "emulator_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


__all__ = ["run_verification"]
