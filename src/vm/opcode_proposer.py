"""Heuristics and tooling for proposing opcode mnemonic mappings.

The proposer consumes handler discovery output from the static parser tracer as
well as disassembly attempts and emits ranked opcode map candidates.  It keeps
the lightweight scoring helpers that earlier callers relied on while layering a
CLI that stitches together handler suggestions, instruction usage statistics,
and optional manual overrides.  The CLI writes a stable
``out/opcode_proposals.json`` file while preserving previously generated
proposals so that analysts can iteratively refine mappings over multiple runs.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

from .disassembler import Instruction

__all__ = [
    "OpcodeProposal",
    "OpcodeMapCandidate",
    "propose_opcode_mappings",
    "group_proposals_by_opcode",
    "generate_map_candidates",
    "render_ir_candidate",
    "compute_opcode_usage",
    "load_handler_suggestions",
    "load_disassembly_instructions",
    "synthesise_opcode_proposals",
    "write_proposals",
    "main",
]


LOGGER = logging.getLogger(__name__)

_RANK_WEIGHTS: Tuple[float, ...] = (1.0, 0.6, 0.4, 0.25)


def _weight_for_rank(rank: int) -> float:
    if rank <= 0:
        return 0.0
    if rank <= len(_RANK_WEIGHTS):
        return _RANK_WEIGHTS[rank - 1]
    return max(0.15, _RANK_WEIGHTS[-1] * (0.75 ** (rank - len(_RANK_WEIGHTS))))


def _normalise_handler_entry(entry: Mapping[str, object]) -> Tuple[int, str, Sequence[str]]:
    opcode = int(entry.get("opcode", 0))
    handler = str(entry.get("handler", ""))
    mnemonics_raw = entry.get("mnemonics", ())
    if isinstance(mnemonics_raw, str):
        mnemonics: Sequence[str] = (mnemonics_raw,)
    elif isinstance(mnemonics_raw, Sequence):
        mnemonics = [str(part) for part in mnemonics_raw]
    else:
        mnemonics = ()
    return opcode, handler, mnemonics


@dataclass(frozen=True)
class OpcodeProposal:
    """Single mnemonic guess for an opcode with metadata."""

    opcode: int
    mnemonic: str
    confidence: float
    handlers: Tuple[str, ...]
    reasons: Tuple[str, ...]

    def as_dict(self) -> Mapping[str, object]:
        return {
            "opcode": self.opcode,
            "mnemonic": self.mnemonic,
            "confidence": self.confidence,
            "handlers": list(self.handlers),
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class OpcodeMapCandidate:
    """Aggregate opcode map assembled from high-confidence proposals."""

    mapping: Mapping[int, str]
    confidence: float
    selections: Mapping[int, OpcodeProposal]

    def as_dict(self) -> Mapping[str, object]:
        return {
            "confidence": self.confidence,
            "mapping": {str(op): mnemonic for op, mnemonic in self.mapping.items()},
            "selections": {
                str(op): {
                    "mnemonic": proposal.mnemonic,
                    "confidence": proposal.confidence,
                    "handlers": list(proposal.handlers),
                    "reasons": list(proposal.reasons),
                }
                for op, proposal in self.selections.items()
            },
        }


def propose_opcode_mappings(
    handler_entries: Iterable[Mapping[str, object]],
    *,
    seeded: Mapping[int, str] | None = None,
) -> List[OpcodeProposal]:
    """Score mnemonic proposals from handler discovery output.

    Parameters
    ----------
    handler_entries:
        Iterable of dictionaries describing handler matches.  Each mapping must
        contain ``opcode`` and ``handler`` keys; a ``mnemonics`` iterable is
        optional.
    seeded:
        Optional pre-existing mapping used to boost confidence for known
        mnemonics (e.g. manually verified entries).
    """

    scores: MutableMapping[Tuple[int, str], float] = {}
    handlers: MutableMapping[Tuple[int, str], List[str]] = {}
    reasons: MutableMapping[Tuple[int, str], List[str]] = {}

    for entry in handler_entries:
        opcode, handler_name, mnemonic_candidates = _normalise_handler_entry(entry)
        if not mnemonic_candidates:
            continue
        lowered_handler = handler_name.lower()
        for rank, mnemonic in enumerate(mnemonic_candidates, start=1):
            if not mnemonic:
                continue
            normalised = mnemonic.upper()
            weight = _weight_for_rank(rank)
            reason = f"rank-{rank}"
            if normalised.lower() in lowered_handler:
                weight += 0.1
                reason += ":name-match"
            key = (opcode, normalised)
            scores[key] = scores.get(key, 0.0) + weight
            handlers.setdefault(key, []).append(handler_name)
            reasons.setdefault(key, []).append(reason)

    if seeded:
        for opcode, mnemonic in seeded.items():
            key = (opcode, mnemonic.upper())
            scores[key] = max(scores.get(key, 0.0), 1.0)
            handlers.setdefault(key, []).append("seeded")
            reasons.setdefault(key, []).append("seeded")

    proposals: List[OpcodeProposal] = []
    for (opcode, mnemonic), score in scores.items():
        confidence = min(1.0, round(score, 3))
        proposal = OpcodeProposal(
            opcode=opcode,
            mnemonic=mnemonic,
            confidence=confidence,
            handlers=tuple(sorted(set(handlers.get((opcode, mnemonic), [])))),
            reasons=tuple(reasons.get((opcode, mnemonic), [])),
        )
        proposals.append(proposal)

    proposals.sort(key=lambda item: (-item.confidence, item.opcode, item.mnemonic))
    return proposals


def group_proposals_by_opcode(
    proposals: Sequence[OpcodeProposal],
) -> Dict[int, List[OpcodeProposal]]:
    grouped: Dict[int, List[OpcodeProposal]] = {}
    for proposal in proposals:
        grouped.setdefault(proposal.opcode, []).append(proposal)
    for options in grouped.values():
        options.sort(key=lambda item: (-item.confidence, item.mnemonic))
    return grouped


def generate_map_candidates(
    grouped: Mapping[int, Sequence[OpcodeProposal]],
    *,
    top_n: int = 3,
    opcode_usage: Mapping[int, int] | None = None,
) -> List[OpcodeMapCandidate]:
    if not grouped:
        return []

    primary_selection: Dict[int, OpcodeProposal] = {}
    for opcode, options in grouped.items():
        if options:
            primary_selection[opcode] = options[0]

    if not primary_selection:
        return []

    usage_total = sum(opcode_usage.values()) if opcode_usage else 0

    def _score(selection: Mapping[int, OpcodeProposal]) -> float:
        if not selection:
            return 0.0
        base = sum(item.confidence for item in selection.values())
        if opcode_usage and usage_total:
            bonus = 0.0
            for opcode, proposal in selection.items():
                usage = opcode_usage.get(opcode, 0)
                if usage:
                    ratio = usage / usage_total
                    bonus += ratio * (0.6 + 0.4 * proposal.confidence)
            base += bonus
        return base / len(selection)

    candidates: List[OpcodeMapCandidate] = []
    base_score = _score(primary_selection)
    candidates.append(
        OpcodeMapCandidate(
            mapping={opcode: proposal.mnemonic for opcode, proposal in primary_selection.items()},
            confidence=base_score,
            selections=dict(primary_selection),
        )
    )

    alternatives: List[Tuple[float, Dict[int, OpcodeProposal]]] = []
    for opcode, options in grouped.items():
        for alternative in options[1:]:
            selection = dict(primary_selection)
            selection[opcode] = alternative
            alternatives.append((_score(selection), selection))

    alternatives.sort(key=lambda item: -item[0])
    for score, selection in alternatives[: max(0, top_n - 1)]:
        candidates.append(
            OpcodeMapCandidate(
                mapping={opcode: proposal.mnemonic for opcode, proposal in selection.items()},
                confidence=score,
                selections=selection,
            )
        )

    return candidates


def render_ir_candidate(
    candidate: OpcodeMapCandidate,
    instructions: Sequence[Instruction],
) -> str:
    """Render a human-readable IR listing for the provided candidate map."""

    lines: List[str] = []
    lines.append(f"# Opcode Map Candidate — confidence {candidate.confidence:.2f}")
    lines.append("")
    lines.append("## Mapping")
    for opcode in sorted(candidate.mapping):
        proposal = candidate.selections[opcode]
        handler_text = ", ".join(proposal.handlers) if proposal.handlers else "<unknown>"
        reason_text = ", ".join(proposal.reasons) if proposal.reasons else "heuristic"
        lines.append(
            f"- {opcode:02d} → {proposal.mnemonic} (conf={proposal.confidence:.2f}; handlers={handler_text}; reasons={reason_text})"
        )

    lines.append("")
    lines.append("## IR Listing")
    if not instructions:
        lines.append("<no instructions available>")
        return "\n".join(lines)

    for inst in instructions:
        mnemonic = candidate.mapping.get(inst.opcode, f"OP_{inst.opcode}")
        raw_hex = f"0x{inst.raw:08x}" if isinstance(inst.raw, int) else str(inst.raw)
        lines.append(
            f"{inst.index:04d}: {mnemonic} A={inst.a:>3} B={inst.b:>3} C={inst.c:>3} | raw={raw_hex}"
        )

    return "\n".join(lines)


def compute_opcode_usage(instructions: Sequence[Instruction]) -> Mapping[int, int]:
    """Return a frequency map describing how often each opcode appears."""

    counts: MutableMapping[int, int] = {}
    for inst in instructions:
        counts[inst.opcode] = counts.get(inst.opcode, 0) + 1
    return dict(counts)


def _iter_handler_entries(payload: Mapping[str, object]) -> Iterator[Mapping[str, object]]:
    handlers = payload.get("handlers")
    if isinstance(handlers, list):
        for entry in handlers:
            if isinstance(entry, Mapping):
                yield entry


def load_handler_suggestions(path: Path) -> List[Mapping[str, object]]:
    """Load handler suggestion JSON and normalise it for proposal scoring."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - filesystem
        LOGGER.warning("Unable to read handler suggestions from %s: %s", path, exc)
        return []

    entries: List[Mapping[str, object]] = []
    candidates = []
    if isinstance(data, Mapping):
        candidates = list(_iter_handler_entries(data))
    elif isinstance(data, list):
        candidates = [entry for entry in data if isinstance(entry, Mapping)]

    for entry in candidates:
        if not entry.get("resolvable", True):
            continue
        opcode = entry.get("opcode")
        if opcode is None:
            continue
        suggestions = entry.get("candidates", [])
        ranked: List[str] = []
        if isinstance(suggestions, list):
            sorted_candidates = sorted(
                (
                    (float(candidate.get("confidence", 0.0)), candidate.get("mnemonic"))
                    for candidate in suggestions
                    if isinstance(candidate, Mapping)
                ),
                key=lambda item: item[0],
                reverse=True,
            )
            ranked = [str(name) for _, name in sorted_candidates if name]
        elif isinstance(suggestions, str):
            ranked = [suggestions]

        if not ranked:
            continue

        entries.append(
            {
                "opcode": int(opcode),
                "handler": str(entry.get("name", "handler")),
                "mnemonics": ranked,
            }
        )

    return entries


def _normalise_instruction(payload: Mapping[str, object]) -> Instruction:
    return Instruction(
        index=int(payload.get("index", 0)),
        raw=int(payload.get("raw", 0)),
        opcode=int(payload.get("opcode", 0)),
        a=int(payload.get("a", 0)),
        b=int(payload.get("b", 0)),
        c=int(payload.get("c", 0)),
    )


def _extract_instruction_dicts(payload: object) -> Iterator[Mapping[str, object]]:
    if isinstance(payload, Mapping):
        if "instructions" in payload and isinstance(payload["instructions"], list):
            for entry in payload["instructions"]:
                if isinstance(entry, Mapping):
                    yield entry
        elif "candidates" in payload and isinstance(payload["candidates"], list):
            for candidate in payload["candidates"]:
                if isinstance(candidate, Mapping):
                    yield from _extract_instruction_dicts(candidate)
    elif isinstance(payload, list):
        for entry in payload:
            if isinstance(entry, Mapping):
                yield entry


def load_disassembly_instructions(paths: Sequence[Path]) -> List[Instruction]:
    """Load instructions from one or more disassembly JSON files."""

    instructions: List[Instruction] = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - filesystem
            LOGGER.warning("Unable to read disassembly from %s: %s", path, exc)
            continue
        for entry in _extract_instruction_dicts(data):
            instructions.append(_normalise_instruction(entry))
    return instructions


def _apply_overrides(
    grouped: MutableMapping[int, List[OpcodeProposal]],
    overrides: Mapping[int, str],
) -> None:
    for opcode, mnemonic in overrides.items():
        override = OpcodeProposal(
            opcode=opcode,
            mnemonic=mnemonic.upper(),
            confidence=1.0,
            handlers=("manual-override",),
            reasons=("manual-override",),
        )
        options = grouped.setdefault(opcode, [])
        filtered = [proposal for proposal in options if proposal.mnemonic != override.mnemonic]
        options[:] = [override] + filtered


def synthesise_opcode_proposals(
    handler_entries: Sequence[Mapping[str, object]],
    instructions: Sequence[Instruction],
    *,
    overrides: Mapping[int, str] | None = None,
    seeded: Mapping[int, str] | None = None,
    top_n: int = 5,
) -> List[OpcodeMapCandidate]:
    """Combine handler data and usage statistics into ranked opcode maps."""

    proposals = propose_opcode_mappings(handler_entries, seeded=seeded)
    grouped = group_proposals_by_opcode(proposals)
    if overrides:
        _apply_overrides(grouped, overrides)
    opcode_usage = compute_opcode_usage(instructions)
    candidates = generate_map_candidates(
        grouped,
        top_n=top_n,
        opcode_usage=opcode_usage,
    )
    return candidates


def _serialise_candidates(candidates: Sequence[OpcodeMapCandidate]) -> List[Mapping[str, object]]:
    serialised: List[Mapping[str, object]] = []
    for index, candidate in enumerate(candidates, start=1):
        payload = dict(candidate.as_dict())
        payload["rank"] = index
        payload["opcode_count"] = len(candidate.mapping)
        serialised.append(payload)
    return serialised


def _load_existing(path: Path) -> Optional[Mapping[str, object]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - filesystem
        LOGGER.warning("Unable to load existing opcode proposals from %s: %s", path, exc)
        return None


def write_proposals(
    output_path: Path,
    candidates: Sequence[OpcodeMapCandidate],
    *,
    overrides: Mapping[int, str] | None = None,
    sources: Mapping[str, Sequence[str]] | None = None,
) -> Path:
    """Write proposal data while preserving previously stored candidates."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    serialised = _serialise_candidates(candidates)
    payload = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "candidates": serialised,
    }
    if overrides:
        payload["overrides"] = {str(op): mnemonic for op, mnemonic in overrides.items()}
    if sources:
        payload["sources"] = {
            key: list(values)
            for key, values in sources.items()
        }

    existing = _load_existing(output_path)
    if existing:
        previous = existing.get("candidates")
        if isinstance(previous, list):
            seen = {
                tuple(sorted(
                    (int(op), str(mnemonic))
                    for op, mnemonic in item.get("mapping", {}).items()
                ))
                for item in previous
                if isinstance(item, Mapping)
            }
            merged: List[Mapping[str, object]] = []
            for item in previous:
                if isinstance(item, Mapping):
                    merged.append(item)
            for item in payload["candidates"]:
                signature = tuple(sorted((int(op), str(mnemonic)) for op, mnemonic in item["mapping"].items()))
                if signature not in seen:
                    merged.append(item)
                    seen.add(signature)
            payload["candidates"] = merged

        for key in ("overrides", "sources"):
            if key in existing and key not in payload and isinstance(existing[key], Mapping):
                payload[key] = existing[key]

    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return output_path


def _parse_override(values: Sequence[str]) -> Dict[int, str]:
    overrides: Dict[int, str] = {}
    for value in values:
        if not value:
            continue
        if "=" not in value:
            LOGGER.warning("Invalid override %s. Expected format opcode=MNEMONIC", value)
            continue
        opcode_text, mnemonic = value.split("=", 1)
        try:
            opcode = int(opcode_text, 0)
        except ValueError:
            LOGGER.warning("Invalid opcode in override %s", value)
            continue
        overrides[opcode] = mnemonic.strip().upper()
    return overrides


def _collect_source_metadata(handler_path: Path, disasm_paths: Sequence[Path]) -> Mapping[str, Sequence[str]]:
    sources: Dict[str, Sequence[str]] = {
        "handlers": [str(handler_path)],
    }
    if disasm_paths:
        sources["disassembly"] = [str(path) for path in disasm_paths]
    return sources


def run_cli(
    *,
    handler_path: Path,
    disasm_paths: Sequence[Path],
    overrides: Mapping[int, str],
    output_path: Path,
    top_n: int,
) -> int:
    handler_entries = load_handler_suggestions(handler_path)
    if not handler_entries:
        LOGGER.error("No handler suggestions available from %s", handler_path)
        return 1

    instructions = load_disassembly_instructions(disasm_paths)
    if not instructions:
        LOGGER.warning("No instructions loaded from disassembly inputs; scores will rely on handler data only")

    candidates = synthesise_opcode_proposals(
        handler_entries,
        instructions,
        overrides=overrides,
        top_n=top_n,
    )
    if not candidates:
        LOGGER.error("Unable to generate opcode proposal candidates")
        return 1

    write_proposals(
        output_path,
        candidates,
        overrides=overrides,
        sources=_collect_source_metadata(handler_path, disasm_paths),
    )
    LOGGER.info("Wrote %d opcode proposal candidates to %s", len(candidates), output_path)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Synthesise opcode map proposals from handler analysis")
    parser.add_argument("--handlers", type=Path, required=True, help="JSON file produced by handler analysis")
    parser.add_argument(
        "--disasm",
        dest="disasm",
        action="append",
        default=[],
        type=Path,
        help="Disassembly JSON dump(s). May be specified multiple times.",
    )
    parser.add_argument(
        "--override",
        action="append",
        default=[],
        help="Manual override in the form opcode=MNEMONIC. May be repeated.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=5,
        help="Number of candidates to keep in the prioritised list",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "opcode_proposals.json",
        help="Destination for the proposal JSON report",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    overrides = _parse_override(args.override)
    return run_cli(
        handler_path=args.handlers,
        disasm_paths=args.disasm,
        overrides=overrides,
        output_path=args.output,
        top_n=max(1, args.top),
    )


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
