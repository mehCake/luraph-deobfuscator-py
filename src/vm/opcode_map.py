"""Opcode mapping helpers and heuristics.

This module started life as a lightweight container for recording discovered
opcode mnemonics.  As the tooling around the heavy Luraph lifter evolved we
needed a more complete mapping manager able to:

* harvest mnemonic hints directly from bootstrap handler snippets,
* score and persist the resulting candidate maps for iterative tuning, and
* project a mapping over decoded instruction streams for quick inspection.

All helpers in this module are **static** – they never execute bootstrap code
and they never persist sensitive keys.  The heuristics include patterns tuned
for Luraph v14.4.2 handler naming conventions (e.g. ``handle_v1442_call``) but
remain generic enough to work for neighbouring versions such as v14.4.1 and
v14.4.3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Sequence, Tuple

Operands = Tuple[int, int, int]

LOGGER = logging.getLogger(__name__)

OUTPUT_DIR = Path("out/opcode_maps")

_CORE_MNEMONIC_WEIGHTS: Dict[str, float] = {
    "LOADK": 1.0,
    "CALL": 0.95,
    "RETURN": 0.95,
    "JMP": 0.85,
    "EQ": 0.8,
    "MOVE": 0.75,
    "SETGLOBAL": 0.6,
    "GETGLOBAL": 0.6,
    "CLOSURE": 0.55,
}

_GENERIC_WEIGHT = 0.35

_HANDLER_NAME_HINTS: Tuple[Tuple[re.Pattern[str], str, float, str], ...] = (
    (re.compile(r"loadk", re.I), "LOADK", 1.0, "name:loadk"),
    (re.compile(r"call", re.I), "CALL", 0.9, "name:call"),
    (re.compile(r"ret", re.I), "RETURN", 0.9, "name:return"),
    (re.compile(r"jump|jmp", re.I), "JMP", 0.85, "name:jmp"),
    (re.compile(r"eq\b", re.I), "EQ", 0.8, "name:eq"),
    (re.compile(r"move", re.I), "MOVE", 0.7, "name:move"),
    (re.compile(r"getglobal", re.I), "GETGLOBAL", 0.65, "name:getglobal"),
    (re.compile(r"setglobal", re.I), "SETGLOBAL", 0.65, "name:setglobal"),
    # Luraph v14.4.2 variations observed in handler dumps.
    (re.compile(r"v?14_?4_?2.*load", re.I), "LOADK", 1.0, "name:v14.4.2-load"),
    (re.compile(r"v?14_?4_?2.*call", re.I), "CALL", 0.95, "name:v14.4.2-call"),
    (re.compile(r"v?14_?4_?2.*ret", re.I), "RETURN", 0.95, "name:v14.4.2-ret"),
)

_HANDLER_BODY_HINTS: Tuple[Tuple[re.Pattern[str], str, float, str], ...] = (
    (re.compile(r"K\[\s*\d+\s*\]", re.I), "LOADK", 0.75, "body:const"),
    (re.compile(r"consts?\[", re.I), "LOADK", 0.7, "body:const-table"),
    (re.compile(r"stack\[[^\]]+\]\s*=\s*stack\[[^\]]+\]\s*\(", re.I), "CALL", 0.85, "body:call"),
    (re.compile(r"return\s+stack", re.I), "RETURN", 0.8, "body:return-stack"),
    (re.compile(r"pc\s*\+", re.I), "JMP", 0.75, "body:pc-adjust"),
    (re.compile(r"==", re.I), "EQ", 0.6, "body:eq"),
    (re.compile(r"bit32", re.I), "EQ", 0.5, "body:bit32"),
    (re.compile(r"register", re.I), "MOVE", 0.6, "body:register"),
    (re.compile(r"env\[", re.I), "GETGLOBAL", 0.55, "body:env"),
)


_LURAPH_1442_BASELINE: Dict[int, Tuple[str, float]] = {
    1: ("LOADK", 0.75),
    5: ("CALL", 0.65),
    6: ("RETURN", 0.65),
    8: ("EQ", 0.55),
}


@dataclass(frozen=True)
class MapCandidate:
    """Represents a scored opcode mapping suggestion."""

    mapping: Mapping[int, str]
    score: float
    reasons: Tuple[str, ...]
    aggregate_weight: float

    def as_dict(self) -> Dict[str, object]:
        return {
            "score": self.score,
            "reasons": list(self.reasons),
            "aggregate_weight": self.aggregate_weight,
            "mapping": {str(op): mn for op, mn in self.mapping.items()},
        }


@dataclass
class OpcodeMap:
    """Container describing a VM's opcode metadata."""

    mnemonics: MutableMapping[int, str] = field(default_factory=dict)
    examples: MutableMapping[int, List[Operands]] = field(default_factory=dict)
    notes: MutableMapping[int, str] = field(default_factory=dict)

    def get_mnemonic(self, opcode: int, default: Optional[str] = None) -> Optional[str]:
        """Return the mnemonic associated with *opcode* if present."""

        return self.mnemonics.get(opcode, default)

    def register(self, opcode: int, mnemonic: str, note: Optional[str] = None) -> None:
        """Record the mnemonic for *opcode*, optionally updating its note.

        Existing mnemonics are preserved to avoid clobbering prior research;
        callers that need to replace an entry must do so explicitly.
        """

        if opcode not in self.mnemonics:
            self.mnemonics[opcode] = mnemonic
        if note:
            self.notes[opcode] = note

    def record_example(self, opcode: int, operands: Operands) -> None:
        """Store an operand example for the provided *opcode*."""

        self.examples.setdefault(opcode, []).append(operands)

    def merge(self, other: "OpcodeMap") -> None:
        """Merge entries from another :class:`OpcodeMap` into this instance."""

        for opcode, mnemonic in other.mnemonics.items():
            if opcode not in self.mnemonics:
                self.mnemonics[opcode] = mnemonic
        for opcode, operands in other.examples.items():
            self.examples.setdefault(opcode, []).extend(operands)
        for opcode, note in other.notes.items():
            self.notes.setdefault(opcode, note)

    def as_dict(self) -> Dict[str, Dict[str, object]]:
        """Return a JSON-serialisable structure representing the map."""

        return {
            "mnemonics": {str(opcode): mnemonic for opcode, mnemonic in self.mnemonics.items()},
            "examples": {
                str(opcode): [list(example) for example in operands]
                for opcode, operands in self.examples.items()
            },
            "notes": {str(opcode): note for opcode, note in self.notes.items()},
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Dict[str, object]]) -> "OpcodeMap":
        """Construct an :class:`OpcodeMap` from ``as_dict`` output."""

        mnemonics = {
            int(opcode): str(mnemonic)
            for opcode, mnemonic in payload.get("mnemonics", {}).items()
        }
        examples = {
            int(opcode): [tuple(int(part) for part in example) for example in operands]
            for opcode, operands in payload.get("examples", {}).items()
        }
        notes = {int(opcode): str(note) for opcode, note in payload.get("notes", {}).items()}
        instance = cls()
        instance.mnemonics.update(mnemonics)
        instance.examples.update(examples)
        instance.notes.update(notes)
        return instance

    def iter_known(self) -> Iterable[Tuple[int, str]]:
        """Yield ``(opcode, mnemonic)`` pairs for known entries."""

        for opcode, mnemonic in self.mnemonics.items():
            yield opcode, mnemonic


def _iter_handler_candidates(bootstrap_snippet: str) -> Iterator[Tuple[int, str, float, Tuple[str, ...]]]:
    """Yield mnemonic candidates gathered from handler patterns."""

    try:
        from src.tools.parser_tracer import match_handler_patterns
    except ImportError:  # pragma: no cover - should not happen during tests
        LOGGER.debug("parser_tracer not available; handler suggestions disabled")
        return

    matches = match_handler_patterns(bootstrap_snippet)
    for match in matches:
        scores: Dict[str, float] = {}
        reasons: Dict[str, List[str]] = {}

        def bump(mnemonic: str, weight: float, reason: str) -> None:
            if not mnemonic or weight <= 0:
                return
            key = mnemonic.upper()
            current = scores.get(key, 0.0)
            if weight > current:
                scores[key] = weight
            reasons.setdefault(key, []).append(reason)

        name = match.handler
        body = match.body or ""

        for rank, mnemonic in enumerate(match.mnemonics, start=1):
            weight = 0.8 if rank == 1 else max(0.4, 0.6 / rank)
            bump(mnemonic, weight, f"hint-rank{rank}")

        lowered = name.lower()
        for pattern, mnemonic, weight, reason in _HANDLER_NAME_HINTS:
            if pattern.search(lowered):
                bump(mnemonic, weight, reason)

        for pattern, mnemonic, weight, reason in _HANDLER_BODY_HINTS:
            if pattern.search(body):
                bump(mnemonic, weight, reason)

        baseline = _LURAPH_1442_BASELINE.get(match.opcode)
        if baseline:
            mnemonic, weight = baseline
            bump(mnemonic, weight, "baseline:v14.4.2")

        if not scores:
            continue

        for mnemonic, weight in scores.items():
            yield match.opcode, mnemonic, weight, tuple(sorted(set(reasons.get(mnemonic, ()))))


def suggest_map_from_handlers(bootstrap_snippet: str) -> List[MapCandidate]:
    """Return opcode map suggestions derived from handler snippets.

    The function consumes the raw bootstrap text and uses the parser tracer to
    locate ``if opcode == N then handler()`` branches.  Each handler is scored
    using naming and body heuristics (including v14.4.2-specific spellings).
    The resulting opcode->mnemonic assignments are combined into one or more
    :class:`MapCandidate` instances ordered by score.
    """

    opcode_candidates: Dict[int, List[Tuple[str, float, Tuple[str, ...]]]] = {}
    for opcode, mnemonic, weight, reasons in _iter_handler_candidates(bootstrap_snippet):
        opcode_candidates.setdefault(opcode, []).append((mnemonic, weight, reasons))

    if not opcode_candidates:
        return []

    for options in opcode_candidates.values():
        options.sort(key=lambda item: (-item[1], item[0]))

    def _build_candidate(selection: Mapping[int, Tuple[str, float, Tuple[str, ...]]]) -> MapCandidate:
        mapping = {opcode: data[0] for opcode, data in selection.items()}
        mapped_score = score_map(mapping)
        aggregate_weight = sum(data[1] for data in selection.values())
        reasons: List[str] = []
        for opcode, (_, weight, info) in selection.items():
            base_reason = f"opcode:{opcode}:weight={weight:.2f}"
            reasons.append(base_reason)
            reasons.extend(f"opcode:{opcode}:{detail}" for detail in info)
        return MapCandidate(
            mapping=mapping,
            score=mapped_score,
            reasons=tuple(sorted(set(reasons))),
            aggregate_weight=aggregate_weight,
        )

    top_selection: Dict[int, Tuple[str, float, Tuple[str, ...]]] = {
        opcode: options[0] for opcode, options in opcode_candidates.items()
    }
    candidates: List[MapCandidate] = [_build_candidate(top_selection)]

    # Provide alternates by swapping the best choice for ambiguous opcodes.
    for opcode, options in opcode_candidates.items():
        for alternative in options[1:3]:
            alt_selection = dict(top_selection)
            alt_selection[opcode] = alternative
            candidate = _build_candidate(alt_selection)
            if all(candidate.mapping != existing.mapping for existing in candidates):
                candidates.append(candidate)

    candidates.sort(
        key=lambda item: (
            -item.score,
            -item.aggregate_weight,
            sorted(item.mapping.items()),
        )
    )
    return candidates


def score_map(mapping: Mapping[int, str]) -> float:
    """Score a mapping using mnemonic coverage heuristics."""

    if not mapping:
        return 0.0

    total = 0.0
    for mnemonic in mapping.values():
        weight = _CORE_MNEMONIC_WEIGHTS.get(mnemonic.upper(), _GENERIC_WEIGHT)
        total += weight

    base = total / max(len(mapping), 1)
    coverage_bonus = min(0.2, 0.03 * len(mapping))
    score = min(1.0, base + coverage_bonus)
    return round(score, 3)


def apply_map_to_disasm(mapping: Mapping[int, str], disassembly: Iterable[Mapping[str, int] | object]) -> List[Dict[str, object]]:
    """Attach mnemonics from *mapping* to a disassembly stream.

    ``disassembly`` may contain :class:`src.vm.disassembler.Instruction`
    instances or any mapping providing ``opcode`` and operand keys.
    """

    applied: List[Dict[str, object]] = []
    for entry in disassembly:
        if hasattr(entry, "as_dict"):
            data = dict(entry.as_dict())  # type: ignore[assignment]
        elif isinstance(entry, Mapping):
            data = dict(entry)
        else:  # pragma: no cover - defensive branch
            raise TypeError("disassembly entries must be mappings or Instruction objects")

        opcode_value = int(data.get("opcode", 0))
        mnemonic = mapping.get(opcode_value)
        if mnemonic is None:
            mnemonic = f"OP_{opcode_value:02X}"
        data["mnemonic"] = mnemonic
        applied.append(data)
    return applied


def persist_candidate(candidate: MapCandidate, *, name: str, output_dir: Optional[Path] = None) -> Path:
    """Persist a mapping candidate to ``out/opcode_maps``.

    The resulting JSON stores the score, reasons, and the standard
    :class:`OpcodeMap.as_dict` payload for easy reuse.
    """

    destination_dir = output_dir or OUTPUT_DIR
    destination_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "score": candidate.score,
        "reasons": list(candidate.reasons),
        "aggregate_weight": candidate.aggregate_weight,
        "map": {"mnemonics": {str(op): mn for op, mn in candidate.mapping.items()}},
    }
    path = destination_dir / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("wrote opcode map candidate to %s", path)
    return path


def load_map(path: Path) -> OpcodeMap:
    """Load an :class:`OpcodeMap` from ``path``."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if "map" in payload:
        map_payload = payload["map"]
    else:
        map_payload = payload
    return OpcodeMap.from_dict(map_payload)


def build_cli_parser() -> "argparse.ArgumentParser":  # pragma: no cover - exercised indirectly
    import argparse

    parser = argparse.ArgumentParser(description="Opcode map helper utilities")
    sub = parser.add_subparsers(dest="command", required=True)

    suggest = sub.add_parser("suggest", help="Suggest mappings from a bootstrap snippet")
    suggest.add_argument("bootstrap", type=Path, help="Path to bootstrap snippet")
    suggest.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="Directory for map JSON output")
    suggest.add_argument("--base-name", type=str, default="candidate", help="Base filename for generated maps")
    suggest.add_argument("--limit", type=int, default=3, help="Maximum number of suggestions to persist")

    inspect = sub.add_parser("inspect", help="Pretty-print one or more map files")
    inspect.add_argument("paths", nargs="+", type=Path, help="Map JSON files to inspect")

    return parser


def _cmd_suggest(args: Mapping[str, object]) -> int:
    bootstrap_path = Path(args["bootstrap"])  # type: ignore[index]
    text = bootstrap_path.read_text(encoding="utf-8")
    candidates = suggest_map_from_handlers(text)
    if not candidates:
        LOGGER.warning("no opcode handlers detected in %s", bootstrap_path)
        return 1

    limit = int(args.get("limit", 3))
    output_dir = Path(args.get("output_dir", OUTPUT_DIR))
    base_name = str(args.get("base_name", "candidate"))

    for index, candidate in enumerate(candidates[:limit], start=1):
        persist_candidate(candidate, name=f"{base_name}-{index:02d}", output_dir=output_dir)
    return 0


def _cmd_inspect(args: Mapping[str, object]) -> int:
    paths: Sequence[Path] = tuple(Path(path) for path in args.get("paths", ()))
    if not paths:
        LOGGER.error("no map paths provided")
        return 1

    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:  # pragma: no cover - defensive
            LOGGER.error("failed to read %s: %s", path, exc)
            continue
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            LOGGER.error("invalid JSON in %s: %s", path, exc)
            continue

        map_payload = payload.get("map", payload)
        mnemonics = map_payload.get("mnemonics", {})
        score = payload.get("score")
        if score is not None:
            print(f"== {path.name} (score={score})")
        else:
            print(f"== {path.name}")
        for opcode_str, mnemonic in sorted(mnemonics.items(), key=lambda item: int(item[0])):
            print(f"  {int(opcode_str):02d}: {mnemonic}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:  # pragma: no cover - thin wrapper
    parser = build_cli_parser()
    args = parser.parse_args(argv)
    if args.command == "suggest":
        return _cmd_suggest(vars(args))
    if args.command == "inspect":
        return _cmd_inspect(vars(args))
    parser.error(f"unsupported command: {args.command}")
    return 2


__all__ = [
    "MapCandidate",
    "OpcodeMap",
    "Operands",
    "apply_map_to_disasm",
    "build_cli_parser",
    "load_map",
    "main",
    "persist_candidate",
    "score_map",
    "suggest_map_from_handlers",
]
