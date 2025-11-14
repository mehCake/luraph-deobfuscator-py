"""Opcode map differencing and adaptation helpers.

This module compares two opcode mapping definitions – typically produced by the
``src.vm.opcode_map`` helpers – and produces suggestions that explain how to
translate IR or disassembly written against the *source* mapping into the
*target* mapping.  The implementation is intentionally static: it never executes
obfuscated code and it never persists secrets such as session keys.

Usage mirrors the other tooling modules in ``src.tools``.  The public API exposes
``diff_opcode_maps`` for programmatic consumption plus a small CLI that writes a
JSON report describing the suggested opcode conversions.
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

LOGGER = logging.getLogger(__name__)

try:  # Optional import; the tooling works without the VM helpers at runtime.
    from src.vm.opcode_map import OpcodeMap
except Exception:  # pragma: no cover - exercised when VM package unavailable
    OpcodeMap = None  # type: ignore[assignment]

__all__ = [
    "MappingCandidate",
    "MappingDiffEntry",
    "MappingDiffResult",
    "diff_opcode_maps",
    "load_mapping",
    "build_arg_parser",
    "main",
]


@dataclass(frozen=True)
class MappingCandidate:
    """Represents a potential target opcode for a given source mnemonic."""

    target_opcode: int
    target_mnemonic: str
    score: float
    reasons: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "target_opcode": self.target_opcode,
            "target_mnemonic": self.target_mnemonic,
            "score": self.score,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class MappingDiffEntry:
    """Describes suggestions for adapting a single source opcode."""

    source_opcode: int
    source_mnemonic: str
    best: Optional[MappingCandidate]
    alternatives: Tuple[MappingCandidate, ...]

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "source_opcode": self.source_opcode,
            "source_mnemonic": self.source_mnemonic,
            "alternatives": [candidate.to_dict() for candidate in self.alternatives],
        }
        if self.best is not None:
            payload["best"] = self.best.to_dict()
        else:
            payload["best"] = None
        return payload


@dataclass(frozen=True)
class MappingDiffResult:
    """Aggregate result describing how to adapt one mapping into another."""

    source_name: str
    target_name: str
    suggestions: Tuple[MappingDiffEntry, ...]
    unmatched_source: Tuple[Tuple[int, str], ...]
    unmatched_target: Tuple[Tuple[int, str], ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "source": self.source_name,
            "target": self.target_name,
            "suggestions": [entry.to_dict() for entry in self.suggestions],
            "unmatched_source": [list(pair) for pair in self.unmatched_source],
            "unmatched_target": [list(pair) for pair in self.unmatched_target],
        }


_SYNONYM_GROUPS: Tuple[Tuple[str, ...], ...] = (
    ("LOADK", "LOADCONST", "LOAD_CONST", "LOAD_CONSTANT"),
    ("CALL", "INVOKE", "CALLFUNC"),
    ("RETURN", "RET"),
    ("JMP", "JUMP"),
    ("MOVE", "SETREG", "MOV"),
    ("EQ", "ISEQ", "TESTEQ"),
)

_SYNONYM_SCORE = 0.6
_PARTIAL_OVERLAP_WEIGHT = 0.45
_NUMERIC_PROXIMITY_WEIGHT = 0.1
_DEFAULT_THRESHOLD = 0.45
_DEFAULT_TOP = 3


def _tokenise(mnemonic: str) -> Tuple[str, ...]:
    tokens = []
    token = []
    for char in mnemonic:
        if char.isalnum():
            token.append(char)
        elif token:
            tokens.append("".join(token))
            token = []
    if token:
        tokens.append("".join(token))
    return tuple(token for token in tokens if token)


def _normalise(mnemonic: str) -> str:
    return mnemonic.replace("_", "").upper()


def _synonym_score(lhs: str, rhs: str) -> Optional[str]:
    for group in _SYNONYM_GROUPS:
        upper_group = tuple(item.upper() for item in group)
        if lhs in upper_group and rhs in upper_group:
            return "synonym"
    return None


def _score_pair(source_opcode: int, source: str, target_opcode: int, target: str) -> MappingCandidate:
    lhs = _normalise(source)
    rhs = _normalise(target)
    reasons: List[str] = []
    score = 0.0

    if lhs == rhs:
        reasons.append("exact mnemonic match")
        score = 1.0
    else:
        synonym = _synonym_score(lhs, rhs)
        if synonym:
            score += _SYNONYM_SCORE
            reasons.append(f"{synonym} group")

        lhs_tokens = set(_tokenise(lhs))
        rhs_tokens = set(_tokenise(rhs))
        overlap = lhs_tokens & rhs_tokens
        if overlap:
            overlap_score = _PARTIAL_OVERLAP_WEIGHT * (
                len(overlap) / max(len(lhs_tokens) or 1, len(rhs_tokens) or 1)
            )
            score += overlap_score
            reasons.append(
                "token overlap: " + ",".join(sorted(overlap))
            )

        numeric_distance = abs(source_opcode - target_opcode)
        if numeric_distance and numeric_distance <= 3:
            score += _NUMERIC_PROXIMITY_WEIGHT
            reasons.append(f"numeric proximity {numeric_distance}")

    score = min(score, 1.0)
    return MappingCandidate(
        target_opcode=target_opcode,
        target_mnemonic=target,
        score=score,
        reasons=tuple(reasons),
    )


def _rank_candidates(
    source_opcode: int,
    source_mnemonic: str,
    target_map: Mapping[int, str],
    *,
    top: int,
) -> Tuple[MappingCandidate, ...]:
    ranked: List[MappingCandidate] = []
    for target_opcode, target_mnemonic in target_map.items():
        candidate = _score_pair(source_opcode, source_mnemonic, target_opcode, target_mnemonic)
        if candidate.score <= 0.0:
            continue
        ranked.append(candidate)
    ranked.sort(key=lambda item: (-item.score, item.target_opcode))
    return tuple(ranked[:top])


def diff_opcode_maps(
    source_map: Mapping[int, str],
    target_map: Mapping[int, str],
    *,
    source_name: str = "source",
    target_name: str = "target",
    min_score: float = _DEFAULT_THRESHOLD,
    top: int = _DEFAULT_TOP,
) -> MappingDiffResult:
    """Compute suggestions that translate ``source_map`` opcodes to ``target_map``.

    ``min_score`` controls the minimum confidence required before a mapping is
    considered actionable.  ``top`` controls how many ranked candidates to record
    per opcode for inspection purposes.
    """

    if top <= 0:
        raise ValueError("top must be positive")
    if not 0.0 <= min_score <= 1.0:
        raise ValueError("min_score must live in the [0, 1] interval")

    used_targets: Set[int] = set()
    suggestions: List[MappingDiffEntry] = []
    unmatched_source: List[Tuple[int, str]] = []

    for source_opcode, source_mnemonic in sorted(source_map.items()):
        ranked = _rank_candidates(source_opcode, source_mnemonic, target_map, top=top)
        best = next((candidate for candidate in ranked if candidate.score >= min_score), None)

        if best is None:
            unmatched_source.append((source_opcode, source_mnemonic))
            suggestions.append(
                MappingDiffEntry(
                    source_opcode=source_opcode,
                    source_mnemonic=source_mnemonic,
                    best=None,
                    alternatives=ranked,
                )
            )
            continue

        used_targets.add(best.target_opcode)
        alternatives = tuple(candidate for candidate in ranked if candidate != best)
        suggestions.append(
            MappingDiffEntry(
                source_opcode=source_opcode,
                source_mnemonic=source_mnemonic,
                best=best,
                alternatives=alternatives,
            )
        )

    unmatched_target = [
        (opcode, mnemonic)
        for opcode, mnemonic in sorted(target_map.items())
        if opcode not in used_targets
    ]

    return MappingDiffResult(
        source_name=source_name,
        target_name=target_name,
        suggestions=tuple(suggestions),
        unmatched_source=tuple(unmatched_source),
        unmatched_target=tuple(unmatched_target),
    )


def _payload_to_mapping(payload: Mapping[str, object]) -> Mapping[int, str]:
    if "mnemonics" in payload:
        raw_mapping = payload["mnemonics"]
    elif "mapping" in payload:
        raw_mapping = payload["mapping"]
    else:
        raise ValueError("opcode map JSON must contain a 'mnemonics' or 'mapping' field")

    mapping: Dict[int, str] = {}
    for key, value in raw_mapping.items():
        try:
            opcode = int(key)
        except (TypeError, ValueError) as exc:  # pragma: no cover - invalid payloads
            raise ValueError(f"opcode {key!r} is not an integer") from exc
        mapping[opcode] = str(value)
    return mapping


def load_mapping(path: Path) -> Mapping[int, str]:
    """Load an opcode mapping JSON file."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if OpcodeMap is not None and "mnemonics" in payload:
        try:
            return OpcodeMap.from_dict(payload).mnemonics
        except Exception:  # pragma: no cover - corrupt payload fallback
            LOGGER.debug("Falling back to raw payload parsing for %s", path)
    return _payload_to_mapping(payload)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare opcode maps and suggest remappings")
    parser.add_argument("source", type=Path, help="Source opcode map JSON (old map)")
    parser.add_argument("target", type=Path, help="Target opcode map JSON (new map)")
    parser.add_argument("--min-score", type=float, default=_DEFAULT_THRESHOLD, help="Minimum score required for a mapping")
    parser.add_argument("--top", type=int, default=_DEFAULT_TOP, help="Number of ranked candidates to retain per opcode")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON destination for the diff report")
    parser.add_argument("--log-level", default="INFO", help="Logging level (default: INFO)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO))

    try:
        source_map = load_mapping(args.source)
        target_map = load_mapping(args.target)
    except (OSError, ValueError) as exc:
        LOGGER.error("Failed to load opcode map: %s", exc)
        return 2

    report = diff_opcode_maps(
        source_map,
        target_map,
        source_name=str(args.source),
        target_name=str(args.target),
        min_score=args.min_score,
        top=args.top,
    )

    destination = args.output
    if destination is None:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
        LOGGER.info("Mapping diff written to %s", destination)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
