"""Shared constants for opcode trust and mandatory operations."""

from __future__ import annotations

__all__ = [
    "MANDATORY_MNEMONICS",
    "MANDATORY_CONFIDENCE_THRESHOLD",
    "is_mandatory_mnemonic",
    "normalise_trust",
    "trust_score",
]


MANDATORY_MNEMONICS = frozenset(
    {
        "LOADK",
        "MOVE",
        "CALL",
        "RETURN",
        "GETTABUP",
        "SETTABUP",
        "JMP",
        "EQ",
        "TESTSET",
    }
)

_TRUST_SCORES = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "heuristic": 0,
}

MANDATORY_CONFIDENCE_THRESHOLD = _TRUST_SCORES["medium"]


def is_mandatory_mnemonic(name: str | None) -> bool:
    """Return ``True`` when *name* denotes a mandatory opcode."""

    if not name:
        return False
    return str(name).upper() in MANDATORY_MNEMONICS


def normalise_trust(value: str | None) -> str:
    """Return a canonical trust label for *value*."""

    if value is None:
        return "heuristic"
    cleaned = str(value).strip()
    if not cleaned:
        return "heuristic"
    lowered = cleaned.lower()
    if lowered in _TRUST_SCORES:
        return lowered
    return cleaned


def trust_score(value: str | None) -> int:
    """Return the numeric confidence score associated with *value*."""

    label = normalise_trust(value)
    return _TRUST_SCORES.get(label, 0)

