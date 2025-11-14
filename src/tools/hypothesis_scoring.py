"""Hypothesis scoring utilities for pipeline confidence estimation."""

from __future__ import annotations

import math
import statistics
import string
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence, Tuple

__all__ = [
    "HypothesisScore",
    "estimate_english_likeliness",
    "estimate_lua_token_density",
    "score_mapping_coherence",
    "score_parity_outcome",
    "score_pipeline_hypothesis",
]

_LUA_KEYWORDS = {
    "and",
    "break",
    "do",
    "else",
    "elseif",
    "end",
    "false",
    "for",
    "function",
    "goto",
    "if",
    "in",
    "local",
    "nil",
    "not",
    "or",
    "repeat",
    "return",
    "then",
    "true",
    "until",
    "while",
}

_COMMON_ENGLISH_FRAGMENTS: Tuple[str, ...] = (
    " the ",
    " and ",
    "tion",
    "ing",
    " for ",
    " with ",
)

_PRINTABLE = set(string.printable)


@dataclass(frozen=True)
class HypothesisScore:
    """Weighted combination of confidence signals.

    Attributes
    ----------
    overall:
        Final confidence score clamped to the ``[0.0, 1.0]`` range.
    components:
        Mapping of individual component contributions before weights are applied.
    notes:
        Additional context highlighting weak signals or missing artefacts.
    """

    overall: float
    components: Mapping[str, float]
    notes: Tuple[str, ...] = ()


def _mean(values: Sequence[float]) -> float:
    valid = [value for value in values if value is not None]
    if not valid:
        return 0.0
    try:
        return float(statistics.fmean(valid))
    except statistics.StatisticsError:  # pragma: no cover - defensive
        return float(sum(valid) / max(len(valid), 1))


def estimate_english_likeliness(text: str) -> float:
    """Estimate how closely *text* resembles readable English.

    The score favours printable ASCII, a healthy proportion of letters/spaces,
    and the presence of common English fragments.
    """

    if not text:
        return 0.0

    length = len(text)
    printable = sum(1 for char in text if char in _PRINTABLE)
    letters_spaces = sum(1 for char in text if char.isalpha() or char.isspace())
    vowels = sum(1 for char in text if char.lower() in "aeiou")

    printable_ratio = printable / length
    alpha_ratio = letters_spaces / length
    vowel_ratio = vowels / max(letters_spaces, 1)

    fragment_bonus = 0.0
    lowered = text.lower()
    for fragment in _COMMON_ENGLISH_FRAGMENTS:
        if fragment in lowered:
            fragment_bonus += 0.08
    fragment_bonus = min(fragment_bonus, 0.24)

    score = (printable_ratio * 0.5) + (alpha_ratio * 0.35) + (vowel_ratio * 0.15) + fragment_bonus
    return max(0.0, min(1.0, score))


def estimate_lua_token_density(text: str) -> float:
    """Return a heuristic Lua token density score for *text*."""

    if not text:
        return 0.0

    tokens = [token for token in text.replace("_", " ").split() if token]
    if not tokens:
        return 0.0

    keyword_hits = sum(1 for token in tokens if token.strip().lower() in _LUA_KEYWORDS)
    identifier_hits = sum(1 for token in tokens if token[0].isalpha())

    base_ratio = keyword_hits / len(tokens)
    identifier_ratio = identifier_hits / len(tokens)

    score = (base_ratio * 0.7) + (identifier_ratio * 0.3)
    return max(0.0, min(1.0, score * 2.0))


def score_mapping_coherence(candidates: Sequence[Mapping[str, object]]) -> float:
    """Score opcode mapping coherence from candidate dictionaries."""

    best = 0.0
    for candidate in candidates:
        confidence_raw = candidate.get("confidence", 0.0)
        try:
            confidence = float(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0.0
        selections = candidate.get("selections")
        if isinstance(selections, Mapping) and selections:
            avg = _mean(
                [
                    float(entry.get("confidence", 0.0))
                    for entry in selections.values()
                    if isinstance(entry, Mapping)
                ]
            )
            confidence = (confidence * 0.7) + (avg * 0.3)
        best = max(best, confidence)
    return max(0.0, min(1.0, best))


def score_parity_outcome(parity_info: Optional[Mapping[str, object]]) -> float:
    """Return a normalised score for a parity report summary."""

    if not parity_info:
        return 0.0

    success = bool(parity_info.get("success"))
    limit_raw = parity_info.get("limit") or parity_info.get("byte_limit") or 0
    prefix_raw = parity_info.get("matching_prefix") or parity_info.get("matched_bytes") or 0
    try:
        limit = int(limit_raw)
    except (TypeError, ValueError):
        limit = 0
    try:
        prefix = int(prefix_raw)
    except (TypeError, ValueError):
        prefix = 0
    if limit <= 0:
        limit = max(prefix, 1)

    ratio = max(0.0, min(1.0, prefix / limit))
    if success:
        return min(1.0, 0.7 + (ratio * 0.3))
    return ratio * 0.6


def score_pipeline_hypothesis(
    *,
    pipeline_confidence: float,
    english_scores: Sequence[float] | None = None,
    lua_scores: Sequence[float] | None = None,
    parity: Mapping[str, object] | None = None,
    mapping_candidates: Sequence[Mapping[str, object]] | None = None,
) -> HypothesisScore:
    """Combine heterogeneous signals into a unified hypothesis score."""

    english_mean = _mean(list(english_scores or ()))
    lua_mean = _mean(list(lua_scores or ()))
    parity_score = score_parity_outcome(parity)
    mapping_score = score_mapping_coherence(mapping_candidates or ())

    pipeline_component = max(0.0, min(1.0, float(pipeline_confidence)))

    components = {
        "pipeline": pipeline_component,
        "english": english_mean,
        "lua": lua_mean,
        "parity": parity_score,
        "mapping": mapping_score,
    }

    weights = {
        "pipeline": 0.35,
        "english": 0.2,
        "lua": 0.2,
        "parity": 0.15,
        "mapping": 0.1,
    }

    overall = sum(components[name] * weight for name, weight in weights.items())
    overall = max(0.0, min(1.0, overall))

    notes = []
    if parity and parity_score < 0.4:
        notes.append("Parity coverage weak or unavailable")
    if mapping_candidates and mapping_score < 0.4:
        notes.append("Opcode map candidates are low confidence")
    if not english_scores:
        notes.append("No textual payload available for English scoring")
    if not lua_scores:
        notes.append("No textual payload available for Lua token scoring")

    return HypothesisScore(overall=overall, components=components, notes=tuple(notes))
