from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Tuple

from src.versions import iter_descriptors


@dataclass(frozen=True)
class VersionInfo:
    """Description of a detected Luraph VM version."""

    name: str
    major: int
    minor: int
    features: frozenset[str]
    confidence: float
    matched_categories: Tuple[str, ...] = ()

    @property
    def is_unknown(self) -> bool:
        return self.name == "unknown"


class VersionDetector:
    """Heuristic detector for Luraph versions using repository descriptors."""

    _CATEGORY_FEATURE_MAP = {
        "signatures": "banner",
        "loaders": "loader",
        "upvalues": "upvalues",
        "long_strings": "container",
        "constants": "constants",
        "prologues": "prologue",
    }

    def __init__(self, descriptors: Mapping[str, Mapping[str, object]] | None = None) -> None:
        if descriptors is None:
            descriptors = {name: desc for name, desc in iter_descriptors()}
        self._descriptors: Dict[str, Mapping[str, object]] = dict(descriptors)

    def detect(self, content: str) -> VersionInfo:
        best = VersionInfo("unknown", 0, 0, frozenset(), 0.0, ())
        best_score = 0
        for name, descriptor in self._descriptors.items():
            heuristics = descriptor.get("heuristics", {})
            if not isinstance(heuristics, Mapping):
                continue
            score = 0
            total = 0
            categories: list[str] = []
            features: set[str] = set()
            for category, patterns in heuristics.items():
                if not isinstance(patterns, Iterable):
                    continue
                category_hits = 0
                for pattern in patterns:
                    if not isinstance(pattern, str):
                        continue
                    total += 1
                    if re.search(pattern, content, re.IGNORECASE):
                        score += 1
                        category_hits += 1
                if category_hits:
                    categories.append(category)
                    feature = self._CATEGORY_FEATURE_MAP.get(category, category)
                    features.add(feature)
            if total == 0:
                continue
            confidence = score / total
            if score > best_score or (score == best_score and confidence > best.confidence):
                major, minor = _parse_version_numbers(name)
                best = VersionInfo(
                    name=name,
                    major=major,
                    minor=minor,
                    features=frozenset(features),
                    confidence=confidence,
                    matched_categories=tuple(categories),
                )
                best_score = score
        return best

    def detect_version(self, content: str) -> VersionInfo:
        return self.detect(content)


def _parse_version_numbers(name: str) -> Tuple[int, int]:
    matches = re.findall(r"\d+", name)
    if not matches:
        return 0, 0
    major = int(matches[0])
    minor = int(matches[1]) if len(matches) > 1 else 0
    return major, minor


__all__ = ["VersionDetector", "VersionInfo"]
