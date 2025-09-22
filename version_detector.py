from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Tuple, FrozenSet

from src.versions import iter_descriptors


_JSON_INIT_RE = re.compile(r"(?:do\s+)?local\s+init_fn\s*=\s*function", re.IGNORECASE)
_JSON_SCRIPT_KEY_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*getgenv\(\)\.script_key",
    re.IGNORECASE,
)

_INITV4_INIT_RE = re.compile(r"\binit_fn\s*\(", re.IGNORECASE)
_INITV4_SCRIPT_KEY_RE = re.compile(
    r"\bscript_key\s*=\s*(?:script_key\s*or\s*)?(?:getgenv\(\)\.script_key|['\"]([^'\"]*)['\"])",
    re.IGNORECASE,
)
_INITV4_ALPHABET_CHARS = re.escape(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+,-./:;<=>?@[]^_`{|}~"
)

_INITV4_BLOB_RE = re.compile(r"s8W-[!-~]{64,}")
_INITV4_JSON_BLOB_RE = re.compile(r"\[\s*['\"](s8W-[!-~]{128,})['\"]", re.IGNORECASE)
_INITV4_ALPHABET_RE = re.compile(
    r"alphabet\s*=\s*['\"]([0-9A-Za-z!#$%&()*+,\-./:;<=>?@\[\]^_`{|}~]{85,})['\"]",
    re.IGNORECASE,
)
_INITV4_JSON_ARRAY_KEY_RE = re.compile(
    rf"\"(?:bytecode|payload|chunks)\"\s*:\s*\[[^\]]*\"[{_INITV4_ALPHABET_CHARS}]{{80,}}\"",
    re.IGNORECASE,
)
_INITV4_QUOTED_CHUNK_RE = re.compile(rf'(["\'])([{_INITV4_ALPHABET_CHARS}]{{80,}})\1')
_INITV4_LONG_BLOB_RE = re.compile(rf"[{_INITV4_ALPHABET_CHARS}]{{160,}}")
_INITV4_CHUNK_ASSIGN_RE = re.compile(r"local\s+chunk_\d+\s*=")
_INITV4_CHUNK_CONCAT_RE = re.compile(r"chunk_\d+\s*\.\.\s*chunk_\d+")
_BASE64_CHARSET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")

_VERSION_BANNER_RE = re.compile(
    r"(?:lura\.ph|Luraph)\s*(?:Obfuscator\s*)?(?:v(?:ersion)?\s*)?(\d+(?:\.\d+)*)",
    re.IGNORECASE,
)

_BANNER_VERSION_MAP = {
    "14.4.1": "luraph_v14_4_initv4",
    "14.4": "luraph_v14_4_initv4",
    "14.2": "luraph_v14_2_json",
    "14.1": "v14.1",
    "14.0.2": "v14.0.2",
    "14.0": "v14.0.2",
}

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
        self._all_features: FrozenSet[str] = self._collect_all_features()

    def detect(self, content: str, *, from_json: bool = False) -> VersionInfo:
        banner_version = _resolve_banner_version(content)
        if banner_version:
            return self.info_for_name(banner_version)

        if from_json and _JSON_INIT_RE.search(content) and _JSON_SCRIPT_KEY_RE.search(content):
            return self.info_for_name("luraph_v14_2_json")

        if _looks_like_initv4(content):
            return self.info_for_name("luraph_v14_4_initv4")

        best = VersionInfo("unknown", 0, 0, frozenset(), 0.0, ())
        best_score = 0
        best_priority = -1
        for name, descriptor in self._descriptors.items():
            heuristics = descriptor.get("heuristics", {})
            if not isinstance(heuristics, Mapping):
                continue
            priority = 0
            raw_priority = descriptor.get("priority") if isinstance(descriptor, Mapping) else None
            if isinstance(raw_priority, (int, float)):
                priority = int(raw_priority)
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
                    feature = self._CATEGORY_FEATURE_MAP.get(category) or category
                    features.add(feature)
            if total == 0:
                continue
            confidence = score / total
            better_score = score > best_score
            better_conf = score == best_score and confidence > best.confidence
            better_priority = (
                score == best_score
                and abs(confidence - best.confidence) < 1e-9
                and priority > best_priority
            )
            if better_score or better_conf or better_priority:
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
                best_priority = priority
        return best

    def detect_version(self, content: str, *, from_json: bool = False) -> VersionInfo:
        return self.detect(content, from_json=from_json)

    @property
    def all_features(self) -> FrozenSet[str]:
        """Return the union of all feature flags known to the detector."""

        return self._all_features

    def info_for_name(self, name: str) -> VersionInfo:
        """Return a :class:`VersionInfo` for ``name`` based on stored descriptors."""

        descriptor = self._descriptors.get(name)
        features: set[str] = set()
        categories: list[str] = []
        if isinstance(descriptor, Mapping):
            heuristics = descriptor.get("heuristics", {})
            if isinstance(heuristics, Mapping):
                for category in heuristics.keys():
                    categories.append(category)
                    feature = self._CATEGORY_FEATURE_MAP.get(category) or category
                    features.add(feature)
        major, minor = _parse_version_numbers(name)
        return VersionInfo(
            name=name,
            major=major,
            minor=minor,
            features=frozenset(features),
            confidence=1.0 if descriptor else 0.0,
            matched_categories=tuple(categories),
        )

    def _collect_all_features(self) -> FrozenSet[str]:
        features: set[str] = set()
        for descriptor in self._descriptors.values():
            heuristics = descriptor.get("heuristics", {}) if isinstance(descriptor, Mapping) else {}
            if not isinstance(heuristics, Mapping):
                continue
            for category in heuristics.keys():
                feature = self._CATEGORY_FEATURE_MAP.get(category) or category
                features.add(feature)
        return frozenset(features)


def _parse_version_numbers(name: str) -> Tuple[int, int]:
    matches = re.findall(r"\d+", name)
    if not matches:
        return 0, 0
    major = int(matches[0])
    minor = int(matches[1]) if len(matches) > 1 else 0
    return major, minor


def _looks_like_initv4(content: str) -> bool:
    if not _INITV4_INIT_RE.search(content):
        return False
    if not _INITV4_SCRIPT_KEY_RE.search(content):
        return False

    if _INITV4_ALPHABET_RE.search(content):
        return True

    if _INITV4_BLOB_RE.search(content):
        return True

    if _INITV4_JSON_BLOB_RE.search(content):
        return True

    if _INITV4_JSON_ARRAY_KEY_RE.search(content):
        return True

    chunk_match = _INITV4_QUOTED_CHUNK_RE.search(content)
    if chunk_match:
        inner = chunk_match.group(2)
        if any(char not in _BASE64_CHARSET for char in inner):
            return True
        if _INITV4_CHUNK_ASSIGN_RE.search(content) and _INITV4_CHUNK_CONCAT_RE.search(content):
            return True

    long_match = _INITV4_LONG_BLOB_RE.search(content)
    if long_match and any(char not in _BASE64_CHARSET for char in long_match.group(0)):
        return True

    if _INITV4_CHUNK_ASSIGN_RE.search(content) and _INITV4_CHUNK_CONCAT_RE.search(content):
        return True

    return False


def _resolve_banner_version(content: str) -> str | None:
    matches = list(_VERSION_BANNER_RE.findall(content))
    if not matches:
        return None
    for raw in matches:
        mapped = _map_banner_version(raw)
        if mapped:
            return mapped
    return None


def _map_banner_version(raw: str) -> str | None:
    candidate = raw.strip()
    if not candidate:
        return None
    parts = candidate.split('.')
    while parts:
        key = '.'.join(parts)
        mapped = _BANNER_VERSION_MAP.get(key)
        if mapped:
            return mapped
        # drop trailing zero segments to allow 14.4.0 -> 14.4
        if parts[-1] == '0':
            parts = parts[:-1]
            continue
        parts = parts[:-1]
    return _BANNER_VERSION_MAP.get(candidate)


__all__ = ["VersionDetector", "VersionInfo"]
