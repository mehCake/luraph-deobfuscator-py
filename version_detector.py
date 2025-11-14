from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Tuple, FrozenSet

from src.versions import iter_descriptors
from string_decryptor import detect_v14_3_string_decoder


_V14_3_DOUBLE_PACK_HEADER_RE = re.compile(
    r"\bo\s*=\s*\(function\(\).*?I\(\s*['\"]<I\\52",
    re.IGNORECASE | re.DOTALL,
)
_V14_3_DOUBLE_PACK_HELPER_RE = re.compile(
    r"\bt3\s*=\s*function\(\).*?I\(\s*['\"]<\\z",
    re.IGNORECASE | re.DOTALL,
)


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

_LURAPH_V14_3_BANNER_RE = re.compile(
    r"protected\s+using\s+Luraph\s+Obfuscator\s+v14\.3",
    re.IGNORECASE,
)
_LURAPH_V14_3_WRAPPER_RE = re.compile(
    r"return\s*\(\s*function\s*\(K\s*,\s*e\s*,\s*n\s*,\s*a",
    re.IGNORECASE,
)
_LURAPH_V14_3_DISPATCH_DECL_RE = re.compile(
    r"local\s+function\s+N\s*\(\s*Y\s*,\s*g\s*\)",
    re.IGNORECASE,
)
_LURAPH_V14_3_DISPATCH_TABLE_RE = re.compile(r"D\s*\[\s*_\s*\]", re.IGNORECASE)

_BANNER_VERSION_MAP = {
    "14.4.1": "luraph_v14_4_initv4",
    "14.4": "luraph_v14_4_initv4",
    "14.2": "luraph_v14_2_json",
    "14.1": "v14.1",
    "14.0.2": "v14.0.2",
    "14.0": "v14.0.2",
}


class VersionFeature(str, Enum):
    """Feature flags exposed by :class:`VersionDetector`."""

    LURAPH_V14_3_VM = "luraph_v14_3_vm"

@dataclass(frozen=True)
class VersionInfo:
    """Description of a detected Luraph VM version."""

    name: str
    major: int
    minor: int
    features: frozenset[str]
    confidence: float
    matched_categories: Tuple[str, ...] = ()
    profile: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_unknown(self) -> bool:
        return self.name == "unknown"

    def __hash__(self) -> int:
        return hash(
            (
                self.name,
                self.major,
                self.minor,
                self.features,
                round(self.confidence, 9),
                self.matched_categories,
            )
        )


class VersionDetector:
    """Heuristic detector for Luraph versions using repository descriptors."""

    _CATEGORY_FEATURE_MAP = {
        "signatures": "banner",
        "loaders": "loader",
        "upvalues": "upvalues",
        "long_strings": "container",
        "constants": "constants",
        "prologues": "prologue",
        "dispatch": "vm_dispatch",
    }

    def __init__(self, descriptors: Mapping[str, Mapping[str, object]] | None = None) -> None:
        if descriptors is None:
            descriptors = {name: desc for name, desc in iter_descriptors()}
        self._descriptors: Dict[str, Mapping[str, object]] = dict(descriptors)
        self._all_features: FrozenSet[str] = self._collect_all_features()

    def detect(self, content: str, *, from_json: bool = False) -> VersionInfo:
        manual = _detect_luraph_v14_3_vm(content)
        if manual is not None:
            return manual

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
        if name == VersionFeature.LURAPH_V14_3_VM.value:
            categories.append("standalone_vm")
            categories.append("vm_dispatch")
            features.add(VersionFeature.LURAPH_V14_3_VM.value)
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
        features.add(VersionFeature.LURAPH_V14_3_VM.value)
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


def _detect_luraph_v14_3_vm(content: str) -> VersionInfo | None:
    if not _LURAPH_V14_3_BANNER_RE.search(content):
        return None
    if not _LURAPH_V14_3_WRAPPER_RE.search(content):
        return None
    if not _LURAPH_V14_3_DISPATCH_DECL_RE.search(content):
        return None
    if not _LURAPH_V14_3_DISPATCH_TABLE_RE.search(content):
        return None
    features = frozenset(
        {VersionFeature.LURAPH_V14_3_VM.value, "vm_dispatch", "banner", "prologue"}
    )
    profile: Dict[str, Any] = {}
    if detect_v14_3_double_packed_constants(content):
        profile["double_packed_constants"] = True
    decoder = detect_v14_3_string_decoder(content)
    if decoder is not None:
        profile["string_decoder"] = decoder.to_dict()
    return VersionInfo(
        name=VersionFeature.LURAPH_V14_3_VM.value,
        major=14,
        minor=3,
        features=features,
        confidence=1.0,
        matched_categories=("signatures", "prologues", "dispatch"),
        profile=profile,
    )


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


def detect_v14_3_double_packed_constants(content: str) -> bool:
    """Return ``True`` if *content* contains the v14.3 double-pack helpers."""

    if not _LURAPH_V14_3_BANNER_RE.search(content):
        return False
    if not _V14_3_DOUBLE_PACK_HEADER_RE.search(content):
        return False
    if not _V14_3_DOUBLE_PACK_HELPER_RE.search(content):
        return False
    return True


__all__ = [
    "VersionDetector",
    "VersionInfo",
    "VersionFeature",
    "detect_v14_3_double_packed_constants",
]
