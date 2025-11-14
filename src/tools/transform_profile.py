"""Persist and load transform profiles without leaking session keys.

The transform profile is a light-weight record describing the analysis
parameters observed for a particular Luraph payload (e.g. PRGA settings,
permutation tables, opcode map candidates).  Profiles are stored as JSON files
without any sensitive material.  In particular, entries named ``key`` are
rejected to avoid accidentally writing session keys to disk.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping

LOGGER = logging.getLogger(__name__)

__all__ = [
    "TransformProfile",
    "load_profile",
    "save_profile",
]

_DEFAULT_VERSION = "1.0"


def _contains_key_field(payload: Any) -> bool:
    """Return ``True`` if ``payload`` contains a mapping entry named ``key``."""

    if isinstance(payload, MutableMapping):
        for key, value in payload.items():
            if str(key).lower() == "key" or _contains_key_field(value):
                return True
        return False
    if isinstance(payload, Mapping):  # pragma: no cover - defensive branch
        for key in payload.keys():
            if str(key).lower() == "key":
                return True
        return any(_contains_key_field(v) for v in payload.values())
    if isinstance(payload, (list, tuple)):
        return any(_contains_key_field(item) for item in payload)
    return False


def _coerce_permutation(table: Any) -> list[int] | None:
    if table is None:
        return None
    if not isinstance(table, Iterable) or isinstance(table, (str, bytes)):
        raise ValueError("permute_table must be an iterable of integers")
    result: list[int] = []
    for entry in table:
        try:
            result.append(int(entry))
        except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
            raise ValueError(f"invalid permutation entry: {entry!r}") from exc
    return result


def _coerce_scores(scores: Any) -> Dict[str, float]:
    if scores is None:
        return {}
    if not isinstance(scores, Mapping):
        raise ValueError("candidate_scores must be a mapping")
    coerced: Dict[str, float] = {}
    for key, value in scores.items():
        try:
            coerced[str(key)] = float(value)
        except (TypeError, ValueError):
            LOGGER.debug("Non-numeric score for %s preserved as-is", key)
            coerced[str(key)] = value  # type: ignore[assignment]
    return coerced


def _coerce_mapping(value: Any) -> Dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("prga_params must be a mapping if provided")
    return dict(value)


def _coerce_metadata(raw: Any, *, extras: Mapping[str, Any]) -> Dict[str, Any]:
    metadata: Dict[str, Any]
    if raw is None:
        metadata = {}
    elif isinstance(raw, Mapping):
        metadata = dict(raw)
    else:  # pragma: no cover - defensive
        raise ValueError("metadata must be a mapping if provided")
    for key, value in extras.items():
        metadata.setdefault(key, value)
    return metadata


def _migrate_profile_data(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """Normalise legacy transform profile dictionaries."""

    version = str(raw.get("version", _DEFAULT_VERSION))

    prga_params = raw.get("prga_params")
    if prga_params is None:
        prga_params = raw.get("prga")

    permute_table = raw.get("permute_table")
    if permute_table is None:
        permute_table = raw.get("permute") or raw.get("permutation")

    opcode_map_ids = raw.get("opcode_map_ids")
    if opcode_map_ids is None:
        if "opcode_map_id" in raw:
            value = raw["opcode_map_id"]
            if isinstance(value, (list, tuple)):
                opcode_map_ids = list(value)
            else:
                opcode_map_ids = [value]
        elif "opcode_maps" in raw:
            opcode_map_ids = raw["opcode_maps"]

    candidate_scores = raw.get("candidate_scores")
    if candidate_scores is None:
        candidate_scores = raw.get("scores")

    recognised = {
        "version",
        "prga_params",
        "permute_table",
        "permute",
        "permutation",
        "opcode_map_ids",
        "opcode_map_id",
        "opcode_maps",
        "candidate_scores",
        "scores",
        "metadata",
        "prga",
    }
    extras = {k: raw[k] for k in raw.keys() - recognised}

    metadata = _coerce_metadata(raw.get("metadata"), extras=extras)

    return {
        "version": version,
        "prga_params": prga_params,
        "permute_table": permute_table,
        "opcode_map_ids": opcode_map_ids,
        "candidate_scores": candidate_scores,
        "metadata": metadata,
    }


@dataclass(slots=True)
class TransformProfile:
    """In-memory representation of a transform profile."""

    version: str = _DEFAULT_VERSION
    prga_params: Dict[str, Any] | None = None
    permute_table: list[int] | None = None
    opcode_map_ids: list[str] = field(default_factory=list)
    candidate_scores: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"version": self.version}
        if self.prga_params:
            data["prga_params"] = dict(self.prga_params)
        if self.permute_table is not None:
            data["permute_table"] = list(self.permute_table)
        if self.opcode_map_ids:
            data["opcode_map_ids"] = list(self.opcode_map_ids)
        if self.candidate_scores:
            data["candidate_scores"] = dict(self.candidate_scores)
        if self.metadata:
            data["metadata"] = dict(self.metadata)
        return data

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "TransformProfile":
        migrated = _migrate_profile_data(raw)
        permute_table = _coerce_permutation(migrated.get("permute_table"))
        opcode_ids_raw = migrated.get("opcode_map_ids")
        if opcode_ids_raw is None:
            opcode_ids: list[str] = []
        elif isinstance(opcode_ids_raw, (list, tuple)):
            opcode_ids = [str(item) for item in opcode_ids_raw]
        else:
            opcode_ids = [str(opcode_ids_raw)]

        prga = _coerce_mapping(migrated.get("prga_params"))
        scores = _coerce_scores(migrated.get("candidate_scores"))
        metadata = _coerce_metadata(migrated.get("metadata"), extras={})

        return cls(
            version=str(migrated.get("version", _DEFAULT_VERSION)),
            prga_params=prga,
            permute_table=permute_table,
            opcode_map_ids=opcode_ids,
            candidate_scores=scores,
            metadata=metadata,
        )


def save_profile(profile: TransformProfile | Mapping[str, Any], path: Path | str) -> Path:
    """Serialise ``profile`` to ``path`` ensuring no key fields are stored."""

    if isinstance(profile, TransformProfile):
        payload = profile.to_dict()
    elif isinstance(profile, Mapping):
        payload = TransformProfile.from_dict(profile).to_dict()
    else:  # pragma: no cover - defensive
        raise TypeError("profile must be a TransformProfile or mapping")

    if _contains_key_field(payload):
        raise ValueError("transform profiles must not contain fields named 'key'")

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Transform profile saved to %s", destination)
    return destination


def load_profile(path: Path | str) -> TransformProfile:
    """Load and validate a transform profile from ``path``."""

    source = Path(path)
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("profile JSON must contain an object at the top level")
    if _contains_key_field(data):
        raise ValueError("profile data contains forbidden 'key' field")
    return TransformProfile.from_dict(data)
