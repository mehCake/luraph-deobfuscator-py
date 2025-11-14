"""Automatic transform profile builder for high-confidence pipelines.

This module inspects the pipeline analysis report produced by
:mod:`src.tools.collector`, picks the most confident pipeline candidate, and
persists a transform profile JSON alongside auxiliary metadata.  The resulting
profile intentionally refuses to persist any information that resembles a
session key.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Optional, Sequence

from .compatibility_adapter import apply_version_adaptations
from .transform_profile import TransformProfile, load_profile, save_profile

LOGGER = logging.getLogger(__name__)

__all__ = [
    "AutoProfile",  # re-exported for typing convenience
    "AutoProfileBuilderError",
    "build_auto_profile",
    "write_auto_profile",
]

DEFAULT_CONFIDENCE_THRESHOLD = 0.7
_MAX_MAPPING_PREVIEW = 12


class AutoProfileBuilderError(RuntimeError):
    """Raised when the auto profile builder cannot proceed safely."""


@dataclass(frozen=True)
class AutoProfile:
    """Summary of the automatically generated transform profile."""

    profile: TransformProfile
    confidence: float
    pipeline_sequence: Sequence[str]
    opcode_map_id: Optional[str]


def _contains_key_field(payload: Any) -> bool:
    """Return ``True`` when the payload contains a mapping entry named ``key``."""

    if isinstance(payload, MutableMapping):
        for key, value in payload.items():
            if str(key).lower() == "key" or _contains_key_field(value):
                return True
        return False
    if isinstance(payload, Mapping):  # pragma: no cover - defensive
        return any(str(key).lower() == "key" for key in payload.keys()) or any(
            _contains_key_field(value) for value in payload.values()
        )
    if isinstance(payload, (list, tuple)):
        return any(_contains_key_field(item) for item in payload)
    return False


def _select_pipeline_candidate(
    pipeline_report: Mapping[str, Any],
    *,
    threshold: float,
) -> tuple[Mapping[str, Any], float] | None:
    pipelines = pipeline_report.get("pipelines") or []
    best_candidate: Optional[Mapping[str, Any]] = None
    best_confidence = float("-inf")
    for entry in pipelines:
        if not isinstance(entry, Mapping):
            continue
        confidence = entry.get("confidence")
        if confidence is None:
            hypothesis = entry.get("hypothesis_score")
            if isinstance(hypothesis, Mapping):
                confidence = hypothesis.get("overall")
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError):
            continue
        if confidence_value > best_confidence:
            best_candidate = entry
            best_confidence = confidence_value
    if best_candidate is None or best_confidence < threshold:
        return None
    return best_candidate, best_confidence


def _select_opcode_map(
    opcode_candidates: Sequence[Mapping[str, Any]] | None,
) -> tuple[str, Mapping[str, str], float] | None:
    if not opcode_candidates:
        return None
    best: Optional[tuple[str, Mapping[str, str], float]] = None
    for index, candidate in enumerate(opcode_candidates):
        if not isinstance(candidate, Mapping):
            continue
        mapping_raw = candidate.get("mapping")
        if not isinstance(mapping_raw, Mapping):
            continue
        try:
            confidence = float(candidate.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        identifier = candidate.get("id") or candidate.get("name")
        if not identifier:
            identifier = f"candidate-{index:02d}"
        normalised_mapping = {str(opcode): str(mnemonic) for opcode, mnemonic in mapping_raw.items()}
        if best is None or confidence > best[2]:
            best = (str(identifier), normalised_mapping, confidence)
    return best


def _build_metadata(
    pipeline_report: Mapping[str, Any],
    pipeline_candidate: Mapping[str, Any],
    *,
    confidence: float,
    opcode_map_preview: tuple[str, Mapping[str, str], float] | None,
) -> dict[str, Any]:
    sequence = pipeline_candidate.get("sequence") or pipeline_report.get("pipeline") or []
    sequence_list = [str(step) for step in sequence if step]

    metadata: dict[str, Any] = {
        "pipeline_sequence": sequence_list,
        "pipeline_confidence": confidence,
    }

    version_hint = pipeline_candidate.get("version_hint") or pipeline_report.get("version_hint")
    if version_hint:
        metadata["version_hint"] = str(version_hint)

    preferred_presets = pipeline_candidate.get("preferred_presets")
    if isinstance(preferred_presets, Sequence):
        metadata["preferred_presets"] = [str(item) for item in preferred_presets if item]

    hypothesis = pipeline_candidate.get("hypothesis_score")
    if isinstance(hypothesis, Mapping):
        metadata["hypothesis_score"] = json.loads(json.dumps(hypothesis))

    scoring_context = pipeline_candidate.get("scoring_context")
    if isinstance(scoring_context, Mapping):
        metadata["candidate_parameters"] = json.loads(json.dumps(scoring_context))

    pipeline_hints = pipeline_report.get("pipeline_hints")
    if isinstance(pipeline_hints, Sequence):
        metadata["pipeline_hints"] = [str(hint) for hint in pipeline_hints]

    if opcode_map_preview:
        map_id, mapping, map_confidence = opcode_map_preview
        preview_items = sorted(mapping.items())[:_MAX_MAPPING_PREVIEW]
        metadata["opcode_map_preview"] = {
            "id": map_id,
            "confidence": map_confidence,
            "entries": preview_items,
        }

    return metadata


def build_auto_profile(
    pipeline_report: Mapping[str, Any],
    opcode_candidates: Sequence[Mapping[str, Any]] | None = None,
    *,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    existing: TransformProfile | None = None,
    extra_metadata: Mapping[str, Any] | None = None,
) -> AutoProfile | None:
    """Build a :class:`TransformProfile` from analysis artefacts."""

    selection = _select_pipeline_candidate(pipeline_report, threshold=threshold)
    if selection is None:
        LOGGER.debug(
            "No pipeline candidate exceeded confidence threshold %.2f; skipping profile", threshold
        )
        return None

    pipeline_candidate, confidence = selection
    opcode_preview = _select_opcode_map(opcode_candidates)

    base_prga = dict(existing.prga_params) if existing and existing.prga_params else None
    base_permute = list(existing.permute_table) if existing and existing.permute_table else None
    opcode_ids = list(existing.opcode_map_ids) if existing else []

    metadata = dict(existing.metadata) if existing else {}
    metadata.update(
        _build_metadata(
            pipeline_report,
            pipeline_candidate,
            confidence=confidence,
            opcode_map_preview=opcode_preview,
        )
    )
    if extra_metadata:
        for key, value in extra_metadata.items():
            metadata.setdefault(str(key), value)

    if _contains_key_field(metadata):
        raise AutoProfileBuilderError("metadata contains a field named 'key'; refusing to save profile")

    candidate_scores: dict[str, float] = dict(existing.candidate_scores) if existing else {}
    candidate_scores["pipeline"] = round(confidence, 4)

    opcode_map_id: Optional[str] = None
    if opcode_preview:
        opcode_map_id, mapping, map_confidence = opcode_preview
        candidate_scores["opcode_map"] = round(map_confidence, 4)
        if opcode_map_id not in opcode_ids:
            opcode_ids.insert(0, opcode_map_id)
        metadata.setdefault("opcode_map_preview", {}).setdefault("entries", list(mapping.items()))

    profile = TransformProfile(
        version=existing.version if existing else TransformProfile().version,
        prga_params=base_prga,
        permute_table=base_permute,
        opcode_map_ids=opcode_ids,
        candidate_scores=candidate_scores,
        metadata=metadata,
    )

    version_hint = metadata.get("version_hint")
    if version_hint:
        profile = apply_version_adaptations(profile, str(version_hint))
        metadata = profile.metadata

    payload = profile.to_dict()
    if _contains_key_field(payload):
        raise AutoProfileBuilderError("generated profile payload contains forbidden 'key' field")

    return AutoProfile(profile=profile, confidence=confidence, pipeline_sequence=tuple(metadata.get("pipeline_sequence", [])), opcode_map_id=opcode_map_id)


def write_auto_profile(
    pipeline_report: Mapping[str, Any],
    opcode_candidates: Sequence[Mapping[str, Any]] | None,
    destination: Path,
    *,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    extra_metadata: Mapping[str, Any] | None = None,
) -> Path | None:
    """Persist an auto-generated transform profile to ``destination``."""

    existing: TransformProfile | None = None
    if destination.exists():
        try:
            existing = load_profile(destination)
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.warning("Failed to load existing transform profile %s: %s", destination, exc)

    result = build_auto_profile(
        pipeline_report,
        opcode_candidates,
        threshold=threshold,
        existing=existing,
        extra_metadata=extra_metadata,
    )
    if result is None:
        return None

    payload = result.profile.to_dict()
    if _contains_key_field(payload):
        raise AutoProfileBuilderError("refusing to write profile containing 'key' field")

    save_profile(result.profile, destination)
    LOGGER.info("Auto transform profile saved to %s", destination)
    return destination
