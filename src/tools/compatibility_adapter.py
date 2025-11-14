"""Compatibility helpers for adapting transform profiles across Luraph releases."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence

from ..decoders.lph_reverse import COMMON_PARAMETER_PRESETS
from .transform_profile import TransformProfile

__all__ = ["apply_version_adaptations"]

LOGGER = logging.getLogger(__name__)

_FORBIDDEN_FIELDS = {"key", "secret", "token"}
_AVAILABLE_PRESETS = {name for name, _params in COMMON_PARAMETER_PRESETS}
_PRESET_PRIORITY = {
    "v14.4.1": ("v14.4.1-default",),
    "v14.4.2": ("v14.4.2-default", "v14.4.1-default"),
    "v14.4.3": ("v14.4.2-default", "v14.4.1-default"),
}


def _normalise_version(version: str | None) -> str | None:
    if not version:
        return None
    cleaned = str(version).strip().lower()
    if not cleaned:
        return None
    cleaned = cleaned.replace("_", ".")
    if cleaned.startswith("v"):
        cleaned = cleaned[1:]
    cleaned = cleaned.lstrip(".")
    parts = cleaned.split(".")
    if len(parts) < 2:
        return None
    if parts[0] != "14":
        prefix = parts[0]
    else:
        prefix = "14"
    suffix = ".".join(parts[1:])
    normalised = f"v{prefix}.{suffix}"
    return normalised


def _dedupe(sequence: Iterable[Any]) -> List[Any]:
    seen: set[Any] = set()
    result: List[Any] = []
    for item in sequence:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _normalise_int_list(payload: Any) -> List[int]:
    if payload is None:
        return []
    if isinstance(payload, (list, tuple, set)):
        items: Iterable[Any] = payload
    else:
        items = [payload]
    result: List[int] = []
    for item in items:
        try:
            result.append(int(item))
        except (TypeError, ValueError):
            continue
    return _dedupe(result)


def _normalise_list(payload: Any) -> List[str]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [str(item) for item in payload if item is not None]
    if isinstance(payload, tuple):
        return [str(item) for item in payload if item is not None]
    return [str(payload)]


def _strip_forbidden_fields(mapping: MutableMapping[str, Any], *, path: str = "") -> List[str]:
    removed: List[str] = []
    for key in list(mapping.keys()):
        value = mapping[key]
        current_path = f"{path}.{key}" if path else str(key)
        lower_key = str(key).lower()
        if lower_key in _FORBIDDEN_FIELDS and value not in (None, "", [], {}, ()):  # type: ignore[comparison-overlap]
            mapping.pop(key, None)
            removed.append(current_path)
            continue
        if isinstance(value, MutableMapping):
            removed.extend(_strip_forbidden_fields(value, path=current_path))
        elif isinstance(value, Mapping):  # pragma: no cover - defensive
            removed.extend(_strip_forbidden_fields(dict(value), path=current_path))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, MutableMapping):
                    removed.extend(
                        _strip_forbidden_fields(item, path=f"{current_path}[{index}]")
                    )
    return removed


def _prioritise_presets(metadata: Dict[str, Any], version: str) -> bool:
    preferences = _PRESET_PRIORITY.get(version, ())
    if not preferences:
        return False
    current = _normalise_list(metadata.get("preferred_presets"))
    changed = False
    for preset in reversed(preferences):
        if preset not in _AVAILABLE_PRESETS:
            continue
        if preset in current:
            idx = current.index(preset)
            if idx != 0:
                current.insert(0, current.pop(idx))
                changed = True
        else:
            current.insert(0, preset)
            changed = True
    if changed:
        metadata["preferred_presets"] = current
    elif current:
        metadata["preferred_presets"] = current
    return changed


def _merge_int_metadata(metadata: Dict[str, Any], key: str, additions: Sequence[int]) -> bool:
    additions_list = _normalise_int_list(additions)
    if not additions_list:
        return False
    existing = _normalise_int_list(metadata.get(key))
    changed = False
    for value in additions_list:
        if value not in existing:
            existing.append(value)
            changed = True
    if existing:
        metadata[key] = existing
    return changed


def _apply_v14_4_1(profile: TransformProfile) -> List[str]:
    notes: List[str] = []
    params = dict(profile.prga_params) if profile.prga_params else {}
    changed_params = False
    if not params.get("variant"):
        params["variant"] = "default"
        changed_params = True
    rotates = _normalise_int_list(params.get("rotate_amounts"))
    if not rotates:
        rotates = [11]
        params["rotate_amounts"] = rotates
        changed_params = True
    if changed_params:
        profile.prga_params = params
        notes.append("Applied v14.4.1 PRGA defaults (default variant, rotate 11).")
    metadata = dict(profile.metadata)
    metadata["version_hint"] = "v14.4.1"
    meta_changed = _prioritise_presets(metadata, "v14.4.1")
    meta_changed |= _merge_int_metadata(metadata, "expected_rotate_amounts", rotates)
    meta_changed |= _merge_int_metadata(metadata, "expected_permutation_lengths", [256])
    if meta_changed:
        notes.append("Updated metadata hints for v14.4.1 pipeline.")
    profile.metadata = metadata
    return notes


def _apply_v14_4_2(profile: TransformProfile) -> List[str]:
    notes: List[str] = []
    params = dict(profile.prga_params) if profile.prga_params else {}
    changed_params = False
    variant = params.get("variant")
    if not variant:
        params["variant"] = "alt"
        changed_params = True
    rotates = _normalise_int_list(params.get("rotate_amounts"))
    missing = [value for value in (11, 13) if value not in rotates]
    if missing:
        rotates.extend(missing)
        params["rotate_amounts"] = rotates
        changed_params = True
    if "xor_seed" not in params:
        params["xor_seed"] = 0x5C
        changed_params = True
    if changed_params:
        profile.prga_params = params
        notes.append("Applied v14.4.2 PRGA defaults (alt variant, rotate 11/13, XOR seed 0x5C).")
    metadata = dict(profile.metadata)
    metadata["version_hint"] = "v14.4.2"
    meta_changed = _prioritise_presets(metadata, "v14.4.2")
    meta_changed |= _merge_int_metadata(metadata, "expected_rotate_amounts", rotates or [11, 13])
    meta_changed |= _merge_int_metadata(metadata, "expected_permutation_lengths", [64, 128])
    if metadata.get("prga_variant_hint") != "alt":
        metadata["prga_variant_hint"] = "alt"
        meta_changed = True
    if meta_changed:
        notes.append("Updated metadata hints for v14.4.2 pipeline (alt variant, 64/128 permutations).")
    profile.metadata = metadata
    return notes


def _apply_v14_4_3(profile: TransformProfile) -> List[str]:
    notes: List[str] = []
    params = dict(profile.prga_params) if profile.prga_params else {}
    changed_params = False
    if not params.get("variant"):
        params["variant"] = "default"
        changed_params = True
    rotates = _normalise_int_list(params.get("rotate_amounts"))
    additions = [1, 5, 7]
    missing = [value for value in additions if value not in rotates]
    if missing:
        rotates.extend(missing)
        params["rotate_amounts"] = rotates
        changed_params = True
    if "mix_rounds" not in params:
        params["mix_rounds"] = 2
        changed_params = True
    if changed_params:
        profile.prga_params = params
        notes.append("Applied v14.4.3 PRGA hints (default variant, rotate 1/5/7, mix rounds 2).")
    metadata = dict(profile.metadata)
    metadata["version_hint"] = "v14.4.3"
    meta_changed = _prioritise_presets(metadata, "v14.4.3")
    meta_changed |= _merge_int_metadata(metadata, "expected_rotate_amounts", rotates or additions)
    meta_changed |= _merge_int_metadata(metadata, "expected_permutation_lengths", [128, 256])
    if metadata.get("prga_variant_hint") != "default":
        metadata["prga_variant_hint"] = "default"
        meta_changed = True
    if meta_changed:
        notes.append("Updated metadata hints for v14.4.3 pipeline (multi-rotate, large permutations).")
    profile.metadata = metadata
    return notes


_VERSION_ADAPTERS = {
    "v14.4.1": _apply_v14_4_1,
    "v14.4.2": _apply_v14_4_2,
    "v14.4.3": _apply_v14_4_3,
}


def apply_version_adaptations(
    profile: TransformProfile | Mapping[str, Any],
    version: str | None,
) -> TransformProfile:
    """Return a profile adjusted for compatibility with the given Luraph version."""

    if isinstance(profile, TransformProfile):
        working = TransformProfile.from_dict(profile.to_dict())
    else:
        working = TransformProfile.from_dict(profile)

    metadata = dict(working.metadata)
    removed = _strip_forbidden_fields(metadata)
    working.metadata = metadata

    params = dict(working.prga_params) if working.prga_params else {}
    removed += _strip_forbidden_fields(params)
    working.prga_params = params or None

    version_hint = _normalise_version(version)
    adapter_notes: List[str] = []
    if version_hint:
        adapter = _VERSION_ADAPTERS.get(version_hint)
        if adapter:
            adapter_notes = adapter(working)
        else:
            metadata = dict(working.metadata)
            metadata.setdefault("version_hint", version_hint)
            working.metadata = metadata
    metadata = dict(working.metadata)

    notes: List[str] = []
    if removed:
        notes.append("Removed forbidden fields: " + ", ".join(removed))
    notes.extend(adapter_notes)
    if notes:
        existing = metadata.get("compatibility_notes")
        if isinstance(existing, list):
            combined = [str(item) for item in existing]
        elif existing is None:
            combined = []
        else:
            combined = [str(existing)]
        for note in notes:
            if note not in combined:
                combined.append(note)
        metadata["compatibility_notes"] = combined
    working.metadata = metadata
    return working
