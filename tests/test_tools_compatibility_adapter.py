import pytest

from src.tools.compatibility_adapter import apply_version_adaptations
from src.tools.transform_profile import TransformProfile


def test_apply_version_adaptations_sets_defaults_for_v1442() -> None:
    profile = TransformProfile(metadata={"pipeline_sequence": ["string-escape", "prga"]})

    adapted = apply_version_adaptations(profile, "v14.4.2")

    assert adapted is not profile
    assert adapted.metadata["version_hint"] == "v14.4.2"
    assert adapted.prga_params is not None
    assert adapted.prga_params["variant"] == "alt"
    assert adapted.prga_params["xor_seed"] == 0x5C
    assert adapted.prga_params["rotate_amounts"] == [11, 13]
    assert set(adapted.metadata["expected_permutation_lengths"]) >= {64, 128}
    assert adapted.metadata["prga_variant_hint"] == "alt"
    notes = adapted.metadata.get("compatibility_notes", [])
    assert any("v14.4.2" in note for note in notes)


def test_apply_version_adaptations_preserves_existing_values_and_scrubs_secrets() -> None:
    profile = TransformProfile(
        prga_params={"variant": "custom", "rotate_amounts": [9]},
        metadata={"version_hint": "v14.4.2", "preferred_presets": ["manual"], "token": "abc123"},
    )

    adapted = apply_version_adaptations(profile, "v14.4.2")

    assert adapted.prga_params is not None
    assert adapted.prga_params["variant"] == "custom"
    assert all(value in adapted.prga_params["rotate_amounts"] for value in (9, 11, 13))
    assert "token" not in adapted.metadata
    assert adapted.metadata["preferred_presets"][0] == "v14.4.2-default"
    notes = adapted.metadata.get("compatibility_notes", [])
    assert any("Removed forbidden fields" in note for note in notes)


def test_apply_version_adaptations_accepts_mapping_input() -> None:
    raw = {
        "version": "1.0",
        "metadata": {"pipeline_sequence": ["string-escape"]},
        "candidate_scores": {},
    }

    adapted = apply_version_adaptations(raw, "14.4.3")

    assert isinstance(adapted, TransformProfile)
    assert adapted.metadata["version_hint"] == "v14.4.3"
    assert adapted.prga_params is not None
    assert all(value in adapted.prga_params["rotate_amounts"] for value in (1, 5, 7))
