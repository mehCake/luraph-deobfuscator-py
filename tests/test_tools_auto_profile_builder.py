from pathlib import Path

import pytest

from src.tools.auto_profile_builder import (
    AutoProfileBuilderError,
    build_auto_profile,
    write_auto_profile,
)
from src.tools.transform_profile import TransformProfile, load_profile, save_profile


def test_build_auto_profile_requires_confidence() -> None:
    pipeline_report = {
        "pipelines": [
            {
                "sequence": ["string-escape"],
                "confidence": 0.42,
            }
        ]
    }

    result = build_auto_profile(pipeline_report, [])
    assert result is None


def test_build_auto_profile_selects_best_map() -> None:
    pipeline_report = {
        "pipeline": ["string-escape", "prga"],
        "pipelines": [
            {
                "sequence": ["string-escape", "prga", "permute"],
                "confidence": 0.82,
                "version_hint": "v14.4.2",
                "preferred_presets": ["v14.4.2-default"],
                "hypothesis_score": {"overall": 0.82, "components": {"pipeline": 0.8}},
                "scoring_context": {"pipeline_confidence": 0.8, "english_scores": [0.2]},
            }
        ],
    }
    opcode_candidates = [
        {"confidence": 0.4, "mapping": {"0": "MOVE"}},
        {"confidence": 0.9, "mapping": {"0": "LOADK", "1": "CALL"}},
    ]

    auto = build_auto_profile(pipeline_report, opcode_candidates)
    assert auto is not None
    payload = auto.profile.to_dict()
    assert payload["candidate_scores"]["pipeline"] == pytest.approx(0.82, rel=1e-3)
    metadata = payload["metadata"]
    assert metadata["pipeline_sequence"] == ["string-escape", "prga", "permute"]
    assert metadata["version_hint"] == "v14.4.2"
    assert metadata["preferred_presets"][0] == "v14.4.2-default"
    assert "v14.4.2-default" in metadata["preferred_presets"]
    preview = metadata["opcode_map_preview"]
    assert preview["confidence"] == pytest.approx(0.9, rel=1e-3)
    assert preview["entries"]
    assert auto.opcode_map_id is not None


def test_write_auto_profile_merges_existing(tmp_path: Path) -> None:
    existing = TransformProfile(
        prga_params={"rotate": 3},
        permute_table=[0, 1, 2],
        opcode_map_ids=["manual"],
        candidate_scores={"manual": 0.25},
        metadata={"previous": True},
    )
    path = tmp_path / "profile.json"
    save_profile(existing, path)

    pipeline_report = {
        "pipelines": [
            {
                "sequence": ["string-escape", "prga"],
                "confidence": 0.91,
                "hypothesis_score": {"overall": 0.91},
            }
        ]
    }
    opcode_candidates = [
        {"confidence": 0.88, "mapping": {"0": "LOADK"}},
    ]

    result_path = write_auto_profile(pipeline_report, opcode_candidates, path)
    assert result_path == path

    loaded = load_profile(path)
    assert loaded.prga_params == {"rotate": 3}
    assert loaded.permute_table == [0, 1, 2]
    assert loaded.metadata["previous"] is True
    assert "manual" in loaded.opcode_map_ids
    assert any(candidate.startswith("candidate-") for candidate in loaded.opcode_map_ids)
    assert loaded.candidate_scores["opcode_map"] == pytest.approx(0.88, rel=1e-3)


def test_write_auto_profile_rejects_key_field(tmp_path: Path) -> None:
    pipeline_report = {
        "pipelines": [
            {
                "sequence": ["prga"],
                "confidence": 0.95,
                "scoring_context": {"key": "secret"},
            }
        ]
    }

    with pytest.raises(AutoProfileBuilderError):
        write_auto_profile(pipeline_report, [], tmp_path / "profile.json")
