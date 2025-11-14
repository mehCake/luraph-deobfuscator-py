import json
from pathlib import Path

import pytest

from src.tools.transform_profile import TransformProfile, load_profile, save_profile


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    profile = TransformProfile(
        version="2.0",
        prga_params={"rotate": [3, 5], "xor_seed": 17},
        permute_table=[2, 0, 1],
        opcode_map_ids=["candidate-a", "candidate-b"],
        candidate_scores={"candidate-a": 0.85, "candidate-b": 0.67},
        metadata={"notes": "v14.4.2"},
    )

    destination = tmp_path / "profile.json"
    written = save_profile(profile, destination)

    assert written == destination
    parsed = json.loads(destination.read_text(encoding="utf-8"))
    assert parsed["version"] == "2.0"
    assert "key" not in parsed

    loaded = load_profile(destination)
    assert loaded.version == "2.0"
    assert loaded.permute_table == [2, 0, 1]
    assert loaded.opcode_map_ids == ["candidate-a", "candidate-b"]
    assert pytest.approx(loaded.candidate_scores["candidate-a"]) == 0.85
    assert loaded.metadata["notes"] == "v14.4.2"


def test_save_rejects_key_field(tmp_path: Path) -> None:
    destination = tmp_path / "profile.json"
    profile = {
        "version": "1.0",
        "prga_params": {"rotate": [1]},
        "key": "should-not-be-written",
    }

    with pytest.raises(ValueError):
        save_profile(profile, destination)


def test_load_migrates_legacy_format(tmp_path: Path) -> None:
    legacy = {
        "prga": {"rotate": [4, 1]},
        "permute": [0, 2, 1],
        "opcode_map_id": "legacy-map",
        "scores": {"legacy-map": 0.5},
        "extra": "kept",
    }
    target = tmp_path / "legacy.json"
    target.write_text(json.dumps(legacy), encoding="utf-8")

    loaded = load_profile(target)

    assert loaded.version == "1.0"
    assert loaded.prga_params == {"rotate": [4, 1]}
    assert loaded.permute_table == [0, 2, 1]
    assert loaded.opcode_map_ids == ["legacy-map"]
    assert loaded.candidate_scores["legacy-map"] == 0.5
    assert loaded.metadata["extra"] == "kept"


def test_load_rejects_files_with_key(tmp_path: Path) -> None:
    payload = {"version": "1.0", "key": "secret"}
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        load_profile(path)
