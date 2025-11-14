from pathlib import Path

import pytest

from src.tools.uid_generator import (
    generate_run_id,
    reserve_artifact_path,
    sanitise_token,
)


def test_generate_run_id_is_deterministic_and_sanitised() -> None:
    components = ["Obfuscated3.lua", "2024-01-01T12:00:00"]
    first = generate_run_id(components=components)
    second = generate_run_id(components=components)
    assert first == second
    assert first == sanitise_token(first)
    assert first.endswith(generate_run_id(components=components)[-8:])


def test_generate_run_id_truncates_long_components() -> None:
    components = ["A" * 120, "B" * 120]
    run_id = generate_run_id(components=components, max_length=32)
    assert len(run_id) <= 32
    assert run_id.endswith(generate_run_id(components=components, max_length=32)[-8:])


def test_reserve_artifact_path_reuses_existing(tmp_path: Path) -> None:
    run_id = generate_run_id(components=["example", "2024"])
    path, created = reserve_artifact_path(tmp_path, run_id=run_id, suffix=".json")
    assert created
    path.write_text("{}", encoding="utf-8")

    reused_path, created_again = reserve_artifact_path(
        tmp_path, run_id=run_id, suffix=".json"
    )
    assert reused_path == path
    assert not created_again


def test_reserve_artifact_path_rejects_unsafe_run_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        reserve_artifact_path(tmp_path, run_id="unsafe id")

