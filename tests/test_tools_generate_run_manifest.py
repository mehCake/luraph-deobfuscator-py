import json
from datetime import datetime
from pathlib import Path

import pytest

from src.tools.generate_run_manifest import (
    RunManifestError,
    build_run_manifest,
    load_run_manifest,
    write_run_manifest,
)


def test_build_and_write_manifest(tmp_path: Path) -> None:
    pipeline_report = {
        "pipeline": ["string_escape", "prga"],
        "pipeline_confidence": 0.82,
        "pipeline_hints": ["v14.4.2"],
        "pipelines": [
            {
                "sequence": ["string_escape", "prga"],
                "confidence": 0.82,
                "hypothesis_score": {
                    "overall": 0.82,
                    "components": {"pipeline": 0.8, "english": 0.75},
                },
                "version_hint": "v14.4.2",
            }
        ],
    }
    mapping_report = {
        "tables": [
            {
                "name": "perm",
                "confidence": 0.7,
                "samples": 4,
                "permutation_score": 0.65,
            }
        ]
    }
    artefact_map = {
        "raw_payload": tmp_path / "raw.txt",
        "pipeline_report": tmp_path / "pipeline.json",
    }
    candidate_file = tmp_path / "map.json"
    candidate_file.write_text("{}", encoding="utf-8")
    candidate_maps = [
        {
            "confidence": 0.9,
            "mapping": {"0": "LOADK", "1": "MOVE"},
            "version_hint": "v14.4.2",
        }
    ]

    manifest = build_run_manifest(
        target="Obfuscated3.lua",
        pipeline_report=pipeline_report,
        mapping_report=mapping_report,
        artefact_paths=artefact_map,
        candidate_maps=candidate_maps,
        candidate_map_files=[candidate_file],
        parity_summary={"success": True, "matching_prefix": 32},
        version_hint="v14.4.2",
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )

    path = write_run_manifest(runs_dir=tmp_path / "runs", manifest=manifest)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "20240101-120000-obfuscated3-3a75a58a"
    assert payload["pipeline_steps"] == ["string_escape", "prga"]
    assert payload["candidate_maps"][0]["confidence"] == pytest.approx(0.9)
    assert payload["candidate_maps"][0]["path"].endswith("map.json")
    assert payload["mapping_summary"]["table_count"] == 1

    # Rewriting should reuse existing manifest without modifying contents
    manifest_again = build_run_manifest(
        target="Obfuscated3.lua",
        pipeline_report=pipeline_report,
        mapping_report=mapping_report,
        artefact_paths=artefact_map,
        candidate_maps=candidate_maps,
        candidate_map_files=[candidate_file],
        parity_summary={"success": True, "matching_prefix": 32},
        version_hint="v14.4.2",
        timestamp=datetime(2024, 1, 1, 12, 0, 0),
    )
    path_again = write_run_manifest(runs_dir=tmp_path / "runs", manifest=manifest_again)
    assert path_again == path
    assert json.loads(path_again.read_text(encoding="utf-8")) == payload


def test_manifest_rejects_key_fields(tmp_path: Path) -> None:
    pipeline_report = {"pipeline": [], "pipeline_confidence": 0.0}
    mapping_report: dict[str, object] = {}
    artefact_map = {"key": tmp_path / "leak.txt"}
    with pytest.raises(RunManifestError):
        build_run_manifest(
            target="test.lua",
            pipeline_report=pipeline_report,
            mapping_report=mapping_report,
            artefact_paths=artefact_map,
            candidate_maps=[],
            candidate_map_files=[],
        )


def test_load_manifest_migrates_legacy(tmp_path: Path) -> None:
    legacy = {
        "version": "0.9",
        "id": "legacy-run",
        "timestamp": "2023-12-31T23:59:59",
        "target": "stub.lua",
        "pipeline": {"steps": ["decode"], "confidence": 0.5, "hints": ["old"]},
        "artefacts": {"raw_manifest": "out/raw.json"},
        "candidate_maps": [],
    }
    manifest_path = tmp_path / "legacy.json"
    manifest_path.write_text(json.dumps(legacy), encoding="utf-8")

    manifest = load_run_manifest(manifest_path)
    assert manifest.run_id == "legacy-run"
    assert manifest.pipeline_steps == ["decode"]
    assert manifest.pipeline_confidence == pytest.approx(0.5)
