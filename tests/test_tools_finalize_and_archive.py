from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = Path("tools/finalize_and_archive.py")


@pytest.mark.skipif(not SCRIPT.exists(), reason="finalize_and_archive script missing")
def test_finalize_and_archive_happy_path(tmp_path):
    out_dir = tmp_path / "analysis_out"
    runs_dir = tmp_path / "runs"
    constants_dir = out_dir / "constants"
    bytes_dir = out_dir / "bytes"
    opcode_maps_dir = out_dir / "opcode_maps"

    for directory in (out_dir, constants_dir, bytes_dir, opcode_maps_dir):
        directory.mkdir(parents=True, exist_ok=True)

    # Minimal payload for emit_pretty.sh pipeline
    unpacked = {
        "array": [
            None,
            None,
            None,
            [
                {"opcode": 1, "A": 0, "B": 0, "C": 0},
                {"opcode": 3, "A": 0, "B": 0, "C": 0},
            ],
            ["hello", "world"],
        ]
    }
    (out_dir / "unpacked_dump.json").write_text(json.dumps(unpacked), encoding="utf-8")

    constants_payload = {
        "candidate": "sample",
        "constants": ["hello", "world"],
        "stats": {"constant_count": 2},
    }
    (constants_dir / "sample.json").write_text(json.dumps(constants_payload), encoding="utf-8")

    profile_payload = {"version": "1.0", "metadata": {"version_hint": "v14.4.2"}}
    (out_dir / "transform_profile.json").write_text(json.dumps(profile_payload), encoding="utf-8")

    bytes_meta = [
        {
            "name": "constants",
            "path": str(constants_dir / "sample.json"),
            "size": 2,
            "confidence": 1.0,
        }
    ]
    (bytes_dir / "meta.json").write_text(json.dumps(bytes_meta), encoding="utf-8")

    pipeline_report = {
        "target": "Obfuscated3.lua",
        "pipeline": ["string-escape", "prga"],
        "pipeline_confidence": 0.75,
        "pipeline_hints": ["v14.4.2"],
        "pipelines": [
            {
                "pipeline": ["string-escape", "prga"],
                "hypothesis_score": {"overall": 0.8},
                "scoring_context": {"pipeline_confidence": 0.75},
            }
        ],
        "opcode_map_candidates": [
            {"mapping": {"1": "LOADK", "2": "RETURN"}, "confidence": 0.7}
        ],
        "opcode_map_files": ["opcode_maps/candidate0.json"],
        "parity_summary": {"success": True, "matching_prefix": 32},
        "version_hint": "v14.4.2",
    }
    (out_dir / "pipeline_candidates.json").write_text(
        json.dumps(pipeline_report, indent=2), encoding="utf-8"
    )

    mapping_report = {
        "tables": [
            {"name": "perm", "confidence": 0.6, "samples": 2, "permutation_score": 0.8}
        ]
    }
    (out_dir / "mapping_candidates.json").write_text(
        json.dumps(mapping_report, indent=2), encoding="utf-8"
    )

    (out_dir / "raw_manifest.json").write_text(
        json.dumps([{"type": "string", "offset": 0, "length": 10}]), encoding="utf-8"
    )
    (out_dir / "bootstrap_chunks.json").write_text(json.dumps([{"id": 1}]), encoding="utf-8")
    (out_dir / "bootstrap_candidates.json").write_text(json.dumps([{"name": "chunk"}]), encoding="utf-8")
    (out_dir / "raw_payload.txt").write_text("payload", encoding="utf-8")
    (out_dir / "user_report.md").write_text("User report", encoding="utf-8")
    (out_dir / "recommendations.md").write_text("Recommendations", encoding="utf-8")
    (out_dir / "detection_report.md").write_text("Detection", encoding="utf-8")

    opcode_map_payload = {"mapping": {"1": "LOADK", "2": "RETURN"}}
    (opcode_maps_dir / "candidate0.json").write_text(json.dumps(opcode_map_payload), encoding="utf-8")

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(Path.cwd()))

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--out-dir",
            str(out_dir),
            "--runs-dir",
            str(runs_dir),
            "--target",
            "Obfuscated3.lua",
            "--tag",
            "14.4.2",
            "--force",
        ],
        cwd=Path.cwd(),
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )

    assert "Finalisation complete" in result.stdout
    assert "14.4.2" in result.stdout

    manifest_files = sorted(runs_dir.glob("run-*.manifest.json"))
    assert manifest_files, "manifest not generated"
    manifest_data = json.loads(manifest_files[0].read_text(encoding="utf-8"))
    assert manifest_data["version_hint"] == "14.4.2"

    archive_files = sorted(runs_dir.glob("run-*.zip"))
    assert archive_files, "archive not generated"

    summary_match = re.search(r"Files archived: (\d+)", result.stdout)
    assert summary_match is not None
    assert int(summary_match.group(1)) > 0
