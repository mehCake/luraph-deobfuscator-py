import json
from datetime import datetime
from pathlib import Path

from src.tools.backup_manager import BackupPlan, snapshot_analysis_inputs


def test_snapshot_creates_timestamped_directory(tmp_path: Path) -> None:
    original = tmp_path / "sample.lua"
    original.write_text("return 1", encoding="utf-8")

    manifest = tmp_path / "raw_manifest.json"
    manifest.write_text(json.dumps({"type": "escaped", "key": "secret"}), encoding="utf-8")

    bootstrap = tmp_path / "bootstrap_chunks.json"
    bootstrap.write_text(
        json.dumps({"chunks": [{"kind": "load", "key": "hidden"}]}),
        encoding="utf-8",
    )

    plan = BackupPlan(
        original_file=original,
        manifest_path=manifest,
        bootstrap_chunks=bootstrap,
        transform_profile=None,
        extra_files={"pipeline": manifest},
    )

    timestamp = datetime(2023, 7, 5, 12, 30, 15)
    run_dir = snapshot_analysis_inputs(output_dir=tmp_path / "out", plan=plan, timestamp=timestamp)

    assert run_dir.name == "run-20230705-123015"
    backup_manifest = json.loads((run_dir / "backup_manifest.json").read_text(encoding="utf-8"))
    assert "files" in backup_manifest
    assert "original" in backup_manifest["files"]

    manifest_copy = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "key" not in manifest_copy

    bootstrap_copy = json.loads((run_dir / "bootstrap_chunks.json").read_text(encoding="utf-8"))
    if isinstance(bootstrap_copy, dict):
        assert "key" not in bootstrap_copy


def test_snapshot_with_existing_directory_adds_suffix(tmp_path: Path) -> None:
    original = tmp_path / "payload.lua"
    original.write_text("return 0", encoding="utf-8")
    plan = BackupPlan(original_file=original)

    timestamp = datetime(2023, 1, 1, 0, 0, 0)
    first = snapshot_analysis_inputs(output_dir=tmp_path / "out", plan=plan, timestamp=timestamp)
    second = snapshot_analysis_inputs(output_dir=tmp_path / "out", plan=plan, timestamp=timestamp)

    assert first.name == "run-20230101-000000"
    assert second.name == "run-20230101-000000-2"
