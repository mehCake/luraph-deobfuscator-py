import json
import importlib
from pathlib import Path

plc = importlib.import_module("src.tools.prune_low_confidence")


def _sample_pipeline() -> dict:
    return {
        "pipelines": [
            {"sequence": ["string-escape"], "confidence": 0.9},
            {"sequence": ["xor"], "confidence": 0.2},
        ],
        "chunks": [
            {"kind": "loadstring", "confidence": 0.7},
            {"kind": "numeric_array", "confidence": 0.1},
        ],
        "byte_candidates": [
            {"name": "payload.bin", "confidence": 0.3},
        ],
        "metadata": {"note": "keep"},
    }


def test_prune_low_confidence_archives_candidates(monkeypatch, tmp_path: Path) -> None:
    pipeline_path = tmp_path / "pipeline_candidates.json"
    pipeline_path.write_text(json.dumps(_sample_pipeline()), encoding="utf-8")

    backups: list[Path] = []

    def fake_snapshot(*, output_dir: Path, plan, timestamp=None) -> Path:
        backups.append(output_dir)
        backup_dir = output_dir / "backups" / "run-test"
        backup_dir.parent.mkdir(parents=True, exist_ok=True)
        backup_dir.mkdir(exist_ok=True)
        return backup_dir

    monkeypatch.setattr(plc, "snapshot_analysis_inputs", fake_snapshot)

    result = plc.prune_low_confidence(
        pipeline_path,
        threshold=0.5,
        archive_dir=tmp_path / "archive",
    )
    assert isinstance(result, plc.PruneResult)
    assert result.total_pruned == 3
    assert result.archive_path is not None and result.archive_path.exists()
    assert backups, "expected a backup snapshot to be created"

    current = json.loads(pipeline_path.read_text(encoding="utf-8"))
    assert len(current["pipelines"]) == 1
    assert current["pipelines"][0]["confidence"] == 0.9
    assert len(current["chunks"]) == 1
    assert current["chunks"][0]["confidence"] == 0.7
    assert current["byte_candidates"] == []

    archived = json.loads(result.archive_path.read_text(encoding="utf-8"))
    assert archived["pruned"]["pipelines"][0]["sequence"] == ["xor"]
    assert archived["pruned"]["byte_candidates"][0]["name"] == "payload.bin"


def test_restore_from_archive_rehydrates_candidates(monkeypatch, tmp_path: Path) -> None:
    pipeline_path = tmp_path / "pipeline_candidates.json"
    pipeline_path.write_text(json.dumps(_sample_pipeline()), encoding="utf-8")
    archive_dir = tmp_path / "archive"

    monkeypatch.setattr(plc, "snapshot_analysis_inputs", lambda **kwargs: tmp_path / "backups" / "run-test")

    prune_result = plc.prune_low_confidence(
        pipeline_path,
        threshold=0.5,
        archive_dir=archive_dir,
    )
    assert prune_result.archive_path is not None

    restore_calls: list[Path] = []

    def fake_snapshot_restore(*, output_dir: Path, plan, timestamp=None) -> Path:
        restore_calls.append(output_dir)
        return output_dir / "backups" / "run-restore"

    monkeypatch.setattr(plc, "snapshot_analysis_inputs", fake_snapshot_restore)

    restore_result = plc.restore_from_archive(
        pipeline_path,
        prune_result.archive_path,
        archive_dir=archive_dir,
    )

    assert isinstance(restore_result, plc.RestoreResult)
    assert restore_result.total_restored == 3
    assert restore_calls, "expected snapshot before restoration"

    restored = json.loads(pipeline_path.read_text(encoding="utf-8"))
    assert len(restored["pipelines"]) == 2
    confidences = sorted(item["confidence"] for item in restored["pipelines"])
    assert confidences == [0.2, 0.9]
    assert any(chunk["confidence"] == 0.1 for chunk in restored["chunks"])
    assert restored["byte_candidates"][0]["confidence"] == 0.3
