from __future__ import annotations

import json
from pathlib import Path

from src.tools.export_for_machine_learning import export_training_data, main as run_export_ml


_SPEC_PATH = Path("tests/samples/pipelines/v14_4_2_sample.yaml")


def _read_records(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def test_export_training_data(tmp_path: Path) -> None:
    output = tmp_path / "dataset.jsonl"
    examples = export_training_data([_SPEC_PATH], output)
    records = _read_records(output)
    assert len(examples) == len(records) >= 2
    labels = {record["label"] for record in records}
    assert {"prga", "permute"}.issubset(labels)
    for record in records:
        assert record["sample"] == "synthetic_v14_4_2"
        key_meta = record["operation_metadata"].get("key")
        if key_meta is not None:
            assert key_meta == {"redacted": True}
        assert record["input_len"] == len(bytes.fromhex(record["input_hex"]))
        assert record["output_len"] == len(bytes.fromhex(record["output_hex"]))


def test_export_training_data_limit(tmp_path: Path) -> None:
    output = tmp_path / "limited.jsonl"
    examples = export_training_data([_SPEC_PATH], output, limit=1)
    records = _read_records(output)
    assert len(examples) == len(records) == 1


def test_export_cli(tmp_path: Path) -> None:
    output = tmp_path / "cli.jsonl"
    exit_code = run_export_ml([
        "--spec",
        str(_SPEC_PATH),
        "--output",
        str(output),
        "--limit",
        "1",
    ])
    assert exit_code == 0
    assert len(_read_records(output)) == 1
