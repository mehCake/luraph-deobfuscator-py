import json

from src.tools.metrics_collector import MetricsCollector, collect_metrics


def test_metrics_collector_writes_report(tmp_path) -> None:
    collector = MetricsCollector()
    collector.record_count("bootstrap_candidates", 3)
    collector.increment("bootstrap_candidates", 2)
    collector.observe("pipeline_confidence", 0.5)
    collector.note("profile_generated", True)

    path = collector.write_report(
        output_dir=tmp_path,
        run_id="run-sample",
        extra={"parity_success": True, "api_key": "drop-me"},
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["run_id"] == "run-sample"
    assert data["step_counts"]["bootstrap_candidates"] == 5
    assert data["metrics"]["pipeline_confidence"] == 0.5
    assert data["extra"]["parity_success"] is True
    assert "api_key" not in data["extra"]
    assert path.parent == tmp_path
    assert path.name == "run-sample.json"


def test_collect_metrics_wrapper(tmp_path) -> None:
    path = collect_metrics(
        output_dir=tmp_path,
        run_id="run-wrapper",
        step_counts={"chunks": 2},
        metrics={"confidence": 0.9},
        extra={"token": "discard", "notes": "ok"},
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["step_counts"] == {"chunks": 2}
    assert payload["metrics"]["confidence"] == 0.9
    assert "token" not in payload["extra"]
