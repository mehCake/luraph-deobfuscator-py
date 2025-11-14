import json
from pathlib import Path

import pytest

from src.tools.visualize_pipeline import (
    classify_operation,
    generate_pipeline_graphs,
    load_pipeline_report,
    main,
    render_pipeline_graph,
)


def test_classify_operation_extended_categories() -> None:
    assert classify_operation("loadstring") == "bootstrap"
    assert classify_operation("vm_dispatch") == "dispatcher"
    assert classify_operation("handler_call") == "handlers"
    assert classify_operation("endianness:little") == "endianness"


def test_render_pipeline_graph_adds_metadata() -> None:
    dot = render_pipeline_graph(
        ["loadstring", "xor", "vm_unpack"],
        title="Candidate",
        version_hint="v14.4.2",
        confidence=0.82,
        preferred_presets=["v14.4.2-default"],
        annotations=["operation_score: 0.7000"],
    )
    assert "label=\"Candidate\\nVersion: v14.4.2" in dot
    assert "Confidence: 0.82" in dot
    assert "Presets: v14.4.2-default" in dot
    assert "operation_score: 0.7000" in dot


def test_generate_pipeline_graphs_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "pipeline": ["loadstring", "xor", "permute", "vm_dispatch"],
        "pipeline_confidence": 0.75,
        "pipeline_hints": ["xor-score=high"],
        "version_hint": "v14.4.2",
        "pipelines": [
            {
                "sequence": ["loadstring", "xor", "permute", "vm_dispatch"],
                "confidence": 0.75,
                "confidence_breakdown": {"operation_score": 0.65},
                "version_hint": "v14.4.2",
                "preferred_presets": ["v14.4.2-default"],
                "parameters": {"rotate": 3},
            }
        ],
    }
    source = tmp_path / "pipeline_candidates.json"
    source.write_text(json.dumps(payload), encoding="utf-8")

    # Force the SVG fallback to exercise deterministic rendering.
    monkeypatch.setattr("src.tools.visualize_pipeline._try_render_with_graphviz", lambda dot, destination: False)

    exit_code = main(["--source", str(source), "--output-dir", str(tmp_path / "graphs"), "--open"])
    assert exit_code == 0

    svg_files = sorted((tmp_path / "graphs").glob("*.svg"))
    dot_files = sorted((tmp_path / "graphs").glob("*.dot"))
    assert svg_files, "Expected at least one SVG output"
    assert dot_files, "Expected DOT artefacts alongside SVG output"

    svg_content = svg_files[0].read_text(encoding="utf-8")
    assert "PRGA" not in svg_content  # pipeline does not include PRGA
    assert "xor" in svg_content.lower()
    assert "v14.4.2" in svg_content

    report = load_pipeline_report(source)
    outputs = generate_pipeline_graphs(report, tmp_path / "graphs_alt")
    assert outputs and outputs[0].suffix == ".svg"
