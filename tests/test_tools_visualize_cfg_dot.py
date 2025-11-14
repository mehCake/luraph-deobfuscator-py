import json
from dataclasses import asdict
from pathlib import Path

import pytest

from src.tools.visualize_cfg_dot import CFG, CFGBlock, load_cfg, main, render_cfg_dot


def _sample_cfg() -> CFG:
    return CFG(
        entry="entry",
        blocks=(
            CFGBlock(
                block_id="entry",
                kind="entry",
                start=0,
                end=4,
                successors=("branch",),
                hints=("entry", "contains_key"),
                metadata={
                    "ir_summary": ["LOADK R0 K0", "CALL R0 1"],
                    "description": "dispatcher entry",
                    "secret": "should not appear",
                },
            ),
            CFGBlock(
                block_id="branch",
                kind="branch",
                start=4,
                end=8,
                successors=(),
                metadata={"trap_reason": "none"},
            ),
        ),
    )


def test_render_cfg_dot_filters_sensitive_metadata() -> None:
    dot = render_cfg_dot(_sample_cfg(), title="candidate")
    assert "contains_key" not in dot  # hints mentioning keys are stripped
    assert "secret" not in dot  # metadata with key-like content is skipped
    assert "LOADK" in dot
    assert "candidate" in dot
    assert "branch" in dot


def test_cli_writes_dot_and_svg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_path = tmp_path / "dispatcher.json"
    cfg_path.write_text(json.dumps(asdict(_sample_cfg())), encoding="utf-8")

    # Force the fallback SVG renderer to exercise deterministic output.
    monkeypatch.setattr("src.tools.visualize_cfg_dot._try_render_with_graphviz", lambda dot, destination: False)

    exit_code = main([str(cfg_path), "--output-dir", str(tmp_path / "cfg_out"), "--candidate", "sample"])
    assert exit_code == 0

    dot_path = tmp_path / "cfg_out" / "sample.dot"
    svg_path = tmp_path / "cfg_out" / "sample.svg"
    assert dot_path.exists()
    assert svg_path.exists()

    dot_content = dot_path.read_text(encoding="utf-8")
    svg_content = svg_path.read_text(encoding="utf-8")
    assert "LOADK" in dot_content
    assert "entry" in svg_content
    assert "CALL" in svg_content

    # Load via helper to ensure JSON structure is retained.
    cfg_loaded = load_cfg(cfg_path)
    assert cfg_loaded.entry == "entry"
    assert len(cfg_loaded.blocks) == 2
