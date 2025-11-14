from pathlib import Path
from types import SimpleNamespace

import pytest

from src.tools.plugin_hooks import (
    PluginContext,
    PluginKeyRequestError,
    PluginValidationError,
    discover_plugins,
    execute_plugins,
)
from src.tools.run_all_detection import ArtefactPaths


def _artefacts(base: Path) -> ArtefactPaths:
    return ArtefactPaths(
        output_dir=base,
        payload_dir=base / "payloads",
        debug_dir=base / "debug",
        payload_debug_dir=base / "debug" / "payloads",
        chunk_debug_dir=base / "debug" / "chunks",
        raw_payload=base / "raw_payload.txt",
        raw_payload_bin=base / "debug" / "raw_payload.bin",
        manifest_json=base / "raw_manifest.json",
        chunks_json=base / "bootstrap_chunks.json",
        bootstrap_candidates_json=base / "bootstrap_candidates.json",
        bytes_meta_json=base / "bytes" / "meta.json",
        pipeline_json=base / "pipeline_candidates.json",
        mapping_json=base / "mapping_candidates.json",
        opcode_proposals=base / "opcode_proposals.json",
        opcode_maps_dir=base / "opcode_maps",
        opcode_annotations_md=base / "opcode_annotations.md",
        graph_dot=base / "pipeline_graph.dot",
        graphs_dir=base / "graphs",
        report_md=base / "detection_report.md",
        ir_candidates_dir=base / "ir_candidates",
        user_report_md=base / "user_report.md",
        recommendations_md=base / "recommendations.md",
        runs_dir=base / "runs",
        handler_tests_dir=base / "handler_tests",
        metrics_dir=base / "metrics",
    )


def test_discover_plugins_filters_allowlist(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "use_me.py").write_text(
        "PLUGIN_NAME = 'accept_me'\n" "requires_key = False\n" "def run_plugin(context):\n    pass\n",
        encoding="utf-8",
    )

    discovery = discover_plugins(plugin_dir, ["accept_me"], logger=None)
    assert not discovery.missing
    assert len(discovery.plugins) == 1
    assert discovery.plugins[0].name == "accept_me"

    missing = discover_plugins(plugin_dir, ["not_present"], logger=None)
    assert missing.plugins == []
    assert missing.missing == ["not_present"]


def test_execute_plugins_runs_callable(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "sample.py").write_text(
        "PLUGIN_NAME = 'sample'\n"
        "requires_key = False\n"
        "def run_plugin(context):\n"
        "    context.metadata.setdefault('executed', []).append(context.plugin_name)\n"
        "    (context.artefacts.output_dir / 'plugin_marker.txt').write_text('ran', encoding='utf-8')\n",
        encoding="utf-8",
    )

    discovery = discover_plugins(plugin_dir, ["sample"], logger=None)
    context = PluginContext(
        artefacts=_artefacts(tmp_path / "out"),
        pipeline_report={},
        mapping_report={},
        metadata={},
        session_key_provided=False,
    )
    context.artefacts.output_dir.mkdir(parents=True, exist_ok=True)

    execute_plugins(discovery.plugins, context, logger=None)

    assert context.metadata["executed"] == ["sample"]
    assert (context.artefacts.output_dir / "plugin_marker.txt").read_text(encoding="utf-8") == "ran"


def test_plugins_requesting_key_are_rejected(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "needs_key.py").write_text(
        "PLUGIN_NAME = 'needs_key'\n" "requires_key = True\n" "def run_plugin(context):\n    pass\n",
        encoding="utf-8",
    )

    discovery = discover_plugins(plugin_dir, ["needs_key"], logger=None)
    context = PluginContext(
        artefacts=_artefacts(tmp_path / "out"),
        pipeline_report={},
        mapping_report={},
        metadata={},
        session_key_provided=True,
    )

    with pytest.raises(PluginKeyRequestError):
        execute_plugins(discovery.plugins, context, logger=None)


def test_invalid_plugin_missing_flag(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "broken.py").write_text(
        "PLUGIN_NAME = 'broken'\n" "def run_plugin(context):\n    pass\n",
        encoding="utf-8",
    )

    with pytest.raises(PluginValidationError):
        discover_plugins(plugin_dir, ["broken"], logger=None)
