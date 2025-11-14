import json
from pathlib import Path
from types import SimpleNamespace

from src.tools.run_all_detection import (
    ArtefactPaths,
    _copy_key_material,
    _scrub_buffer,
    _write_opcode_map_candidates,
    run_detection,
)
from src.vm.opcode_proposer import OpcodeMapCandidate, OpcodeProposal


def test_write_opcode_map_candidates(tmp_path) -> None:
    proposal = OpcodeProposal(
        opcode=0,
        mnemonic="LOADK",
        confidence=0.9,
        handlers=("handler_loadk",),
        reasons=("rank-1",),
    )
    candidate = OpcodeMapCandidate(mapping={0: "LOADK"}, confidence=0.9, selections={0: proposal})

    paths = _write_opcode_map_candidates(tmp_path, [candidate])
    assert len(paths) == 1
    output_path = paths[0]
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["mapping"] == {"0": "LOADK"}
    assert payload["confidence"] == 0.9


def test_run_detection_scrubs_session_key(monkeypatch, tmp_path) -> None:
    target = tmp_path / "stub.lua"
    target.write_text("return 1", encoding="utf-8")

    # Minimal artefact paths to keep directories consistent
    def fake_determine_paths(base: Path, report: Path | None) -> ArtefactPaths:
        base.mkdir(parents=True, exist_ok=True)
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

    monkeypatch.setattr("src.tools.run_all_detection._determine_paths", fake_determine_paths)
    monkeypatch.setattr(
        "src.tools.run_all_detection.load_lua_file",
        lambda *_args, **_kwargs: (
            "--stub",
            {"large_payload": "A" * 1024},
            [{"kind": "string", "start": 0, "end": 10, "length": 10}],
        ),
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.extract_bootstrap_chunks",
        lambda _text: [SimpleNamespace(kind="load", start=0, end=10, text="loadstring('x')")],
    )

    class _Candidate:
        def to_dict(self) -> dict[str, object]:
            return {"name": "candidate", "offset": 0, "length": 10, "kind": "load"}

    monkeypatch.setattr(
        "src.tools.run_all_detection.identify_bootstrap_candidates",
        lambda _manifest, _raw, _payload_dir: [_Candidate()],
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.generate_candidate_bytes",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.collect_pipeline_candidates",
        lambda *_args, **_kwargs: {
            "pipeline": [],
            "chunks": [],
            "pipeline_confidence": 0.1,
            "pipelines": [
                {
                    "sequence": ["loadstring"],
                    "confidence": 0.1,
                    "hypothesis_score": {
                        "overall": 0.1,
                        "components": {
                            "pipeline": 0.1,
                            "english": 0.0,
                            "lua": 0.0,
                            "parity": 0.0,
                            "mapping": 0.0,
                        },
                        "notes": [],
                    },
                    "scoring_context": {
                        "pipeline_confidence": 0.1,
                        "english_scores": [],
                        "lua_scores": [],
                    },
                }
            ],
        },
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.propose_opcode_mappings",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.group_proposals_by_opcode",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.generate_map_candidates",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.detect_mapping_candidates",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.generate_pipeline_graphs",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "src.tools.run_all_detection.render_pipeline_graph",
        lambda *_args, **_kwargs: "digraph{}",
    )

    validation_calls: list[Path] = []

    def fake_validate_json_directory(path: Path, **_kwargs):
        validation_calls.append(path)
        return []

    monkeypatch.setattr(
        "src.tools.run_all_detection.validate_json_directory",
        fake_validate_json_directory,
    )

    backup_calls: list[tuple[Path, object, object]] = []

    def fake_snapshot_analysis_inputs(*, output_dir, plan, timestamp=None):
        backup_calls.append((output_dir, plan, timestamp))
        return output_dir / "backups" / "run-test"

    monkeypatch.setattr(
        "src.tools.run_all_detection.snapshot_analysis_inputs",
        fake_snapshot_analysis_inputs,
    )

    from src.tools.heuristics import VMStyleScore

    monkeypatch.setattr(
        "src.tools.run_all_detection.detect_vm_style",
        lambda _instructions: VMStyleScore(
            style="unknown",
            confidence=0.0,
            register_score=0.0,
            stack_score=0.0,
            sample_size=0,
            max_operand=0,
            unique_operands=0,
            small_operand_ratio=0.0,
            sequential_ratio=0.0,
        ),
    )

    key_buffer = _copy_key_material("secret")
    assert key_buffer is not None

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    (plugin_dir / "sample_plugin.py").write_text(
        "PLUGIN_NAME = 'sample'\n"
        "requires_key = False\n"
        "def run_plugin(context):\n"
        "    marker = context.artefacts.output_dir / 'plugin_executed.txt'\n"
        "    marker.parent.mkdir(parents=True, exist_ok=True)\n"
        "    marker.write_text('executed', encoding='utf-8')\n"
        "    context.metadata.setdefault('plugins', []).append(context.plugin_name)\n",
        encoding="utf-8",
    )

    artefacts = run_detection(
        target,
        output_dir=tmp_path / "out",
        debug=False,
        session_key=key_buffer,
        plugins=["sample"],
        plugin_search_dir=plugin_dir,
    )

    assert artefacts.output_dir.exists()
    assert all(byte == 0 for byte in key_buffer)
    assert backup_calls
    assert backup_calls[0][0] == artefacts.output_dir
    assert artefacts.user_report_md.exists()
    assert artefacts.recommendations_md.exists()
    assert artefacts.run_manifest_path is not None
    assert artefacts.run_manifest_path.exists()
    assert artefacts.metrics_path is not None
    assert artefacts.metrics_path.exists()
    assert validation_calls == [artefacts.output_dir]
    assert (artefacts.output_dir / "plugin_executed.txt").read_text(encoding="utf-8") == "executed"
    license_copy = artefacts.output_dir / "LICENSE"
    assert license_copy.exists()
    assert license_copy.read_text(encoding="utf-8").startswith("MIT License")
    report_text = artefacts.report_md.read_text(encoding="utf-8")
    assert report_text.startswith("<!-- Licensed under the MIT License")
    user_summary_text = artefacts.user_report_md.read_text(encoding="utf-8")
    assert user_summary_text.startswith("<!-- Licensed under the MIT License")
    recommendations_text = artefacts.recommendations_md.read_text(encoding="utf-8")
    assert recommendations_text.startswith("<!-- Licensed under the MIT License")


def test_scrub_buffer_idempotent() -> None:
    sample = bytearray(b"abc")
    _scrub_buffer(sample)
    assert sample == bytearray(b"\x00\x00\x00")
    _scrub_buffer(sample)
    assert sample == bytearray(b"\x00\x00\x00")

