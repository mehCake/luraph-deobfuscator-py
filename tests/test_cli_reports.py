from __future__ import annotations

import json
from pathlib import Path

import pytest

from src import main as cli_main
from src.pipeline import PIPELINE

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class _FakeVMIR:
    def __init__(self, *, constants, bytecode, opcode_map, prototypes=None):
        self.constants = constants
        self.bytecode = bytecode
        self.opcode_map = opcode_map
        self.prototypes = prototypes or []


@pytest.fixture
def lifter_fixture_data() -> tuple[dict[str, object], dict[str, object]]:
    unpacked_path = PROJECT_ROOT / "tests" / "fixtures" / "v14_4_1" / "expected_unpacked.json"
    opcode_path = PROJECT_ROOT / "tests" / "fixtures" / "v14_4_1" / "expected_opcodes.json"
    unpacked = json.loads(unpacked_path.read_text(encoding="utf-8"))
    opcode_map = json.loads(opcode_path.read_text(encoding="utf-8"))
    return unpacked, opcode_map


def test_cli_lifter_artifacts_and_metadata(tmp_path, monkeypatch, lifter_fixture_data):
    unpacked, opcode_map = lifter_fixture_data

    def fake_run_passes(ctx, skip=None, only=None, profile=False):
        from src.utils.luraph_vm import rebuild_vm_bytecode

        rebuild = rebuild_vm_bytecode(unpacked, opcode_map)
        ctx.vm_ir = _FakeVMIR(
            constants=rebuild.constants,
            bytecode=rebuild.instructions,
            opcode_map=opcode_map,
            prototypes=[],
        )
        ctx.vm_metadata.setdefault("opcode_map", opcode_map)
        ctx.stage_output = "return true\n"
        ctx.output = ctx.stage_output
        ctx.report.version_detected = "stub_vm"
        ctx.report.output_length = len(ctx.output)
        ctx.pass_metadata.setdefault("payload_decode", {"handler_payload_meta": {}})
        return [("stub", 0.0)]

    monkeypatch.setattr(PIPELINE, "run_passes", fake_run_passes)

    target = tmp_path / "dummy.lua"
    target.write_text("return true", encoding="utf-8")
    out_dir = tmp_path / "out"

    exit_code = cli_main.main(
        [
            str(target),
            "--run-lifter",
            "--lifter-mode",
            "accurate",
            "--format",
            "json",
            "--out",
            str(out_dir),
        ]
    )
    assert exit_code == 0

    report_path = out_dir / f"{target.stem}_deob.json"
    assert report_path.exists()

    data = json.loads(report_path.read_text(encoding="utf-8"))
    vm_meta = data.get("vm_metadata", {})
    lifter_meta = vm_meta.get("lifter", {})

    assert lifter_meta.get("mode") == "accurate"
    assert lifter_meta.get("functions", 0) >= 1

    coverage = lifter_meta.get("opcode_coverage", {})
    assert isinstance(coverage, dict) and coverage.get("seen")

    artifacts = lifter_meta.get("artifacts", {})
    assert isinstance(artifacts, dict)

    decoded_path = Path(artifacts.get("decoded_output", ""))
    assert decoded_path.exists(), "decoded_output.lua should be written"
    decoded_text = decoded_path.read_text(encoding="utf-8")
    assert "loadk" in decoded_text.lower()

    metadata_path = Path(artifacts.get("metadata", ""))
    stack_path = Path(artifacts.get("stack", ""))
    assert metadata_path.exists()
    assert stack_path.exists()

    lift_meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert lift_meta.get("function_count", 0) >= 1

    stack_entries = json.loads(stack_path.read_text(encoding="utf-8"))
    assert isinstance(stack_entries, list)

    report_section = data.get("report", {})
    report_vm_meta = report_section.get("vm_metadata", {})
    assert report_vm_meta.get("lifter", {}).get("mode") == "accurate"

    lifter_artifacts = data.get("artifacts", {}).get("lifter", {})
    assert lifter_artifacts == artifacts

    lift_metadata_payload = data.get("lift_metadata")
    assert isinstance(lift_metadata_payload, dict)
    assert lift_metadata_payload.get("function_count", 0) >= 1


def test_cli_lifter_debug_outputs(tmp_path, monkeypatch, lifter_fixture_data):
    unpacked, opcode_map = lifter_fixture_data

    def fake_run_passes(ctx, skip=None, only=None, profile=False):
        from src.utils.luraph_vm import rebuild_vm_bytecode

        rebuild = rebuild_vm_bytecode(unpacked, opcode_map)
        ctx.vm_ir = _FakeVMIR(
            constants=rebuild.constants,
            bytecode=rebuild.instructions,
            opcode_map=opcode_map,
            prototypes=[],
        )
        ctx.vm_metadata.setdefault("opcode_map", opcode_map)
        ctx.stage_output = "return true\n"
        ctx.output = ctx.stage_output
        ctx.report.version_detected = "stub_vm"
        ctx.report.output_length = len(ctx.output)
        ctx.pass_metadata.setdefault("payload_decode", {"handler_payload_meta": {}})
        return [("stub", 0.0)]

    monkeypatch.setattr(PIPELINE, "run_passes", fake_run_passes)
    monkeypatch.chdir(tmp_path)

    target = Path("debug_input.lua")
    target.write_text("return true", encoding="utf-8")
    out_dir = Path("artifacts")

    exit_code = cli_main.main(
        [
            str(target),
            "--run-lifter",
            "--lifter-mode",
            "accurate",
            "--lifter-debug",
            "--format",
            "json",
            "--out",
            str(out_dir),
        ]
    )
    assert exit_code == 0

    debug_dir = Path("out") / "debug" / target.stem
    assert debug_dir.exists()

    raw_path = debug_dir / "raw_instructions.json"
    table_path = debug_dir / "opcode_table_used.json"
    snippets_path = debug_dir / "handler_snippets.json"
    trace_path = debug_dir / "lift_trace.log"

    for artifact in (raw_path, table_path, snippets_path, trace_path):
        assert artifact.exists(), f"missing {artifact.name}"

    raw_data = json.loads(raw_path.read_text(encoding="utf-8"))
    assert isinstance(raw_data, list) and raw_data, "raw instructions should not be empty"

    table_data = json.loads(table_path.read_text(encoding="utf-8"))
    assert isinstance(table_data, dict)

    trace_content = trace_path.read_text(encoding="utf-8")
    assert trace_content.strip(), "trace log should contain entries"

    report_path = out_dir / f"{target.stem}_deob.json"
    assert report_path.exists()
    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    lifter_meta = report_data.get("vm_metadata", {}).get("lifter", {})
    assert lifter_meta.get("debug_path") == str(debug_dir.resolve())
