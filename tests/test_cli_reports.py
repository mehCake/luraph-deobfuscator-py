from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import main as cli_main
from src.cli import reporting as cli_reporting
from src.cli.reporting import run_lifter_for_cli
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


def test_run_lifter_skips_when_mandatory_opcodes_missing(tmp_path, monkeypatch):
    source_path = tmp_path / "input.lua"
    output_path = tmp_path / "output.lua"
    source_path.write_text("return true", encoding="utf-8")

    ctx = SimpleNamespace(
        vm_ir=SimpleNamespace(bytecode=[], constants=[], opcode_map={}, prototypes=[]),
        vm_metadata={"errors": ["missing/low-trust: LOADK"]},
        options={},
        report=None,
    )

    invoked = False

    def _fail_run(*args, **kwargs):  # pragma: no cover - sanity guard
        nonlocal invoked
        invoked = True
        raise AssertionError("accurate lifter should not run when mandatory ops are missing")

    monkeypatch.setattr(cli_reporting, "run_lifter_safe", _fail_run)

    result = run_lifter_for_cli(
        ctx,
        source_path=source_path,
        output_path=output_path,
        mode="accurate",
    )

    assert invoked is False
    metadata = result.get("metadata", {})
    assert metadata.get("status") == "skipped"
    assert "missing/low-trust: LOADK" in metadata.get("errors", [])


def _stub_pipeline_with_metadata(monkeypatch, metadata):
    def fake_run_passes(ctx, skip=None, only=None, profile=False):
        ctx.vm_ir = _FakeVMIR(constants=[], bytecode=[{"opcode": 0}], opcode_map={})
        ctx.vm_metadata.update(metadata)
        ctx.stage_output = "return true\n"
        ctx.output = ctx.stage_output
        ctx.report.version_detected = "stub_vm"
        ctx.report.output_length = len(ctx.output)
        ctx.pass_metadata.setdefault("payload_decode", {"handler_payload_meta": {}})
        return [("stub", 0.0)]

    monkeypatch.setattr(PIPELINE, "run_passes", fake_run_passes)


def test_cli_fails_when_mandatory_opcodes_low_trust(tmp_path, monkeypatch):
    target = tmp_path / "input.lua"
    target.write_text("return true", encoding="utf-8")
    out_dir = tmp_path / "out"

    _stub_pipeline_with_metadata(
        monkeypatch,
        {"errors": ["missing/low-trust: LOADK", "missing/low-trust: MOVE"]},
    )

    def fake_run_lifter(ctx, **kwargs):
        return {
            "metadata": {
                "mode": kwargs.get("mode", "accurate"),
                "status": "skipped",
                "reason": "mandatory opcode trust too low",
                "errors": ["missing/low-trust: LOADK"],
                "functions": 0,
            },
            "artifacts": {},
            "lift_metadata": {},
            "stack_trace": [],
        }

    monkeypatch.setattr(cli_reporting, "run_lifter_for_cli", fake_run_lifter)

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

    assert exit_code == 1

    report_path = out_dir / f"{target.stem}_deob.json"
    assert report_path.exists()
    data = json.loads(report_path.read_text(encoding="utf-8"))
    errors = data.get("report", {}).get("errors", [])
    assert any(
        "mandatory opcode coverage below threshold" in entry for entry in errors
    )


def test_cli_force_allows_mandatory_gap_with_warning(tmp_path, monkeypatch):
    target = tmp_path / "input.lua"
    target.write_text("return true", encoding="utf-8")
    out_dir = tmp_path / "out"

    _stub_pipeline_with_metadata(
        monkeypatch,
        {"errors": ["missing/low-trust: LOADK", "missing/low-trust: MOVE"]},
    )

    def fake_run_lifter(ctx, **kwargs):
        return {
            "metadata": {
                "mode": kwargs.get("mode", "accurate"),
                "status": "skipped",
                "reason": "mandatory opcode trust too low",
                "errors": ["missing/low-trust: LOADK"],
                "functions": 0,
            },
            "artifacts": {},
            "lift_metadata": {},
            "stack_trace": [],
        }

    monkeypatch.setattr(cli_reporting, "run_lifter_for_cli", fake_run_lifter)

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
            "--force",
        ]
    )

    assert exit_code == 0

    report_path = out_dir / f"{target.stem}_deob.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    warnings = data.get("report", {}).get("warnings", [])
    assert any(
        "mandatory opcode coverage below threshold" in entry for entry in warnings
    )


def test_cli_emits_placeholder_warning(tmp_path, monkeypatch, capsys):
    target = tmp_path / "input.lua"
    target.write_text("return true", encoding="utf-8")
    out_dir = tmp_path / "out"

    def fake_run_passes(ctx, skip=None, only=None, profile=False):
        ctx.vm_ir = _FakeVMIR(constants=[], bytecode=[{"opcode": 0}], opcode_map={})
        ctx.vm_metadata.setdefault("opcode_map", {})
        ctx.stage_output = "return true\n"
        ctx.output = ctx.stage_output
        ctx.report.version_detected = "stub_vm"
        ctx.report.output_length = len(ctx.output)
        ctx.pass_metadata["payload_decode"] = {
            "placeholder_output": True,
            "handler_payload_meta": {"placeholders_only": True},
        }
        return [("stub", 0.0)]

    monkeypatch.setattr(PIPELINE, "run_passes", fake_run_passes)

    def fake_run_lifter(ctx, **kwargs):
        return {
            "metadata": {
                "mode": kwargs.get("mode", "accurate"),
                "functions": 0,
            },
            "artifacts": {},
            "lift_metadata": {},
            "stack_trace": [],
        }

    monkeypatch.setattr(cli_reporting, "run_lifter_for_cli", fake_run_lifter)

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
    captured = capsys.readouterr()
    assert "placeholder-only output" in captured.out

    report_path = out_dir / f"{target.stem}_deob.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    warnings = data.get("report", {}).get("warnings", [])
    assert "placeholder-only output" in warnings

