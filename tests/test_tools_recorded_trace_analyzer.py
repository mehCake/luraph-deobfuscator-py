from pathlib import Path

import pytest

from src.tools.recorded_trace_analyzer import (
    TraceAnalysisReport,
    analyze_trace,
    build_arg_parser,
    main as trace_analysis_main,
)
from src.tools.trace_recorder import TraceEvent, TraceRecording, write_trace


@pytest.fixture()
def sample_recording() -> TraceRecording:
    return TraceRecording(
        run_name="demo",
        events=[
            TraceEvent(
                pc=1,
                opcode="LOADK",
                stack_depth=1,
                register_usage=1,
                registers=[0],
                extras={"handler": "LOADK", "ra": 0},
            ),
            TraceEvent(
                pc=2,
                opcode="MOVE",
                stack_depth=1,
                register_usage=1,
                registers=[1],
                extras={"handler": "MOVE", "ra": 1},
            ),
            TraceEvent(
                pc=3,
                opcode="LOADK",
                stack_depth=1,
                register_usage=1,
                registers=[0],
                extras={"handler": "LOADK", "ra": 0},
            ),
        ],
        metadata={"version": "v14.4.2", "note": "unit-test"},
    )


def test_analyze_trace_register_lifetimes(sample_recording: TraceRecording):
    report = analyze_trace(sample_recording, max_pattern_length=2)
    assert isinstance(report, TraceAnalysisReport)
    assert report.total_events == 3
    lifetimes = {item.register: item for item in report.register_lifetimes}
    assert lifetimes["R0"].first_pc == 1
    assert lifetimes["R0"].last_pc == 3
    assert lifetimes["R0"].occurrences == 2
    handlers = {item.handler: item for item in report.hot_handlers}
    assert handlers["LOADK"].count == 2
    # No repeated patterns expected for this small trace, but prologue should reflect start.
    assert report.prologue[0] == "LOADK"
    markdown = report.as_markdown()
    assert "Trace analysis for demo" in markdown
    assert "Total instructions" in markdown


def test_cli_writes_markdown_and_csv(tmp_path: Path, sample_recording: TraceRecording):
    trace_path = write_trace(sample_recording, tmp_path)
    output_dir = tmp_path / "analysis"
    argv = [str(trace_path), "--output-dir", str(output_dir)]
    exit_code = trace_analysis_main(argv)
    assert exit_code == 0
    markdown_path = output_dir / "demo.md"
    assert markdown_path.exists()
    assert "Trace analysis" in markdown_path.read_text(encoding="utf-8")
    registers_csv = output_dir / "demo_registers.csv"
    handlers_csv = output_dir / "demo_handlers.csv"
    patterns_csv = output_dir / "demo_patterns.csv"
    for csv_path in (registers_csv, handlers_csv, patterns_csv):
        assert csv_path.exists()
        content = csv_path.read_text(encoding="utf-8")
        assert content.splitlines()[0]


def test_arg_parser_defaults():
    parser = build_arg_parser()
    args = parser.parse_args(["trace.json"])
    assert args.output_dir == Path("out/trace_analysis")
    assert args.max_pattern_length == 3
    assert args.top_handlers == 10
