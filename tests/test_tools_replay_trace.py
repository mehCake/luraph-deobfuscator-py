import json
from pathlib import Path

from src.tools.replay_trace import (
    build_arg_parser,
    load_opcode_map,
    load_trace,
    main as replay_trace_main,
    replay_trace,
    write_report,
)


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _sample_trace_payload() -> dict:
    return {
        "run": "unit",
        "events": [
            {
                "pc": 1,
                "opcode": "LOADK",
                "registers": [0, 123],
                "extras": {
                    "raw_opcode": 1,
                    "operands": {"dest": 0, "const": 123},
                    "writes": [{"reg": 0, "value": 123}],
                },
            },
            {
                "pc": 2,
                "opcode": "ADD",
                "registers": [1, 0, 0],
                "extras": {
                    "raw_opcode": 2,
                    "operands": {"dest": 1, "lhs": 0, "rhs": 0},
                    "writes": [{"reg": 1, "value": 246}],
                },
            },
        ],
    }


def _sample_opcode_map(overrides=None) -> dict:
    mapping = {"1": "LOADK", "2": "ADD"}
    if overrides:
        mapping.update({str(key): value for key, value in overrides.items()})
    return {"mnemonics": mapping}


def test_replay_trace_matches_expected(tmp_path: Path):
    trace_path = _write_json(tmp_path / "trace.json", _sample_trace_payload())
    map_path = _write_json(tmp_path / "map.json", _sample_opcode_map())

    recording = load_trace(trace_path)
    opcode_map = load_opcode_map(map_path)
    report = replay_trace(recording, opcode_map, version_hint="v14.4.2")

    assert report.summary["events_processed"] == 2
    assert not report.differences
    target = write_report(report, tmp_path / "reports", "unit")
    assert target.exists()
    saved = json.loads(target.read_text(encoding="utf-8"))
    assert saved["summary"]["events_processed"] == 2


def test_replay_trace_detects_mismatch_and_suggests_fix(tmp_path: Path):
    trace_path = _write_json(tmp_path / "trace.json", _sample_trace_payload())
    bad_map_path = _write_json(tmp_path / "bad_map.json", _sample_opcode_map({2: "MOVE"}))

    report = replay_trace(load_trace(trace_path), load_opcode_map(bad_map_path), version_hint="v14.4.2")

    assert len(report.differences) == 2  # mnemonic + write mismatch
    suggestions = {suggestion.raw_opcode: suggestion for suggestion in report.suggestions}
    assert suggestions[2].suggested_mnemonic == "ADD"
    assert suggestions[2].confidence >= 0.7


def test_cli_writes_report(tmp_path: Path):
    trace_path = _write_json(tmp_path / "trace.json", _sample_trace_payload())
    map_path = _write_json(tmp_path / "map.json", _sample_opcode_map())

    argv = [
        str(trace_path),
        str(map_path),
        "--output-dir",
        str(tmp_path / "replays"),
        "--candidate-name",
        "cli",
        "--version-hint",
        "v14.4.2",
    ]

    exit_code = replay_trace_main(argv)
    assert exit_code == 0
    report_path = tmp_path / "replays" / "cli.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    assert payload["summary"]["difference_count"] == 0


def test_arg_parser_defaults():
    parser = build_arg_parser()
    args = parser.parse_args(["trace.json", "map.json"])
    assert args.candidate_name == "candidate"
    assert args.output_dir == Path("out/replay")
