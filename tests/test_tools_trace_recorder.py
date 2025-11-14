import json
from pathlib import Path

import pytest

from src.tools.trace_recorder import (
    LuaRuntime,
    TraceRecorderError,
    build_arg_parser,
    main as trace_recorder_main,
    record_trace,
    write_trace,
)


SAMPLE_TRACE_JSON = json.dumps(
    [
        {"pc": 1, "opcode": "LOADK", "registers": [1, 7], "stack": 2, "extras": {"note": "init"}},
        {"pc": 2, "opcode": "ADD", "registers": [2, 3], "stack": 2, "extras": {"note": "bump"}},
    ]
)

SAMPLE_LUA = f"""
-- trace: {SAMPLE_TRACE_JSON}
"""


def _using_fallback_runtime() -> bool:
    runtime = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    return getattr(runtime, "is_fallback", False)


def test_record_trace_and_write(tmp_path: Path):
    recording = record_trace(
        SAMPLE_LUA,
        entry_point="run",
        run_name="sample",
        input_data={"opcodes": [{"name": "LOADK"}, {"name": "ADD"}]},
        max_instructions=8,
    )

    assert recording.run_name == "sample"
    assert len(recording.events) == 2
    first, second = recording.events
    assert first.stack_depth == 2
    assert first.register_usage == 2
    assert first.opcode == "LOADK"
    assert second.opcode == "ADD"
    target = write_trace(recording, tmp_path)
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["summary"]["total_instructions"] == 2
    assert payload["events"][0]["extras"]["note"] == "init"


def test_sandbox_blocks_io():
    if _using_fallback_runtime():
        pytest.skip("sandbox enforcement not available under fallback runtime")
    lua_source = """
function run()
  local fh = io.open('forbidden.txt', 'w')
end
"""
    with pytest.raises(TraceRecorderError, match="io.open"):
        record_trace(lua_source, entry_point="run", run_name="forbidden")


def test_cli_entrypoint(tmp_path: Path, monkeypatch):
    lua_file = tmp_path / "trace.lua"
    lua_file.write_text(SAMPLE_LUA, encoding="utf-8")
    input_json = tmp_path / "input.json"
    input_json.write_text(json.dumps({"opcodes": [{"name": "LOADK"}]}), encoding="utf-8")

    argv = [
        str(lua_file),
        "--entry",
        "run",
        "--run-name",
        "cli",
        "--output-dir",
        str(tmp_path / "traces"),
        "--input-json",
        str(input_json),
        "--max-instructions",
        "4",
    ]

    exit_code = trace_recorder_main(argv)
    assert exit_code == 0
    trace_path = tmp_path / "traces" / "cli.json"
    assert trace_path.exists()


def test_arg_parser_has_expected_defaults():
    parser = build_arg_parser()
    args = parser.parse_args(["sample.lua"])
    assert args.entry == "run"
    assert args.max_instructions == 1024
