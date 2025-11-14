import json
from pathlib import Path

import pytest

from src.vm.opcode_map import (
    MapCandidate,
    apply_map_to_disasm,
    load_map,
    main as opcode_map_main,
    persist_candidate,
    score_map,
    suggest_map_from_handlers,
)


SAMPLE_BOOTSTRAP = """
local stack = {}
local consts = {}

function handle_v1442_loadk(base)
    stack[base] = consts[pc]
end

function handle_v1442_call(base)
    return stack[base](stack[base + 1])
end

function handle_v1442_return(base)
    return stack[base]
end

if opcode == 1 then
    return handle_v1442_loadk(base)
elseif opcode == 5 then
    return handle_v1442_call(base)
elseif opcode == 6 then
    return handle_v1442_return(base)
end
"""


def test_suggest_map_from_handlers_returns_candidates() -> None:
    candidates = suggest_map_from_handlers(SAMPLE_BOOTSTRAP)
    assert candidates, "expected at least one candidate"

    primary = candidates[0]
    assert isinstance(primary, MapCandidate)
    assert primary.mapping[1] == "LOADK"
    assert primary.mapping[5] == "CALL"
    assert primary.mapping[6] == "RETURN"
    assert 0.0 < primary.score <= 1.0


def test_score_map_prefers_core_mnemonics() -> None:
    mapping = {1: "LOADK", 5: "CALL", 6: "RETURN"}
    assert score_map(mapping) == pytest.approx(1.0)

    weaker = {1: "LOADK", 2: "SOMETHING"}
    assert score_map(weaker) < 1.0


def test_apply_map_to_disasm_injects_mnemonics() -> None:
    mapping = {1: "LOADK"}
    disasm = [
        {"index": 0, "raw": 0x01020304, "opcode": 1, "a": 0, "b": 1, "c": 2},
        {"index": 1, "raw": 0xFFFFFFFF, "opcode": 255, "a": 0, "b": 0, "c": 0},
    ]
    result = apply_map_to_disasm(mapping, disasm)
    assert result[0]["mnemonic"] == "LOADK"
    assert result[1]["mnemonic"] == "OP_FF"


def test_persist_and_load_candidate(tmp_path: Path) -> None:
    candidates = suggest_map_from_handlers(SAMPLE_BOOTSTRAP)
    candidate = candidates[0]
    path = persist_candidate(candidate, name="sample", output_dir=tmp_path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["score"] == candidate.score
    assert "mnemonics" in payload["map"]

    loaded = load_map(path)
    assert loaded.get_mnemonic(1) == "LOADK"


def test_cli_suggest_and_inspect(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snippet_path = tmp_path / "snippet.lua"
    snippet_path.write_text(SAMPLE_BOOTSTRAP, encoding="utf-8")

    output_dir = tmp_path / "maps"
    exit_code = opcode_map_main(
        [
            "suggest",
            str(snippet_path),
            "--output-dir",
            str(output_dir),
            "--base-name",
            "test",
            "--limit",
            "1",
        ]
    )
    assert exit_code == 0

    files = sorted(output_dir.glob("test-*.json"))
    assert len(files) == 1

    exit_code = opcode_map_main(["inspect", str(files[0])])
    assert exit_code == 0
    captured = capsys.readouterr().out
    assert "LOADK" in captured and "CALL" in captured and "RETURN" in captured
