import json
from pathlib import Path

from src.vm.opcode_mapper_tui import (
    HandlerInfo,
    OpcodeMappingSession,
    load_handler_index,
    load_mapping_file,
)


PIPELINE_SAMPLE = {
    "chunks": [
        {
            "handler_map": [
                {
                    "opcode": 1,
                    "handler": "handle_call",
                    "mnemonics": ["CALL", "INVOKE"],
                    "body": "function handle_call(base)\n    return stack[base]()\nend",
                },
                {
                    "opcode": "2",
                    "handler": "handle_return",
                    "mnemonics": ("RETURN",),
                    "body": "function handle_return(base)\n    return stack[base]\nend",
                },
            ]
        }
    ],
    "opcode_mnemonics": {"1": ["CALL"], "2": ["RETURN", "RET"]},
}


CANDIDATE_SAMPLE = {
    "mapping": {"1": "CALL", "2": "RETURN"},
    "confidence": 0.5,
}


MNEMONIC_SAMPLE = {"mnemonics": {"3": "LOADK"}}


def test_load_handler_index_collects_candidates() -> None:
    handlers = load_handler_index(PIPELINE_SAMPLE)
    assert set(handlers.keys()) == {1, 2}

    info_call = handlers[1]
    assert isinstance(info_call, HandlerInfo)
    assert info_call.handlers == ["handle_call"]
    assert "CALL" in info_call.candidates
    assert info_call.bodies and "stack" in info_call.bodies[0]

    info_return = handlers[2]
    assert "RETURN" in info_return.candidates and "RET" in info_return.candidates


def test_session_save_and_load(tmp_path) -> None:
    handlers = load_handler_index(PIPELINE_SAMPLE)
    session = OpcodeMappingSession(handlers=handlers)
    session.assign(1, "call")
    session.assign(2, "Return")

    output = session.save(tmp_path / "map.json")
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mnemonics"] == {"1": "CALL", "2": "RETURN"}

    temp_path = tmp_path / "candidate.json"
    temp_path.write_text(json.dumps(CANDIDATE_SAMPLE), encoding="utf-8")
    mapping = load_mapping_file(temp_path)
    assert mapping == {1: "CALL", 2: "RETURN"}

    temp_path.write_text(json.dumps(MNEMONIC_SAMPLE), encoding="utf-8")
    mapping = load_mapping_file(temp_path)
    assert mapping == {3: "LOADK"}
