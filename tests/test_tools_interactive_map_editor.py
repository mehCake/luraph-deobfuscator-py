import json
from pathlib import Path

from src.tools.interactive_map_editor import (
    MapEditorShell,
    create_session,
    load_candidate_mapping,
    load_handler_entries,
    load_base_mapping,
    run_editor,
)


def _write_handler_file(tmp_path: Path) -> Path:
    payload = {
        "handlers": [
            {
                "name": "handler_call",
                "opcode": 1,
                "resolvable": True,
                "body": "stack[ra] = constants[rb]\nreturn stack[ra]",
                "candidates": [
                    {"mnemonic": "CALL", "confidence": 0.9},
                    {"mnemonic": "LOADK", "confidence": 0.6},
                ],
            },
            {
                "name": "handler_return",
                "opcode": 2,
                "resolvable": True,
                "body": "return stack[ra]",
                "candidates": [{"mnemonic": "RETURN", "confidence": 0.8}],
            },
        ]
    }
    path = tmp_path / "handler_suggestions.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _write_proposals_file(tmp_path: Path) -> Path:
    payload = {
        "candidates": [
            {
                "name": "candidate-01",
                "mapping": {"1": "CALL", "2": "RETURN"},
                "confidence": 0.82,
            }
        ]
    }
    path = tmp_path / "opcode_proposals.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _write_existing_map(tmp_path: Path) -> Path:
    payload = {"mnemonics": {"3": "JMP"}}
    path = tmp_path / "existing_map.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_accept_writes_map(tmp_path: Path) -> None:
    handler_path = _write_handler_file(tmp_path)
    proposal_path = _write_proposals_file(tmp_path)
    entries = load_handler_entries(handler_path)
    candidate_name, proposed = load_candidate_mapping(proposal_path)
    session = create_session(
        entries=entries,
        candidate_name=candidate_name,
        proposed_mapping=proposed,
        base_mapping={},
        output_dir=tmp_path / "out/opcode_maps",
    )
    session.auto_save = True
    session.accept()  # accept opcode 1 default (CALL)
    saved = session.output_path
    assert saved.exists()
    data = json.loads(saved.read_text(encoding="utf-8"))
    assert data["mnemonics"]["1"] == "CALL"


def test_undo_reverts_last_change(tmp_path: Path) -> None:
    handler_path = _write_handler_file(tmp_path)
    proposal_path = _write_proposals_file(tmp_path)
    entries = load_handler_entries(handler_path)
    candidate_name, proposed = load_candidate_mapping(proposal_path)
    session = create_session(
        entries=entries,
        candidate_name=candidate_name,
        proposed_mapping=proposed,
        base_mapping={},
        output_dir=tmp_path / "out/opcode_maps",
    )
    session.auto_save = True
    session.accept()  # CALL
    session.current_index = 0
    session.modify("RETURN")
    assert session.mapping[1] == "RETURN"
    session.undo()
    assert session.mapping[1] == "CALL"
    data = json.loads(session.output_path.read_text(encoding="utf-8"))
    assert data["mnemonics"]["1"] == "CALL"


def test_merge_preserves_existing_entries(tmp_path: Path) -> None:
    handler_path = _write_handler_file(tmp_path)
    proposal_path = _write_proposals_file(tmp_path)
    existing_map_path = _write_existing_map(tmp_path)

    entries = load_handler_entries(handler_path)
    candidate_name, proposed = load_candidate_mapping(proposal_path)
    base_mapping = load_base_mapping(existing_map_path)
    session = create_session(
        entries=entries,
        candidate_name=candidate_name,
        proposed_mapping=proposed,
        base_mapping=base_mapping,
        output_dir=tmp_path / "out/opcode_maps",
    )
    session.auto_save = True
    session.accept()  # opcode 1 -> CALL
    other_map = {2: "RETURN"}
    session.merge_from_map(other_map)
    saved = session.output_path
    data = json.loads(saved.read_text(encoding="utf-8"))
    assert data["mnemonics"]["1"] == "CALL"
    assert data["mnemonics"]["2"] == "RETURN"
    assert data["mnemonics"]["3"] == "JMP"


def test_shell_shortcuts_drive_session(tmp_path: Path) -> None:
    handler_path = _write_handler_file(tmp_path)
    proposal_path = _write_proposals_file(tmp_path)
    entries = load_handler_entries(handler_path)
    candidate_name, proposed = load_candidate_mapping(proposal_path)
    session = create_session(
        entries=entries,
        candidate_name=candidate_name,
        proposed_mapping=proposed,
        base_mapping={},
        output_dir=tmp_path / "out/opcode_maps",
    )
    session.auto_save = False  # Avoid filesystem churn for this interaction test
    shell = MapEditorShell(session)
    shell.onecmd("show")
    shell.onecmd("a")
    assert session.mapping[1] == "CALL"
    shell.onecmd("m RETURN")
    assert session.mapping[2] == "RETURN"
    shell.onecmd("u")
    assert 2 not in session.mapping
    shell.onecmd("r")
    assert 2 not in session.mapping


def test_run_editor_auto_accept(tmp_path: Path) -> None:
    handler_path = _write_handler_file(tmp_path)
    proposal_path = _write_proposals_file(tmp_path)
    session = run_editor(
        handler_path=handler_path,
        proposal_path=proposal_path,
        candidate=None,
        base_map_path=None,
        output_dir=tmp_path / "out/opcode_maps",
        version="14.4.2",
        auto_accept=True,
    )
    saved = session.output_path
    assert saved.exists()
    data = json.loads(saved.read_text(encoding="utf-8"))
    assert data["mnemonics"]["1"] == "CALL"
    assert data["mnemonics"]["2"] == "RETURN"
