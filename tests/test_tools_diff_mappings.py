import json

import pytest

from src.tools.diff_mappings import diff_opcode_maps, main as run_diff_mappings


def _entry_map(result):
    assert isinstance(result.suggestions, tuple)
    return {entry.source_opcode: entry for entry in result.suggestions}


def test_diff_mappings_prefers_exact_match():
    source = {1: "LOADK", 2: "CALL", 3: "MOVE"}
    target = {4: "LOADK", 8: "CALL", 9: "RETURN"}

    result = diff_opcode_maps(source, target, source_name="old", target_name="new", top=2)
    entries = _entry_map(result)

    assert entries[1].best and entries[1].best.target_opcode == 4
    assert entries[2].best and entries[2].best.target_opcode == 8
    assert entries[3].best is None
    assert (3, "MOVE") in result.unmatched_source
    assert (9, "RETURN") in result.unmatched_target


def test_diff_mappings_synonym_scores():
    source = {11: "RET"}
    target = {2: "RETURN"}

    result = diff_opcode_maps(source, target, min_score=0.3, top=1)
    entry = result.suggestions[0]
    assert entry.best is not None
    assert entry.best.score >= 0.6
    assert "synonym" in " ".join(entry.best.reasons).lower()


def test_diff_mappings_cli(tmp_path):
    source_path = tmp_path / "source.json"
    target_path = tmp_path / "target.json"
    output_path = tmp_path / "diff.json"

    source_path.write_text(json.dumps({"mnemonics": {"1": "LOADK", "2": "CALL"}}, indent=2))
    target_path.write_text(json.dumps({"mnemonics": {"5": "CALL", "7": "LOADK"}}, indent=2))

    exit_code = run_diff_mappings([
        str(source_path),
        str(target_path),
        "--output",
        str(output_path),
        "--log-level",
        "ERROR",
    ])
    assert exit_code == 0

    payload = json.loads(output_path.read_text())
    assert payload["source"].endswith("source.json")
    assert payload["target"].endswith("target.json")
    assert payload["suggestions"], "expected at least one suggestion in diff output"
