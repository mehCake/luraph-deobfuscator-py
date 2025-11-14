import json
from pathlib import Path

from src.tools.generate_handler_tests import generate_handler_tests


def _sample_report() -> dict:
    return {
        "chunks": [
            {
                "kind": "vm_dispatch",
                "start": 0,
                "end": 120,
                "handler_map": [
                    {
                        "opcode": 3,
                        "handler": "handler_loadk",
                        "mnemonics": ["LOADK"],
                        "body": "stack[ra + 1] = constants[rb + 1]\nvm.pc = vm.pc + 1\nreturn stack[ra + 1]",
                    },
                    {
                        "opcode": 5,
                        "handler": "handler_jump",
                        "mnemonics": ["JMP"],
                        "body": "if stack[ra + 1] then vm.pc = vm.pc + 4 end",
                    },
                ],
            }
        ]
    }


def test_generate_handler_tests_writes_snippets(tmp_path: Path) -> None:
    report = _sample_report()
    output_dir = tmp_path / "handler_tests"
    suite = generate_handler_tests(report, output_dir=output_dir, pipeline_path=tmp_path / "pipeline.json")

    assert suite is not None
    assert len(suite.cases) == 2
    assert suite.manifest_path.exists()
    assert suite.definitions_path.exists()

    manifest = json.loads(suite.manifest_path.read_text(encoding="utf-8"))
    assert manifest["tests"][0]["handler"] == "handler_loadk"

    definitions = json.loads(suite.definitions_path.read_text(encoding="utf-8"))
    assert definitions["testcases"][0]["entrypoint"] == "run_handler_test"

    first_snippet = suite.cases[0].snippet_path.read_text(encoding="utf-8")
    assert "local function handler_under_test()" in first_snippet
    assert "stack = vm.stack" in first_snippet
    assert "return run_handler_test()" in first_snippet


def test_generate_handler_tests_handles_empty(tmp_path: Path) -> None:
    report = {"chunks": []}
    suite = generate_handler_tests(report, output_dir=tmp_path / "handler_tests")
    assert suite is None

