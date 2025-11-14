from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.tools.resolve_with_testcases import (
    ResolveWithTestcasesError,
    load_testcases,
    main as run_resolve_with_testcases,
    resolve_with_testcases,
)
from src.tools.trace_recorder import LuaRuntime


def _using_fallback_runtime() -> bool:
    runtime = LuaRuntime(unpack_returned_tuples=True, register_eval=False)
    return getattr(runtime, "is_fallback", False)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_resolve_with_bootstrap_and_logs(tmp_path: Path) -> None:
    if _using_fallback_runtime():
        pytest.skip("fallback Lua runtime cannot execute function definitions")
    bootstrap = tmp_path / "bootstrap.lua"
    bootstrap.write_text("function helper(value) return value * 2 end", encoding="utf-8")

    snippet = tmp_path / "snippet.lua"
    snippet.write_text(
        "print('running', 5)\nfunction run_case(value) return helper(value) + 1 end",
        encoding="utf-8",
    )

    testcase_path = tmp_path / "cases.json"
    _write_json(
        testcase_path,
        {
            "bootstrap": {"path": "bootstrap.lua"},
            "testcases": [
                {
                    "name": "double",
                    "lua_path": "snippet.lua",
                    "entrypoint": "run_case",
                    "args": [5],
                }
            ],
        },
    )

    definitions, bootstrap_source = load_testcases(testcase_path)
    assert bootstrap_source is not None
    summary = resolve_with_testcases(
        definitions,
        bootstrap_source=bootstrap_source,
        base_dir=testcase_path.parent,
    )

    assert summary.observations[0].returns == [11]
    assert summary.observations[0].logs == ["running 5"]


def test_rejects_remote_paths(tmp_path: Path) -> None:
    testcase_path = tmp_path / "cases.json"
    _write_json(
        testcase_path,
        {
            "testcases": [
                {
                    "name": "remote",
                    "lua_path": "https://example.com/snippet.lua",
                }
            ]
        },
    )

    with pytest.raises(ResolveWithTestcasesError):
        load_testcases(testcase_path)


def test_cli_writes_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    snippet = tmp_path / "inline.lua"
    snippet.write_text("function run_case(v) return v + 2 end", encoding="utf-8")

    testcase_path = tmp_path / "cases.json"
    _write_json(
        testcase_path,
        {
            "testcases": [
                {
                    "name": "inline",
                    "lua_path": "inline.lua",
                    "entrypoint": "run_case",
                    "args": [40],
                }
            ],
        },
    )

    output_path = tmp_path / "out.json"
    exit_code = run_resolve_with_testcases(
        [
            str(testcase_path),
            "--assume-yes",
            "--output",
            str(output_path),
            "--log-level",
            "WARNING",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert output_path.exists()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    observation = data["observations"][0]
    if _using_fallback_runtime():
        assert observation["success"] is False
        assert observation["error"]
    else:
        assert observation["returns"] == [42]
