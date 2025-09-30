from __future__ import annotations
from pathlib import Path

import pytest

from src import sandbox_runner

REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_PATH = REPO_ROOT / "initv4.lua"
JSON_PATH = REPO_ROOT / "Obfuscated.json"
SCRIPT_KEY = "dummy-key"


@pytest.fixture(autouse=True)
def reset_log():
    sandbox_runner.LOG = None
    yield
    sandbox_runner.LOG = None


def test_runner_prefers_python(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    def fake_python(path, init_path, json_path, key, output_dir, timeout):  # noqa: D401
        assert path == Path("src/sandbox.py")
        assert init_path == INIT_PATH
        assert json_path == JSON_PATH
        assert key == SCRIPT_KEY
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "unpacked_dump.json").write_text("{}", encoding="utf-8")
        return True, "ok", ""

    monkeypatch.setattr(sandbox_runner, "discover_sandboxes", lambda _: [("python", Path("src/sandbox.py"))])
    monkeypatch.setattr(sandbox_runner, "try_python_sandbox", fake_python)

    code = sandbox_runner.main(
        [
            "--init",
            str(INIT_PATH),
            "--json",
            str(JSON_PATH),
            "--key",
            SCRIPT_KEY,
            "--out",
            str(out_dir),
        ]
    )
    assert code == 0
    assert (out_dir / "unpacked_dump.json").exists()


def test_runner_falls_back_to_luajit(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    def fake_python(*_):
        return False, "no-lupa", "missing"

    def fake_lua(path, init_path, json_path, key, output_dir, timeout):
        assert path == Path("tools/devirtualize_v2.lua")
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "unpacked_dump.json").write_text("{}", encoding="utf-8")
        return True, "ok", ""

    monkeypatch.setattr(
        sandbox_runner,
        "discover_sandboxes",
        lambda _: [("python", Path("src/sandbox.py")), ("lua", Path("tools/devirtualize_v2.lua"))],
    )
    monkeypatch.setattr(sandbox_runner, "try_python_sandbox", fake_python)
    monkeypatch.setattr(sandbox_runner, "try_lua_wrapper", fake_lua)

    code = sandbox_runner.main(
        [
            "--init",
            str(INIT_PATH),
            "--json",
            str(JSON_PATH),
            "--key",
            SCRIPT_KEY,
            "--out",
            str(out_dir),
        ]
    )
    assert code == 0
    assert (out_dir / "unpacked_dump.json").exists()


def test_runner_reports_missing_deps(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    def fake_python(*_):
        return False, "no-lupa", "missing"

    def fake_lua(*_):
        return False, "no-luajit", "missing"

    monkeypatch.setattr(
        sandbox_runner,
        "discover_sandboxes",
        lambda _: [
            ("python", Path("src/sandbox.py")),
            ("lua", Path("tools/devirtualize_v2.lua")),
        ],
    )
    monkeypatch.setattr(sandbox_runner, "try_python_sandbox", fake_python)
    monkeypatch.setattr(sandbox_runner, "try_lua_wrapper", fake_lua)

    code = sandbox_runner.main(
        [
            "--init",
            str(INIT_PATH),
            "--json",
            str(JSON_PATH),
            "--key",
            SCRIPT_KEY,
            "--out",
            str(out_dir),
        ]
    )
    assert code == 3
    failure_report = out_dir / "failure_report.txt"
    assert failure_report.exists()
    text = failure_report.read_text(encoding="utf-8")
    assert "Missing dependencies" in text
    assert "lupa" in text
    assert "LuaJIT" in text
