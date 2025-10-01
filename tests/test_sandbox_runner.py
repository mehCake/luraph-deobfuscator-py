from __future__ import annotations

import json
from pathlib import Path

import pytest

from src import sandbox_runner

REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_PATH = REPO_ROOT / "initv4.lua"
JSON_PATH = REPO_ROOT / "Obfuscated.json"
SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


def _dummy_unpacked(opcode: int = 1) -> dict[str, object]:
    return {
        "4": [[None, None, opcode]],
        "5": ["dummy"],
    }


@pytest.fixture(autouse=True)
def reset_log(tmp_path):
    sandbox_runner.LOG_PATH = tmp_path / "log.txt"
    yield
    sandbox_runner.LOG_PATH = None


def test_runner_prefers_python(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    def fake_python(init_path, json_path, key):
        assert Path(init_path) == INIT_PATH
        assert Path(json_path) == JSON_PATH
        assert key == SCRIPT_KEY
        return True, sandbox_runner._normalise(_dummy_unpacked()), ""

    monkeypatch.setattr(sandbox_runner, "_run_python_sandbox", fake_python)
    monkeypatch.setattr(sandbox_runner, "_run_lua_wrapper", lambda *args, **kwargs: (False, None, "no"))

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
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["status"] == "ok"
    assert summary["unpacked_dump_exists"] is True


def test_runner_requires_fixture_flag(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    monkeypatch.setattr(sandbox_runner, "_run_python_sandbox", lambda *args, **kwargs: (False, None, "no-lupa"))
    monkeypatch.setattr(sandbox_runner, "_run_lua_wrapper", lambda *args, **kwargs: (False, None, "no luajit"))

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
    assert code != 0
    failure = (out_dir / "failure_report.txt").read_text(encoding="utf-8")
    assert "sandbox capture failed" in failure


def test_runner_uses_fixture_when_allowed(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"
    sandbox_runner._ensure_dirs(out_dir)
    (out_dir / "unpacked_dump.json").write_text(json.dumps(_dummy_unpacked()), encoding="utf-8")

    monkeypatch.setattr(sandbox_runner, "_run_python_sandbox", lambda *args, **kwargs: (False, None, "no-lupa"))
    monkeypatch.setattr(sandbox_runner, "_run_lua_wrapper", lambda *args, **kwargs: (False, None, "no luajit"))

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
            "--use-fixtures",
        ]
    )
    assert code == 0
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["fallback_fixture"] is True


def test_runner_detection_writes_report(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"

    monkeypatch.setattr(
        sandbox_runner,
        "_run_python_sandbox",
        lambda *args, **kwargs: (True, sandbox_runner._normalise(_dummy_unpacked()), ""),
    )

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
            "--detect-protections",
        ]
    )
    assert code == 0
    report_path = out_dir / "protection_report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert "protection_detected" in report


def test_runner_runtime_capture_frida_file(monkeypatch, tmp_path):
    out_dir = tmp_path / "out"
    capture_src = tmp_path / "trace.json"
    capture_src.write_text(json.dumps(_dummy_unpacked(opcode=5)), encoding="utf-8")

    def should_not_run(*args, **kwargs):
        raise AssertionError("sandbox should not run when capture succeeds")

    monkeypatch.setattr(sandbox_runner, "_run_python_sandbox", should_not_run)
    monkeypatch.setattr(sandbox_runner, "_run_lua_wrapper", should_not_run)

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
            "--capture-runtime",
            "frida",
            "--capture-target",
            f"file://{capture_src.as_posix()}",
        ]
    )
    assert code == 0
    summary = json.loads((out_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["runtime_capture_method"] == "frida"
    unpacked = json.loads((out_dir / "unpacked_dump.json").read_text(encoding="utf-8"))
    assert unpacked["4"][0][2] == 5

