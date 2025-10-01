import json
from pathlib import Path

import pytest

from src import detect_protections


def write_temp(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_detects_multiple_categories(tmp_path: Path) -> None:
    sample = """
    local chunks = {}
    for i = 1, #segments do
        chunks[#chunks + 1] = segments[i]
    end
    local out = {}
    for i = 1, #chunks do
        out[i] = bit32.bxor(chunks[i], script_key)
    end
    local inflated = LPH_UnpackData(out)
    """
    path = write_temp(tmp_path, "sample.lua", sample)
    report = detect_protections.scan_files([path])
    assert report["protection_detected"] is True
    assert set(report["types"]) >= {"xor", "fragmentation", "compression", "vm_bootstrap", "randomisation"}


@pytest.mark.parametrize(
    "snippet, expected",
    [
        (
            "local handlers = {}\nhandlers[1] = function()\n  return\nend",
            "junk_ops",
        ),
        ("debug.sethook(function() end)", "anti_trace"),
        ("local b = string.char(65,66,67)", "dynamic_generation"),
    ],
)
def test_individual_patterns(snippet: str, expected: str, tmp_path: Path) -> None:
    path = write_temp(tmp_path, "single.lua", snippet)
    report = detect_protections.scan_files([path])
    assert expected in report["types"]


def test_cli_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    sample = "local x = L1({1,2,3}, 7)"
    path = write_temp(tmp_path, "initv4.lua", sample)
    monkeypatch.chdir(tmp_path)
    exit_code = detect_protections.main([str(path)])
    assert exit_code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "vm_bootstrap" in data["types"]
