"""Tests for static protection detection heuristics."""

from __future__ import annotations

from pathlib import Path

import pytest

from src import detect_protections


@pytest.mark.parametrize(
    "snippet,expected",
    [
        ("for i = 1, #buf do buf[i] = buf[i] ^ key end", "xor"),
        ("local data = zlib.inflate(blob)", "compression"),
        ("local chunk = load(string.char(65,66))", "dynamic_generation"),
        ("math.randomseed(os.time())", "randomisation"),
        ("for i = 1, #segments do", "fragmentation"),
        ("handlers[42] = function() return noop end", "junk_ops"),
        ("debug.getinfo(1)", "anti_trace"),
        (
            "local osname = os.getenv('OS')\nif not osname then error('tamper detected') end",
            "anti_tamper",
        ),
    ],
)
def test_scan_lua_detects_categories(snippet: str, expected: str) -> None:
    report = detect_protections.scan_lua(snippet, filename="test.lua")
    assert report["protection_detected"] is True
    assert expected in report["types"]


def test_scan_files_multiple(tmp_path: Path) -> None:
    file_a = tmp_path / "a.lua"
    file_a.write_text("bit32.bxor(a, b)", encoding="utf-8")
    file_b = tmp_path / "b.lua"
    file_b.write_text("debug.sethook(fn)", encoding="utf-8")

    report = detect_protections.scan_files([file_a, file_b])
    assert report["protection_detected"] is True
    assert set(report["types"]) >= {"xor", "anti_trace"}
    assert any(item["filename"].endswith("a.lua") for item in report["evidence"])


def test_scan_lua_reports_bypass_guidance() -> None:
    snippet = """
    local key = os.getenv('SESSION_KEY')
    if not key then error('tamper') end
    """
    report = detect_protections.scan_lua(snippet, filename="guard.lua")
    assert "anti_tamper" in report["types"]
    hints = report.get("bypass_instructions")
    assert hints, "expected bypass instructions"
    assert any("os.getenv" in hint or "environment" in hint for hint in hints)


def test_scan_files_merges_bypass_guidance(tmp_path: Path) -> None:
    env_file = tmp_path / "env.lua"
    env_file.write_text("if not TOKEN then error('tamper') end", encoding="utf-8")
    proc_file = tmp_path / "proc.lua"
    proc_file.write_text("local handle = io.popen('whoami')", encoding="utf-8")

    report = detect_protections.scan_files([env_file, proc_file])
    hints = report.get("bypass_instructions")
    assert hints and len(hints) >= 2
