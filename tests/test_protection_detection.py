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


def test_real_life_profile_for_v14_3_vm() -> None:
    sample = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    report = detect_protections.scan_lua(sample, filename="Obfuscated4.lua")
    profile = report.get("profile")
    assert profile is not None
    assert profile["vm_mode"] == "full"
    assert profile["string_encryption"] is True
    assert profile["real_life_score"] == pytest.approx(15.17, rel=0.05)
    assert profile["double_packed_constants"] is True


def test_scan_files_carries_profile() -> None:
    report = detect_protections.scan_files([Path("Obfuscated4.lua")])
    profile = report.get("profile")
    assert profile is not None
    assert profile["vm_mode"] == "full"
    assert profile["double_packed_constants"] is True
