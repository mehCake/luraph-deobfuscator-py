import json
from pathlib import Path

import pytest

from src import detect_protections


BOOTSTRAP_SAMPLE = """
-- Luraph v14.5, settings=performance
-- @lph_novirtualize
local settings = {
    virtualize_all = false,
    exclude_list = {"foo", "bar"},
    max_jit_kernels = 6,
}

function bootstrap()
    LPH_JIT_MAX(12)
    local chunk = LPH_NO_VIRTUALIZE("noop")
    return chunk
end
"""


def test_detects_macros_and_settings(tmp_path: Path) -> None:
    report = detect_protections.scan_lua(BOOTSTRAP_SAMPLE, filename="initv5.lua")
    assert "LPH_NO_VIRTUALIZE" in report["macros"]
    assert "LPH_JIT_MAX" in report["macros"]
    settings_known = report["settings"]["known"]
    assert settings_known["virtualize_all"] is False
    assert settings_known["max_jit_kernels"] == 6
    assert settings_known["exclude_list"] == ["foo", "bar"]
    metadata = report["metadata"]
    assert metadata["luraph_version"] == "14.5"
    assert report["limitations"] == []


def test_scan_files_merges_macros(tmp_path: Path) -> None:
    init_path = tmp_path / "initv4.lua"
    init_path.write_text(BOOTSTRAP_SAMPLE, encoding="utf-8")
    other_path = tmp_path / "other.lua"
    other_path.write_text("-- lph_no_virt\nLPH_SKIP()", encoding="utf-8")

    report = detect_protections.scan_files([init_path, other_path])
    assert sorted(report["macros"]) == ["LPH_JIT_MAX", "LPH_NO_VIRTUALIZE", "LPH_SKIP"]
    assert report["settings"]["known"]["virtualize_all"] is False
    assert "pipeline_mode" not in report
    assert report["metadata"]["luraph_version"] == "14.5"
    assert "signature_lookup" not in report["metadata"]


@pytest.mark.parametrize(
    "sample,expected",
    [
        ("-- lph_no_virt", ["LPH_NO_VIRTUALIZE"]),
        ("LPH_SKIP()", ["LPH_SKIP"]),
        ("-- @lph_jit", ["LPH_JIT"]),
    ],
)
def test_macro_comment_normalisation(sample: str, expected: list[str]) -> None:
    report = detect_protections.scan_lua(sample)
    assert report["macros"] == expected
