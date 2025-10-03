from pathlib import Path

from src import detect_protections


def write_init(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "initv4.lua"
    path.write_text(content, encoding="utf-8")
    return path


def test_v144_macro_and_settings_detection(tmp_path: Path) -> None:
    sample = """
    -- Luraph v14.4.2, settings profile
    local settings = {
      virtualize_all = false,
      max_jit_kernels = 4,
      exclude_list = {"decode", "utility"},
    }
    -- lph_no_virtualize helper
    LPH_NO_VIRTUALIZE(function() return 123 end)
    -- @lph_jit
    local result = LPH_JIT(function()
      return "ok"
    end)
    -- lph-encfunc (comment form)
    -- lph-encfunc
    return result
    """
    path = write_init(tmp_path, sample)
    report = detect_protections.scan_files([path])
    assert report["path"] == path.as_posix()
    assert "LPH_NO_VIRTUALIZE" in report["macros"]
    assert "LPH_JIT" in report["macros"]
    assert "LPH_ENCFUNC" in report["macros"]
    known = report["settings"]["known"]
    assert known["virtualize_all"] is False
    assert known["max_jit_kernels"] == 4
    assert "decode" in known["exclude_list"]
    assert report["metadata"]["luraph_version"] == "14.4.2"
    assert report["recommendation"] == "luajit"
    assert any("LPH_ENCFUNC" in item for item in report["limitations"])
