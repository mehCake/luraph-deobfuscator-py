from pathlib import Path

import pytest

from src.tools.preview_deobf import generate_preview, preview_files


def test_preview_side_by_side(tmp_path: Path) -> None:
    original = tmp_path / "original.lua"
    deobf = tmp_path / "deobf.lua"
    original.write_text("line_a\nline_b\n", encoding="utf-8")
    deobf.write_text("line_a\nline_c\n", encoding="utf-8")

    preview = preview_files(original, deobf, max_lines=10, column_width=20, colour=False)

    assert "line_b" in preview
    assert "line_c" in preview
    assert "│" in preview


def test_generate_preview_colours_highlight_differences() -> None:
    table = generate_preview(["alpha"], ["beta"], column_width=12, colour=True)
    assert "\x1b[31m" in table
    assert "\x1b[32m" in table


def test_preview_truncation_notes(tmp_path: Path) -> None:
    original = tmp_path / "orig.lua"
    deobf = tmp_path / "new.lua"
    original.write_text("\n".join(f"orig_{i}" for i in range(6)), encoding="utf-8")
    deobf.write_text("\n".join(f"new_{i}" for i in range(6)), encoding="utf-8")

    preview = preview_files(original, deobf, max_lines=3, colour=False)

    assert "truncated original" in preview
    assert "truncated deobfuscated" in preview
