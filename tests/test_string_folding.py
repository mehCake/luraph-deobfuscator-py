from __future__ import annotations

from pathlib import Path

from src.pipeline import Context
from src.passes.string_folding import run as string_folding_run


def _make_context(tmp_path: Path, code: str) -> Context:
    target = tmp_path / "sample.lua"
    target.write_text(code, encoding="utf-8")
    ctx = Context(input_path=target, raw_input=code, stage_output=code)
    ctx.working_text = code
    return ctx


def test_string_folding_collapses_simple_concat(tmp_path: Path) -> None:
    snippet = 'return "hello " .. "world"'
    ctx = _make_context(tmp_path, snippet)

    metadata = string_folding_run(ctx)

    assert ctx.stage_output == 'return "hello world"'
    assert metadata["collapsed_concats"] >= 1
    assert metadata["decoded_segments"] == 0


def test_string_folding_collapses_long_chain(tmp_path: Path) -> None:
    snippet = 'return "he" .. "ll" .. "o" .. " " .. "world"'
    ctx = _make_context(tmp_path, snippet)

    metadata = string_folding_run(ctx)

    assert ctx.stage_output == 'return "hello world"'
    assert metadata["collapsed_concats"] >= 4


def test_string_folding_decodes_lph_chunks(tmp_path: Path) -> None:
    snippet = 'return "LPH!48 65" .. "LPH!6C 6C" .. "LPH!6F"'
    ctx = _make_context(tmp_path, snippet)

    metadata = string_folding_run(ctx)

    assert ctx.stage_output == 'return "Hello"'
    assert metadata["collapsed_concats"] >= 2
    assert metadata["decoded_segments"] >= 3
