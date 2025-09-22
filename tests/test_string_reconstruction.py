from __future__ import annotations

import base64
from pathlib import Path

from src.pipeline import Context
from src.passes.string_reconstruction import run as string_reconstruction_run


def _make_context(tmp_path: Path, code: str) -> Context:
    target = tmp_path / "sample.lua"
    target.write_text(code, encoding="utf-8")
    ctx = Context(input_path=target, raw_input=code, stage_output=code)
    ctx.working_text = code
    return ctx


def test_string_reconstruction_decodes_numeric_chunks(tmp_path: Path) -> None:
    snippet = 'return "\\72\\101\\108\\108\\111" .. "\\x20\\x57\\x6F\\x72\\x6C\\x64"'
    ctx = _make_context(tmp_path, snippet)

    metadata = string_reconstruction_run(ctx)

    assert ctx.stage_output == 'return "Hello World"'
    assert metadata["concatenations_collapsed"] >= 1
    assert metadata["decoded_literals"] >= 1


def test_string_reconstruction_promotes_code_literals(tmp_path: Path) -> None:
    payload = base64.b64encode(
        "function greet()\n    print('hi')\nend\n".encode("utf-8")
    ).decode("ascii")
    snippet = f"local chunk = \"{payload}\""
    ctx = _make_context(tmp_path, snippet)

    metadata = string_reconstruction_run(ctx)

    assert "function greet" in ctx.stage_output
    assert "[[" in ctx.stage_output and "]]" in ctx.stage_output
    assert metadata["entropy_literals"] >= 1
    assert metadata["promoted_literals"] >= 1
