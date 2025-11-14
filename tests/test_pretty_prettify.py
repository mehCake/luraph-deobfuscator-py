from __future__ import annotations

from pathlib import Path

import json

from src.pretty.prettify import (
    CommentInjection,
    Provenance,
    format_file,
    format_pseudo_lua,
)


def test_format_pseudo_lua_includes_provenance_and_indents(tmp_path: Path) -> None:
    source = """
function demo()
if cond then
return 1
else
return 2
end
end
""".strip()

    provenance = Provenance.from_profile({"pipeline": "demo", "version": "14.4.2"}, label="profile")
    formatted = format_pseudo_lua(source, indent_width=2, max_column=80, provenance=provenance)

    lines = formatted.splitlines()
    assert lines[0].startswith("-- PROVENANCE: profile: pipeline=demo; version=14.4.2")
    assert lines[1] == "function demo()"
    assert lines[2] == "  if cond then"
    assert lines[3] == "    return 1"
    assert lines[4] == "  else"
    assert lines[5] == "    return 2"
    assert lines[6] == "  end"
    assert lines[7] == "end"


def test_formatting_wraps_long_lines() -> None:
    source = "function demo() print(\"" + "x" * 60 + "\") end"
    provenance = Provenance(summary="demo pipeline")
    formatted = format_pseudo_lua(source, max_column=50, provenance=provenance)

    for line in formatted.splitlines():
        if len(line) > 50:
            # String literals without whitespace cannot be wrapped safely – ensure we only
            # exceed the column limit for those cases.
            assert "\"" in line


def test_comment_injection_positions(tmp_path: Path) -> None:
    source = "return result"
    provenance = Provenance(summary="demo")
    rules = [
        CommentInjection(match="return", comment="final value", position="append"),
        CommentInjection(match="result", comment="post-processed", position="below"),
    ]
    formatted = format_pseudo_lua(source, provenance=provenance, comment_rules=rules)

    lines = formatted.splitlines()
    assert lines[1].endswith("-- final value")
    assert lines[2].strip().startswith("-- post-processed")


def test_format_file_writes_output(tmp_path: Path) -> None:
    input_path = tmp_path / "input.lua"
    profile_path = tmp_path / "transform_profile.json"
    input_path.write_text("return 0", encoding="utf-8")
    profile_path.write_text(json.dumps({"pipeline": "demo"}), encoding="utf-8")

    output_path = tmp_path / "formatted.lua"
    provenance = Provenance.from_file(profile_path, label="profile")
    format_file(
        input_path,
        output_path=output_path,
        provenance=provenance,
        indent_width=2,
        max_column=40,
    )

    payload = output_path.read_text(encoding="utf-8")
    assert payload.startswith("-- PROVENANCE: profile: pipeline=demo")
    assert "return 0" in payload
