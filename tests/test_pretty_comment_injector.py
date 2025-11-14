import json

import pytest

from src.pretty.comment_injector import (
    CommentHint,
    inject_comments,
    load_hints,
    write_with_comments,
)


def test_inject_comments_inserts_after_matching_offset(tmp_path):
    source = """-- header\n    instruction -- offset 0x0010\n-- footer\n"""
    hint = CommentHint(
        offset=0x0010,
        raw_opcode=0xAB,
        suggested_mnemonic="LOADK",
        confidence=0.75,
        notes=("possible constant loader",),
        artifacts=("out/intermediate/op_0010.bin",),
    )

    result = inject_comments(source, [hint])
    assert "AMBIGUOUS_OPCODE" in result
    assert "SUGGESTED_MNEMONIC: LOADK (confidence 0.75)" in result
    assert "SEE: out/intermediate/op_0010.bin" in result

    lines = result.splitlines()
    index = lines.index("    instruction -- offset 0x0010")
    assert lines[index + 1].strip().startswith("-- [offset 0x0010]")


def test_unmatched_hint_appends_warning(caplog):
    caplog.set_level("WARNING")
    source = "line without offsets\n"
    hint = CommentHint(offset=0x9999)

    result = inject_comments(source, [hint])
    assert "unmatched analysis hints" in result
    assert any("did not match" in record.getMessage() for record in caplog.records)


def test_load_hints_and_write_with_comments(tmp_path):
    hints_path = tmp_path / "hints.json"
    hints_path.write_text(
        json.dumps(
            {
                "hints": [
                    {
                        "offset": 0x20,
                        "raw_opcode": 0x10,
                        "suggested_mnemonic": "CALL",
                        "confidence": 0.5,
                        "notes": ["calls helper"],
                        "artifacts": ["out/intermediate/stage-1.bin"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    source_path = tmp_path / "input.lua"
    source_path.write_text("-- offset 0x0020\n", encoding="utf-8")

    output_path = tmp_path / "output.lua"
    rendered = write_with_comments(source_path, hints_path, output_path=output_path)

    assert output_path.exists()
    assert "CALL" in rendered
    assert "stage-1.bin" in rendered
    assert "SUGGESTED_MNEMONIC" in output_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("payload", [[], {"hints": []}])
def test_load_hints_accepts_list_or_mapping(tmp_path, payload):
    path = tmp_path / "hints.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    hints = load_hints(path)
    assert hints == []
