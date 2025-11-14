from __future__ import annotations

import json

from src.vm.compare_handlers import (
    analyse_handler_source,
    compare_handler_bytes,
    emit_handler_suggestions,
    extract_function_bodies,
)


def _top_mnemonic(blob: bytes) -> str:
    comparisons = compare_handler_bytes(blob)
    assert comparisons, "expected at least one comparison"
    return comparisons[0].mnemonic


def test_compare_handler_bytes_identifies_loadk() -> None:
    blob = bytes(range(12))
    assert _top_mnemonic(blob) == "LOADK"


def test_compare_handler_bytes_identifies_call() -> None:
    blob = bytes((i * 3) % 256 for i in range(80))
    assert _top_mnemonic(blob) == "CALL"


def test_compare_handler_bytes_identifies_return() -> None:
    blob = bytes([10, 11, 10, 11, 12, 13, 12, 13, 10, 11])
    assert _top_mnemonic(blob) == "RETURN"


def test_compare_handler_bytes_identifies_jump() -> None:
    blob = bytes([1, 2, 1, 2, 1, 2, 1, 3])
    assert _top_mnemonic(blob) == "JMP"


def test_compare_handler_bytes_identifies_eq() -> None:
    blob = bytes(range(56))
    assert _top_mnemonic(blob) == "EQ"


def test_analyse_handler_source_loadk_text() -> None:
    body = "stack[ra] = constants[rb]\nreturn stack[ra]"
    suggestion = analyse_handler_source("handler_loadk", body, version_hint="14.4.2")
    assert suggestion.resolvable
    assert suggestion.candidates
    assert suggestion.candidates[0].mnemonic == "LOADK"
    assert suggestion.candidates[0].confidence >= 0.5


def test_analyse_handler_source_jmp_text() -> None:
    body = "pc = pc + offsets[ra]\nreturn"
    suggestion = analyse_handler_source("handler_jump", body, version_hint="14.4.2")
    assert suggestion.resolvable
    assert suggestion.candidates[0].mnemonic == "JMP"


def test_extract_function_bodies_parses_local_functions() -> None:
    source = """
    local function handler_loadk(stack, constants)
        stack[ra] = constants[rb]
    end

    handler_jump = function(pc, offsets)
        pc = pc + offsets[ra]
    end
    """
    bodies = extract_function_bodies(source)
    assert "handler_loadk" in bodies
    assert "handler_jump" in bodies
    assert "constants" in bodies["handler_loadk"]


def test_emit_handler_suggestions_writes_json(tmp_path) -> None:
    handlers = {
        "handler_eq": "if stack[ra] == stack[rb] then pc = pc + 1 end",
    }
    out_dir = tmp_path / "out"
    path = emit_handler_suggestions(handlers, output_dir=out_dir, version_hint="14.4.2")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["handlers"]
    first = data["handlers"][0]
    assert first["resolvable"]
    assert first["candidates"]
