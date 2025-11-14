from __future__ import annotations

import json
from pathlib import Path

from src.tools.parser_tracer import (
    analyse_transform_snippet,
    match_handler_patterns,
    main as parser_tracer_main,
)


SAMPLE_DISPATCH = """
local function dispatch(opcode)
    if opcode == 0 then
        return handle_add(r1, r2)
    elseif opcode == 0x10 then
        handler_sub()
    elseif other == 3 then
        return ignored()
    elseif opcode == 0x11 then
        if opcode == 99 then
            nested()
        end
        return handlers.mul(r3)
    end
end
"""

SAMPLE_WITH_HANDLERS = """
local stack, constants = {}, {1, 2, 3}

function handle_loadk(reg, idx)
    stack[reg] = constants[idx]
end

function handle_call(base)
    stack[base](stack[base + 1])
end

function handle_return(base)
    return stack[base], stack[base + 1]
end

function handle_jump(pc, offset)
    pc = pc + offset
end

function handle_eq(a, b, target)
    if stack[a] == stack[b] then
        return target
    end
end

local function dispatch(opcode)
    if opcode == 0 then
        return handle_loadk(1, 2)
    elseif opcode == 1 then
        return handle_call(1)
    elseif opcode == 2 then
        return handle_return(1)
    elseif opcode == 3 then
        return handle_jump(5, 2)
    elseif opcode == 4 then
        return handle_eq(1, 2, 10)
    end
end
"""

SAMPLE_TRANSFORM = """
local salt = 3

function transform_byte(byte, key)
    local rotated = bit32.rrotate(byte, salt)
    local masked = bit32.band(rotated, 0xff)
    return bit32.bxor(masked, key)
end

local function trivial()
    return loadstring("print('hi')")
end
"""


def _write_candidates(path: Path, snippet: str) -> None:
    payload = [
        {
            "type": "loadstring",
            "start_offset": 0,
            "end_offset": len(snippet),
            "confidence": 0.9,
            "snippet": snippet,
        }
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_match_handler_patterns_prefers_consistent_variable() -> None:
    matches = match_handler_patterns(SAMPLE_DISPATCH)
    assert [match.opcode for match in matches] == [0, 0x10, 0x11]
    assert [match.handler for match in matches] == ["handle_add", "handler_sub", "handlers.mul"]
    assert all(not match.mnemonics for match in matches)
    assert all(match.body is None or isinstance(match.body, str) for match in matches)


def test_match_handler_patterns_allows_explicit_variable() -> None:
    snippet = "if op == 5 then return do_op() elseif other == 9 then skip() end"
    matches = match_handler_patterns(snippet, opcode_name="op")
    assert len(matches) == 1
    assert matches[0].opcode == 5
    assert matches[0].handler == "do_op"
    assert matches[0].mnemonics == ()


def test_match_handler_patterns_infers_handler_mnemonics() -> None:
    matches = match_handler_patterns(SAMPLE_WITH_HANDLERS)
    mapping = {match.handler: match.mnemonics for match in matches}
    assert "handle_loadk" in mapping and "LOADK" in mapping["handle_loadk"]
    assert "handle_call" in mapping and "CALL" in mapping["handle_call"]
    assert "handle_return" in mapping and "RETURN" in mapping["handle_return"]
    assert "handle_jump" in mapping and "JMP" in mapping["handle_jump"]
    assert "handle_eq" in mapping and "EQ" in mapping["handle_eq"]
    assert any(
        match.body and "stack" in match.body for match in matches if match.handler.startswith("handle_")
    )


def test_analyse_transform_snippet_detects_operations() -> None:
    analyses = analyse_transform_snippet(SAMPLE_TRANSFORM)
    assert analyses, "expected at least one function analysis"
    transform = next(item for item in analyses if item.name == "transform_byte")
    assert transform.resolvable is True
    assert [op.type for op in transform.operations] == ["rotate", "mask", "xor"]
    xor_args = next(op.args for op in transform.operations if op.type == "xor")
    assert xor_args["rhs"] == "key"


def test_analyse_transform_snippet_marks_runtime_constructs() -> None:
    analyses = analyse_transform_snippet(SAMPLE_TRANSFORM)
    runtime = next(item for item in analyses if item.name == "trivial")
    assert runtime.resolvable is False
    assert any("loadstring" in issue for issue in runtime.issues)


def test_parser_tracer_cli_writes_trace(tmp_path: Path) -> None:
    candidates_path = tmp_path / "bootstrap_candidates.json"
    _write_candidates(candidates_path, SAMPLE_TRANSFORM)
    output_dir = tmp_path / "trace"

    exit_code = parser_tracer_main([str(candidates_path), "--output-dir", str(output_dir)])

    assert exit_code == 0
    files = list(output_dir.glob("*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text(encoding="utf-8"))
    assert data["functions"]
    transform = next(item for item in data["functions"] if item["name"] == "transform_byte")
    assert any(op["type"] == "xor" for op in transform["operations"])
