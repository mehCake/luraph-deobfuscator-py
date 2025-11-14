import json
from pathlib import Path

from opcode_lifter import (
    OpcodeLifter,
    build_bootstrap_ir_v14_3,
    find_vm_loader_v14_3,
)
from src.utils_pkg import ast as lua_ast


def test_numeric_opcode_mapping_produces_canonical_instructions():
    payload = {
        "constants": ["print", "hello"],
        "bytecode": [
            {"op": "0x01", "a": 0, "const": 1},
            {"op": "MOVE", "a": 1, "b": 0},
            {"op": "0x24", "a": 0, "b": 2, "c": 1},
            {"op": "0x27", "a": 1, "b": 1},
        ],
    }

    lifter = OpcodeLifter()
    program = lifter.lift_program(payload, version="v14.0.2")

    assert len(program.instructions) == 4
    loadk = program.instructions[0]
    assert loadk.opcode == "LOADK"
    assert loadk.aux["const_b"] == "hello"
    assert loadk.pc == 0

    call = program.instructions[2]
    assert call.opcode == "CALL"
    assert call.aux["immediate_b"] == 2
    assert call.aux["immediate_c"] == 1

    ret = program.instructions[3]
    assert ret.opcode == "RETURN"
    assert ret.aux["immediate_b"] == 1

    metadata = program.metadata
    assert metadata["opcode_table"]["trusted"] is False
    trace = metadata.get("ir_trace")
    assert isinstance(trace, list) and trace[0]["pc"] == 0
    assert trace[2]["op"] == "CALL"


def _zero_arg_call(name: str) -> lua_ast.Call:
    return lua_ast.Call(lua_ast.Name(name), [])


def _table_write(table: str, index: str, value: lua_ast.Expr, *, local: bool = False) -> lua_ast.Assignment:
    return lua_ast.Assignment(
        targets=[lua_ast.TableAccess(lua_ast.Name(table), lua_ast.Name(index))],
        values=[value],
        is_local=local,
    )


def test_find_vm_loader_v14_3_builds_model() -> None:
    loop = lua_ast.NumericFor(
        var="i",
        start=lua_ast.Literal(1),
        stop=_zero_arg_call("o"),
        step=lua_ast.Literal(1),
        body=[
            lua_ast.Assignment(
                targets=[lua_ast.Name("len")],
                values=[_zero_arg_call("a3")],
                is_local=True,
            ),
            _table_write("protos", "i", _zero_arg_call("M")),
            lua_ast.CallStmt(_zero_arg_call("t3")),
            _table_write(
                "code",
                "i",
                lua_ast.Call(lua_ast.Name("r"), [lua_ast.Name("blob"), lua_ast.Name("i")]),
            ),
        ],
    )

    chunk = lua_ast.Chunk(
        body=[
            loop,
            lua_ast.Assignment(
                targets=[lua_ast.Name("proto_bytes")],
                values=[lua_ast.Call(lua_ast.Name("r"), [lua_ast.Name("blob"), lua_ast.Literal(0)])],
                is_local=True,
            ),
        ]
    )

    loader = find_vm_loader_v14_3(chunk)
    assert loader is not None
    assert loader.helpers["prototype_counter"] == "o"
    assert loader.helpers["table_reader"] == "M"
    assert loader.helpers["instruction_slice"] == "r"
    assert loader.helper_usage["o"] >= 1
    assert any(call.helper == "M" for call in loader.loops[0].body_calls)
    assert any(call.helper == "r" for call in loader.loops[0].body_calls)
    assert any(call.helper == "t3" for call in loader.loops[0].body_calls)
    payload = loader.to_dict()
    assert json.loads(json.dumps(payload))["helpers"]["prototype_counter"] == "o"


def test_find_vm_loader_v14_3_rejects_when_helpers_missing() -> None:
    chunk = lua_ast.Chunk(
        body=[
            lua_ast.NumericFor(
                var="i",
                start=lua_ast.Literal(1),
                stop=lua_ast.Literal(4),
                step=lua_ast.Literal(1),
                body=[
                    lua_ast.Assignment(
                        targets=[lua_ast.Name("value")],
                        values=[lua_ast.Literal(0)],
                        is_local=True,
                    )
                ],
            )
        ]
    )

    assert find_vm_loader_v14_3(chunk) is None


def test_build_bootstrap_ir_v14_3_collects_metadata() -> None:
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    chunk = lua_ast.Chunk(body=[], metadata={"source": source})

    bootstrap = build_bootstrap_ir_v14_3(chunk)
    assert bootstrap is not None
    assert bootstrap.serialized_chunk is not None
    assert bootstrap.c3_primitives is not None
    assert bootstrap.c3_primitives.get("count", 0) > 0
    assert bootstrap.string_decoder is not None
    assert bootstrap.string_decoder.token_length == 5
    assert bootstrap.cache_slots
    assert any(slot.semantic_role == "double mantissa mask" for slot in bootstrap.cache_slots)

    payload = bootstrap.to_dict()
    assert json.loads(json.dumps(payload))["string_decoder"]["token_length"] == 5
