import importlib
import logging
import sys
import types
from typing import Mapping

stub_utils = types.ModuleType("utils")
stub_utils.create_output_path = lambda path: path
stub_utils.setup_logging = lambda level: None
stub_utils.validate_file = lambda _: True
sys.modules.setdefault("utils", stub_utils)

stub_deobfuscator = types.ModuleType("deobfuscator")


class _DummyLuaDeobfuscator:
    def __init__(self, *_: object, **__: object) -> None:  # pragma: no cover - stub
        pass


stub_deobfuscator.LuaDeobfuscator = _DummyLuaDeobfuscator
sys.modules.setdefault("deobfuscator", stub_deobfuscator)

run = importlib.import_module("run")

from pattern_analyzer import Constant, SerializedChunk, SerializedChunkDescriptor, SerializedPrototype


def _sample_chunk() -> SerializedChunk:
    descriptor = SerializedChunkDescriptor(
        buffer_name="payload",
        initial_offset=0,
        helper_functions={},
    )
    child = SerializedPrototype(
        constants=[Constant(kind="number", value=42)],
        instructions=[],
        prototypes=[],
    )
    root = SerializedPrototype(
        constants=[
            Constant(kind="string", value="hello"),
            Constant(kind="string", value="x" * 80),
        ],
        instructions=[],
        prototypes=[child],
    )
    return SerializedChunk(descriptor=descriptor, prototypes=[root])


def _analysis_with_chunk(chunk: SerializedChunk) -> Mapping[str, object]:
    return {
        "version": {"name": "luraph_v14_3"},
        "bootstrap": {"serialized_chunk_model": chunk},
    }


def test_dump_v14_3_constants_prints_table(capsys) -> None:
    chunk = _sample_chunk()
    analysis = _analysis_with_chunk(chunk)

    dumped = run.dump_v14_3_constants(analysis)
    assert dumped is True

    output = capsys.readouterr().out
    assert "V14.3 CONSTANT TABLE" in output
    assert "Prototype 0" in output
    assert "[00] string" in output
    assert "..." in output  # truncated long string preview


def test_dump_v14_3_constants_skips_non_v14_3(capsys) -> None:
    analysis = {"version": {"name": "luraph_v14_4"}}
    dumped = run.dump_v14_3_constants(analysis)
    assert dumped is False
    output = capsys.readouterr().out
    assert output.strip() == ""


def test_dump_v14_3_constants_warns_when_chunk_missing(caplog) -> None:
    caplog.set_level(logging.WARNING)
    analysis = {"version": {"major": 14, "minor": 3}}
    dumped = run.dump_v14_3_constants(analysis, logger=logging.getLogger("test"))
    assert dumped is False
    assert "serialized chunk metadata" in caplog.text
