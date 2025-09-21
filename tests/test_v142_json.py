import json
from pathlib import Path

from version_detector import VersionDetector

from src.deobfuscator import LuaDeobfuscator
from src.pipeline import Context, PIPELINE
from src.passes.preprocess import flatten_json_to_lua
from src.passes.vm_lift import VMLifter
from src.versions import VersionHandler, decode_constant_pool, get_handler

FIXTURE_PATH = Path("tests/fixtures/v142_init.json")


class _NoLoaderLuaDeobfuscator(LuaDeobfuscator):
    """Test helper that skips executing the VM during payload decoding."""

    def decode_payload(self, text, *, version, features=None, script_key=None, bootstrapper=None):  # type: ignore[override]
        base = features if features is not None else version.features
        filtered = frozenset(base or ())
        if "loader" in filtered:
            filtered = frozenset(flag for flag in filtered if flag != "loader")
        return super().decode_payload(
            text,
            version=version,
            features=filtered,
            script_key=script_key,
            bootstrapper=bootstrapper,
        )


def _fixture_text() -> str:
    return flatten_json_to_lua(FIXTURE_PATH)


def _get_handler() -> VersionHandler:
    handler = get_handler("luraph_v14_2_json")
    assert isinstance(handler, VersionHandler)
    return handler


def _locate_payload():
    text = _fixture_text()
    handler = _get_handler()
    payload = handler.locate_payload(text)
    assert payload is not None, "expected handler to locate JSON payload"
    return handler, payload, text


def _decoded_constants(handler: VersionHandler, payload) -> list[object]:
    data = payload.data
    if data is None:
        data = json.loads(payload.text)
    assert isinstance(data, dict)
    constants = data.get("constants")
    assert isinstance(constants, list) and constants, "expected constant table"
    decoder = handler.const_decoder()
    decoded = decode_constant_pool(decoder, constants) if decoder else list(constants)
    return decoded


def test_detect_json_variant() -> None:
    text = _fixture_text()
    detector = VersionDetector()
    detected = detector.detect(text)
    assert detected.name == "luraph_v14_2_json"

    deob = LuaDeobfuscator()
    assert deob.detect_version(text).name == "luraph_v14_2_json"


def test_payload_extraction() -> None:
    handler, payload, _ = _locate_payload()
    bytecode = handler.extract_bytecode(payload)
    assert isinstance(bytecode, bytes) and len(bytecode) > 0

    data = payload.data
    if data is None:
        data = json.loads(payload.text)
    assert isinstance(data, dict)
    constants = data.get("constants")
    assert isinstance(constants, list) and constants


def test_lift_no_unknowns() -> None:
    handler, payload, _ = _locate_payload()
    bytecode = handler.extract_bytecode(payload)
    decoded = _decoded_constants(handler, payload)
    module = VMLifter().lift(bytecode, handler.opcode_table(), decoded)

    assert module.instructions, "expected lifted instructions"
    assert all(inst.opcode != "Unknown" for inst in module.instructions)
    assert not module.warnings


def test_full_deob_produces_lua(tmp_path: Path) -> None:
    temp_source = tmp_path / "init.json"
    temp_source.write_text(FIXTURE_PATH.read_text(), encoding="utf-8")

    ctx = Context(input_path=temp_source, deobfuscator=_NoLoaderLuaDeobfuscator())
    PIPELINE.run_passes(ctx)

    assert ctx.detected_version is not None
    assert ctx.detected_version.name == "luraph_v14_2_json"

    output_path = temp_source.with_name(f"{temp_source.stem}_deob.lua")
    assert output_path.exists()
    rendered = output_path.read_text(encoding="utf-8")
    assert rendered.strip(), "expected rendered Lua output"

    lines = [line for line in rendered.splitlines() if line.strip() and not line.strip().startswith("--")]
    assert len(lines) >= 3, "expected multiple non-bootstrap statements"

    forbidden = ("BXOR", "BNOT", "dispatcher", "opcode_map", "vm_step", "loadstring(string.char")
    for marker in forbidden:
        assert marker not in rendered

    assert "hello from luraph json variant" in rendered


def test_strings_decoded() -> None:
    handler, payload, _ = _locate_payload()
    decoded = _decoded_constants(handler, payload)
    assert any(
        isinstance(entry, str) and "hello" in entry.lower() for entry in decoded
    ), "expected decoded plaintext strings"
