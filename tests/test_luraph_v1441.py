import base64
import json
from pathlib import Path
from pathlib import Path
from types import SimpleNamespace

import pytest

try:  # pragma: no cover
    from version_detector import VersionDetector  # type: ignore
    from src.pipeline import Context, PIPELINE  # type: ignore
    from src.passes.payload_decode import run as payload_decode_run  # type: ignore
    from src.versions import get_handler  # type: ignore
    from src.versions.initv4 import InitV4Decoder  # type: ignore
    from src.versions.luraph_v14_4_initv4 import (  # type: ignore
        DEFAULT_ALPHABET as INITV4_DEFAULT_ALPHABET,
        decode_blob as initv4_decode_blob,
    )
    from src.versions.luraph_v14_4_1 import (  # type: ignore
        LuraphV1441,
        _INITV4_ALPHABET,
        _apply_script_key_transform,
        _encode_base91,
        decode_blob,
        decode_blob_with_metadata,
    )
    from src.deobfuscator import LuaDeobfuscator  # type: ignore
except Exception as exc:  # pragma: no cover
    pytest.skip(f"legacy v14.4.1 stack unavailable: {exc}", allow_module_level=True)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_V1441 = PROJECT_ROOT / "examples" / "v1441_hello.lua"
GOLDEN_V1441 = PROJECT_ROOT / "tests" / "golden" / "v1441_hello.lua.out"
EXAMPLE_SCRIPT_KEY = "x5elqj5j4ibv9z3329g7b"


def _make_sample(raw: bytes | None = None, *, script_key: str = "SuperSecretKey") -> tuple[str, bytes, str, str]:
    payload = raw if raw is not None else bytes(range(256))
    key_bytes = script_key.encode("utf-8")
    masked = _apply_script_key_transform(payload, key_bytes)
    blob = _encode_base91(masked)
    script = (
        "-- Luraph v14.4.1 bootstrap\n"
        "local script_key = script_key or \""
        + script_key
        + "\"\n"
        "local init_fn = function(blob)\n"
        "    return blob\n"
        "end\n"
        "local payload = \""
        + blob
        + "\"\n"
        "return init_fn(payload)\n"
    )
    return script, payload, script_key, blob


def _make_chunked_sample(
    raw: bytes | None = None,
    *,
    script_key: str = "SuperSecretKey",
    chunk_count: int = 3,
) -> tuple[str, bytes, str, list[str]]:
    payload = raw if raw is not None else bytes(range(256)) * 2
    key_bytes = script_key.encode("utf-8")
    chunk_count = max(1, chunk_count)
    chunk_size = max(1, (len(payload) + chunk_count - 1) // chunk_count)
    chunks = [payload[index : index + chunk_size] for index in range(0, len(payload), chunk_size)]
    encoded_chunks: list[str] = []
    for chunk in chunks:
        masked = _apply_script_key_transform(chunk, key_bytes)
        encoded_chunks.append(_encode_base91(masked))

    chunk_lines = [f"local chunk_{index} = \"{chunk}\"" for index, chunk in enumerate(encoded_chunks)]
    concat_expr = " .. ".join(f"chunk_{index}" for index in range(len(encoded_chunks)))

    script = "\n".join(
        [
            "-- Luraph v14.4.1 chunked bootstrap",
            f"local script_key = script_key or \"{script_key}\"",
            "local init_fn = function(blob)",
            "    return blob",
            "end",
            *chunk_lines,
            f"local payload = {concat_expr}",
            "return init_fn(payload)",
        ]
    )

    return script, payload, script_key, encoded_chunks


def _write_bootstrap_stub(tmp_path: Path) -> Path:
    fixture = Path("tests/fixtures/initv4_stub/initv4.lua")
    dest_dir = tmp_path / "bootstrap"
    dest_dir.mkdir()
    dest = dest_dir / "initv4.lua"
    dest.write_text(fixture.read_text(encoding="utf-8"), encoding="utf-8")
    return dest_dir


def test_decode_blob_roundtrip() -> None:
    _, raw, script_key, blob = _make_sample()
    assert decode_blob(blob, script_key) == raw


def test_decode_blob_known_vector() -> None:
    blob = "qx6zfmk8qigsbzcd3bv64"
    expected = bytes([85, 129, 209, 137, 49, 236, 178, 144, 132, 70, 29, 96, 69, 93, 80, 119, 50])
    assert decode_blob(blob, "x5elqj5j4ibv9z3329g7b") == expected


def test_initv4_decode_blob_helper_matches_handler() -> None:
    _, raw, script_key, blob = _make_sample()
    helper = initv4_decode_blob(blob, INITV4_DEFAULT_ALPHABET, script_key.encode("utf-8"))
    assert helper == raw
    assert helper == decode_blob(blob, script_key)


def test_decode_blob_wrong_key_changes_payload() -> None:
    _, raw, script_key, blob = _make_sample()
    assert decode_blob(blob, script_key + "!") != raw


def test_decode_blob_base64_fallback() -> None:
    _, raw, script_key, _ = _make_sample()
    key_bytes = script_key.encode("utf-8")
    masked = _apply_script_key_transform(raw, key_bytes)
    blob = base64.b64encode(masked).decode("ascii")
    data, meta = decode_blob_with_metadata(blob, script_key)
    assert data == raw
    assert meta["decode_method"] in {"base64", "base64-relaxed"}
    assert meta.get("index_xor") is True


def test_decode_blob_falls_back_to_default_alphabet() -> None:
    raw = b'{"bytecode": [], "constants": []}'
    script_key = EXAMPLE_SCRIPT_KEY
    key_bytes = script_key.encode("utf-8")
    masked = _apply_script_key_transform(raw, key_bytes)
    blob = _encode_base91(masked)

    wrong_alphabet = "".join(reversed(_INITV4_ALPHABET))
    data, meta = decode_blob_with_metadata(blob, script_key, alphabet=wrong_alphabet)

    assert data == raw
    assert meta.get("alphabet_source") == "heuristic"
    attempts = meta.get("decode_attempts", [])
    assert any(entry.get("alphabet_source") == "bootstrap" for entry in attempts)


def test_v1441_handler_locates_payload() -> None:
    script, raw, script_key, blob = _make_sample()
    handler = LuraphV1441()
    assert handler.matches(script)
    payload = handler.locate_payload(script)
    assert payload is not None
    assert payload.text == blob
    assert payload.metadata["script_key"] == script_key
    assert handler.extract_bytecode(payload) == raw
    assert payload.metadata.get("decode_method") == "base91"
    assert payload.metadata.get("index_xor") is True
    assert payload.metadata.get("alphabet_source") == "heuristic"


def test_v1441_handler_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    script, raw, script_key, blob = _make_sample()
    script = script.replace(f'"{script_key}"', "getgenv().script_key")
    handler = LuraphV1441()
    payload = handler.locate_payload(script)
    assert payload is not None
    assert payload.text == blob
    assert "script_key" not in payload.metadata
    monkeypatch.setenv("LURAPH_SCRIPT_KEY", script_key)
    try:
        assert handler.extract_bytecode(payload) == raw
        assert payload.metadata.get("decode_method") == "base91"
        assert payload.metadata.get("index_xor") is True
        assert payload.metadata.get("alphabet_source") == "heuristic"
    finally:
        monkeypatch.delenv("LURAPH_SCRIPT_KEY", raising=False)


def test_v1441_handler_requires_script_key() -> None:
    script, _, script_key, _ = _make_sample()
    script = script.replace(f'"{script_key}"', "getgenv().script_key")
    handler = LuraphV1441()
    payload = handler.locate_payload(script)
    assert payload is not None
    with pytest.raises(RuntimeError):
        handler.extract_bytecode(payload)


def test_v1441_handler_uses_bootstrapper_metadata(tmp_path: Path) -> None:
    stub_dir = _write_bootstrap_stub(tmp_path)
    handler = LuraphV1441()
    meta = handler.set_bootstrapper(stub_dir)
    assert meta["path"].endswith("initv4.lua")
    table = handler.opcode_table()
    assert table[0x10].mnemonic == "MOVE"
    assert table[0x2A].mnemonic == "FORLOOP"
    assert table[0x2B].mnemonic == "TFORLOOP"
    assert table[0x22].mnemonic == "CONCAT"
    extraction = meta.get("extraction") or {}
    dispatch_meta = extraction.get("opcode_dispatch", {})
    assert dispatch_meta.get("count", 0) >= len(table)


def test_initv4_decoder_extracts_metadata(tmp_path: Path) -> None:
    script, raw, script_key, blob = _make_sample()
    stub_dir = _write_bootstrap_stub(tmp_path)
    ctx = SimpleNamespace(script_key=script_key, bootstrapper_path=stub_dir)
    decoder = InitV4Decoder(ctx)

    assert decoder.alphabet is not None and len(decoder.alphabet) >= 85

    payloads = decoder.locate_payload(script)
    assert f'"{blob}"' in payloads

    decoded = decoder.extract_bytecode(payloads[0])
    assert decoded == raw

    opcode_table = decoder.opcode_table()
    assert opcode_table.get(0x10) == "MOVE"
    assert opcode_table.get(0x2A) == "FORLOOP"
    assert opcode_table.get(0x2B) == "TFORLOOP"
    assert opcode_table.get(0x22) == "CONCAT"


def test_initv4_decoder_locates_string_char_payload() -> None:
    script, raw, script_key, blob = _make_sample()
    byte_args = ",".join(str(ord(char)) for char in blob)
    script = script.replace(
        f'local payload = "{blob}"',
        f"local payload = string.char({byte_args})",
    )

    decoder = InitV4Decoder(SimpleNamespace(script_key=script_key))

    payloads = decoder.locate_payload(script)
    string_char_literal = next(
        (entry for entry in payloads if entry.lstrip().lower().startswith("string.char")),
        None,
    )
    assert string_char_literal is not None

    decoded = decoder.extract_bytecode(string_char_literal)
    assert decoded == raw


def test_initv4_decoder_locates_numeric_array_payload() -> None:
    _, raw, script_key, blob = _make_sample()
    values = ",".join(str(ord(char)) for char in blob)
    array_literal = "{" + values + "}"

    script = "\n".join(
        [
            "-- Luraph v14.4.1 bootstrap",
            f"local script_key = script_key or \"{script_key}\"",
            "local init_fn = function(blob)",
            "    return blob",
            "end",
            f"local payload_bytes = {array_literal}",
            "local function build_blob(data)",
            "    local out = {}",
            "    for i = 1, #data do",
            "        out[i] = string.char(data[i])",
            "    end",
            "    return table.concat(out)",
            "end",
            "local payload = build_blob(payload_bytes)",
            "return init_fn(payload)",
        ]
    )

    decoder = InitV4Decoder(SimpleNamespace(script_key=script_key))

    payloads = decoder.locate_payload(script)
    array_payload = next((entry for entry in payloads if entry.lstrip().startswith("{")), None)
    assert array_payload is not None

    decoded = decoder.extract_bytecode(array_payload)
    assert decoded == raw


def test_v1441_handler_decodes_chunked_payload() -> None:
    script, raw, script_key, encoded_chunks = _make_chunked_sample(chunk_count=4)
    handler = LuraphV1441()

    payload = handler.locate_payload(script)
    assert payload is not None

    meta_before = dict(payload.metadata)
    assert meta_before.get("chunk_count") == len(encoded_chunks)
    assert isinstance(meta_before.get("chunks"), list)

    decoded = handler.extract_bytecode(payload)
    assert decoded == raw

    meta_after = payload.metadata
    assert meta_after.get("chunk_count") == len(encoded_chunks)
    assert "_chunks" not in meta_after

    chunk_size = max(1, (len(raw) + len(encoded_chunks) - 1) // len(encoded_chunks))
    expected_decoded = [len(raw[index : index + chunk_size]) for index in range(0, len(raw), chunk_size)]
    assert meta_after.get("chunk_decoded_bytes") == expected_decoded
    assert meta_after.get("chunk_lengths") == [len(chunk) for chunk in encoded_chunks]

    attempts = meta_after.get("decode_attempts", [])
    assert attempts
    assert {entry.get("chunk_index") for entry in attempts} == set(range(len(encoded_chunks)))


def test_extract_bytecode_includes_bootstrap_info(tmp_path: Path) -> None:
    stub_dir = _write_bootstrap_stub(tmp_path)
    handler = LuraphV1441()
    handler.set_bootstrapper(stub_dir)
    script, raw, _, _ = _make_sample()
    payload = handler.locate_payload(script)
    assert payload is not None
    data = handler.extract_bytecode(payload)
    assert data == raw
    meta = payload.metadata.get("bootstrapper")
    assert isinstance(meta, dict)
    assert meta.get("path", "").endswith("initv4.lua")
    assert payload.metadata.get("alphabet_length", 0) >= 85
    assert payload.metadata.get("alphabet_source") == "bootstrap"
    extraction_meta = payload.metadata.get("bootstrapper_metadata")
    assert isinstance(extraction_meta, dict)
    assert extraction_meta.get("opcode_dispatch", {}).get("count", 0) >= len(handler.opcode_table())


def test_payload_decode_requires_script_key(tmp_path: Path) -> None:
    script, _, script_key, _ = _make_sample()
    script = script.replace(f'"{script_key}"', "getgenv().script_key")
    payload_dir = tmp_path / "payload_missing_key"
    payload_dir.mkdir(parents=True, exist_ok=True)
    path = payload_dir / "sample.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(input_path=path, raw_input=script, stage_output=script)

    with pytest.raises(RuntimeError, match="script key"):
        payload_decode_run(ctx)


def test_payload_decode_force_allows_missing_key(tmp_path: Path) -> None:
    script, _, script_key, _ = _make_sample()
    script = script.replace(f'"{script_key}"', "getgenv().script_key")
    payload_dir = tmp_path / "payload_missing_key_force"
    payload_dir.mkdir(parents=True, exist_ok=True)
    path = payload_dir / "sample.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=script,
        stage_output=script,
        force=True,
    )
    ctx.options["force"] = True

    metadata = payload_decode_run(ctx)

    assert "handler_bytecode_error" in metadata
    warnings = metadata.get("warnings", [])
    assert any("script key" in str(entry).lower() for entry in warnings)
    assert any("script key" in warning.lower() for warning in ctx.report.warnings)


def test_payload_decode_uses_script_key(tmp_path: Path) -> None:
    script, raw, script_key, _ = _make_sample()
    script = script.replace(f'"{script_key}"', "getgenv().script_key")
    payload_dir = tmp_path / "payload_with_key"
    payload_dir.mkdir(parents=True, exist_ok=True)
    path = payload_dir / "sample.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=script,
        stage_output=script,
        script_key=script_key,
    )
    ctx.detected_version = VersionDetector().info_for_name("luraph_v14_4_initv4")

    metadata = payload_decode_run(ctx)

    assert ctx.version is not None and ctx.version.name in {
        "luraph_v14_4_initv4",
        "v14.4.1",
    }
    assert metadata.get("handler_bytecode_bytes") == len(raw)
    assert ctx.vm.bytecode == raw
    payload_meta = metadata.get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("decode_method") == "base91"
    assert payload_meta.get("index_xor") is True
    assert payload_meta.get("alphabet_source") in {"heuristic", "bootstrap"}
    assert ctx.vm.meta.get("handler") in {"luraph_v14_4_initv4", "v14.4.1"}
    assert ctx.report.script_key_used == script_key
    assert ctx.report.blob_count >= 1
    assert ctx.report.decoded_bytes >= len(raw)


def test_payload_decode_parses_script_payload(tmp_path: Path) -> None:
    script = EXAMPLE_V1441.read_text(encoding="utf-8")
    raw_expected = """local sum = 2 + 2
assert(false, 'init trap neutralised')
print('hello from v14.4.1!')
return 'ok'"""
    path = tmp_path / "v1441.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=script,
        stage_output=script,
        script_key=EXAMPLE_SCRIPT_KEY,
    )

    metadata = payload_decode_run(ctx)

    assert ctx.stage_output.strip() == raw_expected.strip()
    assert metadata.get("handler_decoded_json") is True
    assert metadata.get("script_payload") is True
    assert not ctx.vm.bytecode
    payload_meta = metadata.get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("decode_method") == "base91"
    assert payload_meta.get("index_xor") is True
    assert payload_meta.get("alphabet_source") in {"heuristic", "bootstrap"}
    assert ctx.report.script_key_used == EXAMPLE_SCRIPT_KEY


def test_deobfuscator_decode_payload_uses_script_key_and_bootstrapper(tmp_path: Path) -> None:
    script = EXAMPLE_V1441.read_text(encoding="utf-8")
    stub_dir = _write_bootstrap_stub(tmp_path)

    deobfuscator = LuaDeobfuscator()
    version = VersionDetector().info_for_name("luraph_v14_4_initv4")

    result = deobfuscator.decode_payload(
        script,
        version=version,
        script_key=EXAMPLE_SCRIPT_KEY,
        bootstrapper=stub_dir,
    )

    assert "local sum = 2 + 2" in result.text
    assert "hello from v14.4.1!" in result.text

    metadata = result.metadata
    assert metadata.get("script_key_override") is True
    bootstrapper_path = metadata.get("bootstrapper_path")
    assert isinstance(bootstrapper_path, str)
    assert Path(bootstrapper_path).name == stub_dir.name

    payload_meta = metadata.get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("alphabet_source") == "bootstrap"
    assert payload_meta.get("decode_method") == "base91"
    assert payload_meta.get("script_key_length") == len(EXAMPLE_SCRIPT_KEY)

    bootstrap_meta = metadata.get("bootstrapper", {})
    assert isinstance(bootstrap_meta, dict)
    assert bootstrap_meta.get("path", "").endswith("initv4.lua")


def test_payload_decode_handles_chunked_script(tmp_path: Path) -> None:
    script_body = "\n".join(["print('chunked payload!')"] * 8)
    raw_mapping = {"bytecode": [], "constants": [], "script": script_body}
    raw_bytes = json.dumps(raw_mapping).encode("utf-8")
    chunk_count = 4
    script, _, script_key, encoded_chunks = _make_chunked_sample(
        raw=raw_bytes,
        script_key=EXAMPLE_SCRIPT_KEY,
        chunk_count=chunk_count,
    )

    path = tmp_path / "chunked.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=script,
        stage_output=script,
        script_key=script_key,
    )

    metadata = payload_decode_run(ctx)

    assert ctx.stage_output.strip() == script_body.strip()
    payload_meta = metadata.get("handler_payload_meta", {})
    assert payload_meta.get("chunk_count") == chunk_count
    assert payload_meta.get("chunk_lengths") == [len(chunk) for chunk in encoded_chunks]
    assert payload_meta.get("chunk_success_count") == chunk_count

    chunk_size = max(1, (len(raw_bytes) + chunk_count - 1) // chunk_count)
    expected_decoded = [len(raw_bytes[index : index + chunk_size]) for index in range(0, len(raw_bytes), chunk_size)]
    assert payload_meta.get("chunk_decoded_bytes") == expected_decoded
    encoded_lengths = metadata.get("handler_chunk_encoded_lengths") or payload_meta.get("chunk_encoded_lengths")
    assert encoded_lengths == [len(chunk) for chunk in encoded_chunks]

    assert metadata.get("handler_payload_chunks") == chunk_count
    assert ctx.report.blob_count == chunk_count
    total_expected = sum(expected_decoded)
    assert ctx.report.decoded_bytes == total_expected
    warning_summary = next(
        (entry for entry in ctx.report.warnings if str(entry).startswith("Decoded chunk sizes (bytes):")),
        None,
    )
    assert warning_summary is not None
    for length in expected_decoded:
        assert str(length) in warning_summary
    assert ctx.report.script_key_used == script_key
    assert ctx.decoded_payloads and ctx.decoded_payloads[-1].strip() == script_body.strip()


def test_payload_decode_merges_multiple_initv4_payloads(tmp_path: Path) -> None:
    script_body_one = "print('first chunk payload')"
    script_body_two = "print('second chunk payload')"

    raw_one = json.dumps({"constants": [], "bytecode": [], "script": script_body_one}).encode("utf-8")
    raw_two = json.dumps({"constants": [], "bytecode": [], "script": script_body_two}).encode("utf-8")

    script_one, _, script_key, _ = _make_sample(raw=raw_one, script_key=EXAMPLE_SCRIPT_KEY)
    script_two, _, _, _ = _make_sample(raw=raw_two, script_key=EXAMPLE_SCRIPT_KEY)

    combined = "\n\n".join([script_one, script_two])
    path = tmp_path / "multi_chunks.lua"
    path.write_text(combined, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=combined,
        stage_output=combined,
        script_key=EXAMPLE_SCRIPT_KEY,
    )

    metadata = payload_decode_run(ctx)

    sources = metadata.get("handler_chunk_sources", [])
    assert isinstance(sources, list) and len([src for src in sources if isinstance(src, str) and src.strip()]) >= 2

    merged = metadata.get("handler_chunk_combined_source")
    assert isinstance(merged, str)
    assert "first chunk payload" in merged
    assert "second chunk payload" in merged

    assert ctx.stage_output.strip() == merged.strip()
    assert ctx.decoded_payloads and ctx.decoded_payloads[-1].strip() == merged.strip()


def test_payload_decode_iterates_nested_payloads(tmp_path: Path) -> None:
    final_script = "print('nested chunk payload')"
    inner_mapping = {"constants": [], "bytecode": [], "script": final_script}
    inner_raw = json.dumps(inner_mapping).encode("utf-8")
    inner_stub, _, _, _ = _make_sample(raw=inner_raw, script_key=EXAMPLE_SCRIPT_KEY)
    outer_stub, _, _, _ = _make_sample(raw=inner_stub.encode("utf-8"), script_key=EXAMPLE_SCRIPT_KEY)

    path = tmp_path / "nested.lua"
    path.write_text(outer_stub, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=outer_stub,
        stage_output=outer_stub,
        script_key=EXAMPLE_SCRIPT_KEY,
    )

    metadata = payload_decode_run(ctx)

    assert ctx.stage_output.strip() == final_script.strip()
    assert metadata.get("payload_iterations", 0) >= 2
    versions = metadata.get("payload_iteration_versions")
    assert isinstance(versions, list) and len(versions) >= 2
    assert ctx.decoded_payloads and ctx.decoded_payloads[-1].strip() == final_script.strip()
    assert metadata.get("handler_payload_chunks", 0) >= 1
    assert ctx.report.blob_count >= metadata.get("handler_payload_chunks", 0)


def test_payload_decode_with_wrong_key_returns_bootstrap(tmp_path: Path) -> None:
    script = EXAMPLE_V1441.read_text(encoding="utf-8")
    path = tmp_path / "wrong_key.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=script,
        stage_output=script,
        script_key="incorrect",
    )

    metadata = payload_decode_run(ctx)

    assert ctx.stage_output.startswith("--[[ undecoded initv4 chunk")
    assert metadata.get("handler_decoded_json") is not True
    assert metadata.get("placeholder_output") is True
    assert "script_payload" not in metadata or not metadata["script_payload"]
    payload_meta = metadata.get("handler_payload_meta", {})
    assert payload_meta.get("decode_method") in {"base91", "base64", "base64-relaxed"}
    assert payload_meta.get("alphabet_source") in {"heuristic", "bootstrap"}


def test_payload_decode_handles_empty_bootstrap() -> None:
    script = (
        "-- Luraph v14.4.1 bootstrap without payload\n"
        "local script_key = script_key or getgenv().script_key\n"
        "local init_fn = function(blob)\n    return blob\nend\n"
    )

    ctx = Context(input_path=Path("dummy.lua"), raw_input=script, stage_output=script)

    metadata = payload_decode_run(ctx)

    assert "handler_payload_offset" not in metadata
    assert ctx.stage_output.startswith("-- Luraph v14.4.1")


def test_version_detector_reports_v1441() -> None:
    script, _, _, _ = _make_sample()
    detector = VersionDetector()
    detected = detector.detect(script)
    assert detected.name == "luraph_v14_4_initv4"
    handler = get_handler("luraph_v14_4_initv4")
    assert isinstance(handler, LuraphV1441)
    assert handler.matches(script)

    legacy = get_handler("v14.4.1")
    assert isinstance(legacy, LuraphV1441)
    assert legacy.matches(script)


def test_pipeline_deobfuscates_v1441_example(tmp_path: Path) -> None:
    script = EXAMPLE_V1441.read_text(encoding="utf-8")
    expected = GOLDEN_V1441.read_text(encoding="utf-8")
    source = tmp_path / "v1441.lua"
    source.write_text(script, encoding="utf-8")
    output = tmp_path / "out.lua"

    ctx = Context(
        input_path=source,
        raw_input=script,
        stage_output=script,
        script_key=EXAMPLE_SCRIPT_KEY,
    )
    ctx.options["render_output"] = str(output)
    ctx.deobfuscator = LuaDeobfuscator(script_key=EXAMPLE_SCRIPT_KEY)

    PIPELINE.run_passes(ctx)

    assert ctx.detected_version is not None and ctx.detected_version.name in {
        "luraph_v14_4_initv4",
        "v14.4.1",
    }
    assert ctx.pass_metadata.get("vm_lift", {}).get("available") is False
    payload_meta = ctx.pass_metadata.get("payload_decode", {}).get("handler_payload_meta", {})
    assert payload_meta.get("script_key_provider") == "override"
    assert payload_meta.get("decode_method") == "base91"
    assert payload_meta.get("index_xor") is True
    assert payload_meta.get("alphabet_source") in {"heuristic", "bootstrap"}
    assert output.read_text(encoding="utf-8").strip() == expected.strip()


def test_pipeline_processes_initv4_bytecode(tmp_path: Path) -> None:
    handler = LuraphV1441()
    table = handler.opcode_table()
    return_opcode = next(
        opcode for opcode, spec in table.items() if spec.mnemonic.upper() == "RETURN"
    )

    raw = bytes([return_opcode, 0x00, 0x01, 0x00] * 64)
    script, _, script_key, _ = _make_sample(raw, script_key="PipelineKey")

    path = tmp_path / "bytecode.lua"
    path.write_text(script, encoding="utf-8")

    ctx = Context(
        input_path=path,
        raw_input=script,
        stage_output=script,
        script_key=script_key,
    )
    ctx.options["render_output"] = str(tmp_path / "bytecode_out.lua")
    ctx.deobfuscator = LuaDeobfuscator(script_key=script_key)

    PIPELINE.run_passes(ctx)

    assert ctx.detected_version is not None and ctx.detected_version.name in {
        "luraph_v14_4_initv4",
        "v14.4.1",
    }
    vm_lift_meta = ctx.pass_metadata.get("vm_lift", {})
    assert vm_lift_meta.get("instructions", 0) >= 1
    assert ctx.ir_module is not None
    devirt_meta = ctx.pass_metadata.get("vm_devirtualize", {})
    assert not devirt_meta.get("skipped", False)
    render_meta = ctx.pass_metadata.get("render", {})
    assert render_meta.get("written") is True
    output_path = Path(render_meta.get("output_path", ""))
    assert output_path.exists()
    assert ctx.output

    report = ctx.report
    assert report.version_detected in {"luraph_v14_4_initv4", "v14.4.1"}
    assert report.script_key_used == script_key
    payload_meta = ctx.pass_metadata.get("payload_decode", {})
    byte_count = payload_meta.get("handler_bytecode_bytes")
    assert isinstance(byte_count, int) and byte_count > 0
    assert report.blob_count >= 1
    assert report.decoded_bytes >= byte_count
    assert "Return" in report.opcode_stats
    assert report.opcode_stats["Return"] == ctx.ir_module.instruction_count
    assert report.unknown_opcodes == []
    assert report.variables_renamed == ctx.pass_metadata.get("vm_devirtualize", {}).get(
        "renamed_count", 0
    )
    assert report.output_length == len(ctx.output)
