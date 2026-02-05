import base64
import json
from pathlib import Path

import pytest

from pattern_analyzer import (
    Constant,
    PrimitiveTableInfo,
    SerializedChunk,
    SerializedChunkDescriptor,
    SerializedPrototype,
)
from src.versions.v14_3_loader import (
    DecodedTokenString,
    apply_string_table_to_chunk,
)
from string_decryptor import (
    StringDecoderDescriptor,
    StringDecryptor,
    build_v14_3_string_table,
    decode_string_v14_3,
    detect_v14_3_string_decoder,
)


LUA_V14_3_DECODER_SOURCE = """
local BASE_OFFSET = 33
local WEIGHTS = {52200625, 614125, 7225, 85, 1}

local function pack_be32(value)
  local b1 = math.floor(value / 16777216) % 256
  local b2 = math.floor(value / 65536) % 256
  local b3 = math.floor(value / 256) % 256
  local b4 = value % 256
  return string.char(b1, b2, b3, b4)
end

local function decode_chunk(chunk)
  local P, U, I, j, Y = string.byte(chunk, 1, 5)
  local digits = {P, U, I, j, Y}
  local value = 0
  for index = 1, #digits do
    local digit = digits[index] - BASE_OFFSET
    value = value + digit * WEIGHTS[index]
  end
  return pack_be32(value)
end

return function(token)
  if (#token % 5) ~= 0 then
    error("token length is not a multiple of 5")
  end
  local pieces = {}
  for offset = 1, #token, 5 do
    local chunk = string.sub(token, offset, offset + 4)
    pieces[#pieces + 1] = decode_chunk(chunk)
  end
  return table.concat(pieces)
end
"""


def test_layered_xor_base64_hex_round_trip():
    plain = "secret value"
    hex_layer = plain.encode("utf-8").hex()
    base64_layer = base64.b64encode(hex_layer.encode("utf-8")).decode("ascii")
    key = " "  # XOR with space keeps characters printable
    xor_layer = "".join(chr(ord(ch) ^ ord(key)) for ch in base64_layer)
    xor_layer_escaped = xor_layer.replace("\\", "\\\\").replace('"', '\\"')

    lua_snippet = f'return xor_layer("{xor_layer_escaped}", "{key}")'

    decrypted = StringDecryptor().decrypt(lua_snippet)
    assert plain in decrypted

    # ensure decode -> encode round trips the original cipher text
    reconstructed_hex = plain.encode("utf-8").hex()
    reconstructed_base64 = base64.b64encode(reconstructed_hex.encode("utf-8")).decode("ascii")
    reconstructed_xor = "".join(chr(ord(ch) ^ ord(key)) for ch in reconstructed_base64)
    assert reconstructed_xor == xor_layer


def test_inline_closure_and_loadstring_are_folded():
    source = """
    local a = (function() return "hello" .. " " .. "world" end)()
    local b = loadstring("return 'ok'")()
    return a .. b
    """

    decrypted = StringDecryptor().decrypt(source)
    assert "function" not in decrypted
    assert "loadstring" not in decrypted
    assert '"hello world"' in decrypted
    assert "'ok'" in decrypted


def test_detect_v14_3_string_decoder_profile() -> None:
    source = Path('Obfuscated4.lua').read_text()
    descriptor = detect_v14_3_string_decoder(source)
    assert descriptor is not None
    assert descriptor.token_length == 5
    assert descriptor.local_variable_count >= 5
    assert descriptor.caches_results is True
    assert descriptor.invocation.replace(" ", "") == "N(u,0x5)"
    assert descriptor.gsub_alias != descriptor.metatable_alias


def _build_decoder_descriptor() -> StringDecoderDescriptor:
    return StringDecoderDescriptor(
        closure_variable="t",
        invocation="return N(u,0x5)",
        gsub_alias="P",
        metatable_alias="a",
        cache_table="F3",
        token_variable="v",
        token_length=5,
        local_variable_count=5,
        caches_results=True,
    )


def _build_primitive_info() -> PrimitiveTableInfo:
    base = 85
    weights = [1]
    for _ in range(1, 5):
        weights.append(weights[-1] * base)
    return PrimitiveTableInfo(
        token_width=5,
        base_offset=33,
        radix=base,
        weights=weights,
        alphabet_literal='"\\62\\073\\u{0034}"',
    )


def _sample_tokens() -> tuple[list[str], list[bytes]]:
    payloads = [b"ABCD", b"WXYZ"]
    tokens = [base64.a85encode(payload).decode("ascii") for payload in payloads]
    return tokens, payloads


def _chunk_with_tokens(tokens: list[str]) -> SerializedChunk:
    descriptor = SerializedChunkDescriptor(
        buffer_name="payload",
        initial_offset=0,
        helper_functions={},
    )
    child = SerializedPrototype(
        constants=[[tokens[1]]],
        instructions=[],
        prototypes=[],
    )
    root = SerializedPrototype(
        constants=[
            tokens[0],
            {"nested": tokens[1]},
            "plain",
        ],
        instructions=[],
        prototypes=[child],
    )
    return SerializedChunk(descriptor=descriptor, prototypes=[root])


@pytest.fixture(scope="module")
def lua_v14_3_decoder_callable():
    lupa = pytest.importorskip("lupa")
    runtime = lupa.LuaRuntime(unpack_returned_tuples=True)
    if getattr(runtime, "is_fallback", False):
        pytest.skip("Lua fallback runtime cannot evaluate string decoder reference")
    return runtime.eval(LUA_V14_3_DECODER_SOURCE)


def test_decode_string_v14_3_zero_chunk_uses_attached_metadata() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()
    descriptor.attach_primitive_table_info(primitive_info)

    decoded = decode_string_v14_3("!!!!!", descriptor=descriptor)
    assert decoded == b"\x00\x00\x00\x00".decode("latin-1")


def test_decode_string_v14_3_matches_python_ascii85() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()

    payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    token = base64.a85encode(payload).decode("ascii")

    decoded = decode_string_v14_3(token, descriptor=descriptor, primitive_table=primitive_info)
    assert decoded == payload.decode("latin-1")


def test_decode_string_v14_3_handles_missing_weights_via_radix() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = PrimitiveTableInfo(
        token_width=5,
        base_offset=33,
        radix=85,
        weights=[],
        alphabet_literal='"\\62\\073\\u{0034}"',
    )

    payload = b"\xAA\xBB\xCC\xDD"
    token = base64.a85encode(payload).decode("ascii")

    decoded = decode_string_v14_3(token, descriptor=descriptor, primitive_table=primitive_info)
    assert decoded == payload.decode("latin-1")


def test_decode_string_v14_3_normalises_token_whitespace() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()

    payload = b"\x00\x11\x22\x33"
    token = base64.a85encode(payload).decode("ascii")
    token = token[:5] + "\n" + token[5:]

    decoded = decode_string_v14_3(token, descriptor=descriptor, primitive_table=primitive_info)
    assert decoded == payload.decode("latin-1")


def test_decode_string_v14_3_matches_lua_runtime(lua_v14_3_decoder_callable) -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()
    tokens, payloads = _sample_tokens()

    lua_decoder = lua_v14_3_decoder_callable

    for token, payload in zip(tokens, payloads):
        python_decoded = decode_string_v14_3(
            token,
            descriptor=descriptor,
            primitive_table=primitive_info,
        )
        lua_decoded = lua_decoder(token)
        assert isinstance(lua_decoded, str)
        assert python_decoded == lua_decoded
        assert python_decoded == payload.decode("latin-1")


def test_build_v14_3_string_table_collects_unique_tokens() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()
    tokens, payloads = _sample_tokens()
    chunk = _chunk_with_tokens(tokens)

    table = build_v14_3_string_table(
        chunk,
        descriptor,
        primitive_table=primitive_info,
    )

    assert set(table.entries.keys()) == set(tokens)
    assert set(table.entries.values()) == {
        payload.decode("latin-1") for payload in payloads
    }


def test_build_v14_3_string_table_emits_debug_file_without_tokens() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()
    tokens, payloads = _sample_tokens()
    chunk = _chunk_with_tokens(tokens)

    debug_path = Path("out") / "tests" / "decoded_strings.json"
    try:
        if debug_path.exists():
            debug_path.unlink()

        table = build_v14_3_string_table(
            chunk,
            descriptor,
            primitive_table=primitive_info,
            debug_output_path=debug_path,
        )

        assert debug_path.exists()
        payload = json.loads(debug_path.read_text(encoding="utf-8"))
        assert payload["strings"] == table.decoded_strings()
        materialised = debug_path.read_text(encoding="utf-8")
        for token in tokens:
            assert token not in materialised
        for decoded in table.decoded_strings():
            assert decoded in materialised
        assert set(payload["strings"]) == {
            value.decode("latin-1") for value in payloads
        }
    finally:
        if debug_path.exists():
            debug_path.unlink()


def test_apply_string_table_to_chunk_decodes_constants_and_instructions() -> None:
    descriptor = _build_decoder_descriptor()
    primitive_info = _build_primitive_info()
    tokens, payloads = _sample_tokens()
    chunk = _chunk_with_tokens(tokens)

    root = chunk.prototypes[0]
    root.constants.append({tokens[0]: tokens[1]})
    root.instructions = [
        {"op": "LOADK", "token": tokens[0]},
        ("CALL", tokens[1]),
    ]

    table = build_v14_3_string_table(
        chunk,
        descriptor,
        primitive_table=primitive_info,
    )

    apply_string_table_to_chunk(chunk, table)

    decoded_constant = root.constants[0]
    assert isinstance(decoded_constant, Constant)
    decoded = decoded_constant.value
    assert isinstance(decoded, DecodedTokenString)
    assert decoded == payloads[0].decode("latin-1")
    assert decoded.encoded_token == tokens[0]

    nested_constant = root.constants[1]
    assert isinstance(nested_constant, Constant)
    nested_value = nested_constant.value["nested"]
    assert isinstance(nested_value, DecodedTokenString)
    assert nested_value == payloads[1].decode("latin-1")

    keyed_constant = root.constants[-1]
    assert isinstance(keyed_constant, Constant)
    keyed_entry = keyed_constant.value
    key = next(iter(keyed_entry.keys()))
    assert isinstance(key, DecodedTokenString)
    assert key == payloads[0].decode("latin-1")
    assert keyed_entry[key] == payloads[1].decode("latin-1")

    child_constant = root.prototypes[0].constants[0]
    assert isinstance(child_constant, Constant)
    child_value = child_constant.value[0]
    assert isinstance(child_value, DecodedTokenString)
    assert child_value == payloads[1].decode("latin-1")

    instruction_operand = root.instructions[0]["token"]
    assert isinstance(instruction_operand, DecodedTokenString)
    assert instruction_operand.encoded_token == tokens[0]

    tuple_operand = root.instructions[1][1]
    assert isinstance(tuple_operand, DecodedTokenString)
    assert tuple_operand == payloads[1].decode("latin-1")
