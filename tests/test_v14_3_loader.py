import struct
from pathlib import Path

import pytest

from pattern_analyzer import (
    Constant,
    SerializedChunk,
    SerializedChunkDescriptor,
    SerializedPrototype,
)
from src.versions.v14_3_loader import (
    DecodedDoubleValue,
    DOUBLE_PAYLOAD_OFFSET,
    PrototypeIRPrototype,
    PrototypeLoaderIR,
    SerializedChunkExtractionError,
    apply_double_constant_unpacker,
    build_serialized_chunk_model,
    build_v14_3_serialized_chunk_from_bytes,
    decode_packed_double,
    extract_v14_3_serialized_chunk_bytes_from_source,
)


DOUBLE_PREFIX = 0x4330000000000000
DOUBLE_VALUE_MASK = (1 << 32) - 1
DOUBLE_FLAG_SHIFT = 32
def _encode_packed_double(value: int, *, flags: int = 0) -> float:
    if not -(1 << 31) <= value < (1 << 31):
        raise ValueError("value must fit in signed 32-bit range")
    if flags < 0 or flags > ((1 << (53 - DOUBLE_FLAG_SHIFT)) - 1):
        raise ValueError("flags exceed payload capacity")

    value_bits = value & DOUBLE_VALUE_MASK
    payload = (flags << DOUBLE_FLAG_SHIFT) | value_bits
    bits = DOUBLE_PREFIX | payload
    return struct.unpack('>d', struct.pack('>Q', bits))[0]


def test_decode_packed_double_recovers_signed_value_and_flags() -> None:
    encoded = _encode_packed_double(-12345, flags=0x155)
    decoded = decode_packed_double(encoded)
    assert isinstance(decoded, DecodedDoubleValue)
    assert int(decoded) == -12345
    assert decoded.flags == 0x155
    expected_payload = (0x155 << DOUBLE_FLAG_SHIFT) | ((-12345) & DOUBLE_VALUE_MASK)
    assert decoded.payload == expected_payload
    assert decoded.raw_double == encoded


def test_decode_packed_double_rejects_plain_floats() -> None:
    assert decode_packed_double(3.14159) is None
    assert decode_packed_double(float('nan')) is None


def test_double_payload_offset_matches_runtime_bias() -> None:
    assert DOUBLE_PAYLOAD_OFFSET == 4503599627370496


def test_apply_double_constant_unpacker_updates_nested_structures() -> None:
    primary = _encode_packed_double(42, flags=3)
    nested = _encode_packed_double(-7, flags=0)
    mapping = {"token": primary, "other": [nested, 1.5]}
    chunk = SerializedChunk(
        descriptor=SerializedChunkDescriptor(
            buffer_name="payload",
            initial_offset=4,
            helper_functions={},
        ),
        prototypes=[
            SerializedPrototype(
                constants=[mapping],
                instructions=[[primary, nested]],
                prototypes=[
                    SerializedPrototype(constants=[nested], instructions=[], prototypes=[])
                ],
            )
        ],
    )

    apply_double_constant_unpacker(chunk)

    root = chunk.prototypes[0]
    decoded_mapping = root.constants[0]
    assert isinstance(decoded_mapping, Constant)
    assert decoded_mapping.kind == "table"
    assert isinstance(decoded_mapping.value["token"], DecodedDoubleValue)
    assert int(decoded_mapping.value["token"]) == 42
    assert decoded_mapping.value["token"].flags == 3
    assert isinstance(root.instructions[0][0], DecodedDoubleValue)
    assert int(root.instructions[0][1]) == -7
    child_constant = root.prototypes[0].constants[0]
    assert isinstance(child_constant, Constant)
    assert child_constant.kind == "number"
    assert child_constant.value == -7
    assert isinstance(child_constant.raw_value, DecodedDoubleValue)
def test_build_serialized_chunk_model_runs_double_unpacker() -> None:
    encoded = _encode_packed_double(77, flags=1)
    descriptor = SerializedChunkDescriptor(
        buffer_name="payload",
        initial_offset=8,
        helper_functions={},
    )
    loader_ir = PrototypeLoaderIR(
        prototypes=[
            PrototypeIRPrototype(
                constants=(encoded,),
                instructions=(),
                prototypes=(),
            )
        ]
    )

    chunk = build_serialized_chunk_model(
        descriptor,
        loader_ir,
        script_key="session",
    )

    decoded_constant = chunk.prototypes[0].constants[0]
    assert isinstance(decoded_constant, Constant)
    assert decoded_constant.kind == "number"
    assert decoded_constant.value == 77
    assert isinstance(decoded_constant.raw_value, DecodedDoubleValue)
    assert decoded_constant.raw_value.flags == 1


def test_apply_double_constant_unpacker_rejects_missing_chunk() -> None:
    with pytest.raises(ValueError):
        apply_double_constant_unpacker(None)


def test_constant_usage_metadata_marks_vm_loader_and_auxiliary() -> None:
    chunk = SerializedChunk(
        descriptor=SerializedChunkDescriptor(
            buffer_name="payload",
            initial_offset=0,
            helper_functions={},
        ),
        prototypes=[
            SerializedPrototype(
                constants=["alpha", "beta", "gamma", "unused"],
                instructions=[
                    {"op": "LOADK", "const": 0},
                    ("LOADK", 0, 1),
                    {"op": "HELPER", "aux": {"const_index": 2}},
                ],
                prototypes=[],
            ),
            SerializedPrototype(constants=["loader"], instructions=[], prototypes=[]),
        ],
    )

    apply_double_constant_unpacker(chunk)

    root_constants = chunk.prototypes[0].constants
    assert [const.metadata.get("usage") for const in root_constants[:3]] == [
        "vm",
        "vm",
        "vm",
    ]
    assert root_constants[3].metadata.get("usage") == "auxiliary"

    loader_constant = chunk.prototypes[1].constants[0]
    assert loader_constant.metadata.get("usage") == "loader"


def test_build_v14_3_serialized_chunk_decodes_real_payload() -> None:
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    descriptor, data = extract_v14_3_serialized_chunk_bytes_from_source(source)

    chunk = build_v14_3_serialized_chunk_from_bytes(
        descriptor,
        data,
        allow_re_fallback=False,
    )

    assert chunk.prototypes, "expected decoded prototype for native payload"
    constants = chunk.prototypes[0].constants
    assert constants, "expected decoded constants for native payload"
    placeholder_roles = {"raw_blob", "header_probe", "constants_probe", "decoder_error"}
    assert all(
        isinstance(constant, Constant)
        and constant.metadata.get("role") not in placeholder_roles
        for constant in constants
    )
