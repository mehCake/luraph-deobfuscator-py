"""Regression coverage for the v14.3 packed-double unpacker."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from pattern_analyzer import (
    Constant,
    SerializedChunk,
    SerializedChunkDescriptor,
    SerializedPrototype,
)
from src.versions.v14_3_loader import (
    DecodedDoubleValue,
    DOUBLE_FLAG_MASK,
    PrototypeIRPrototype,
    PrototypeLoaderIR,
    apply_double_constant_unpacker,
    build_serialized_chunk_model,
    decode_packed_double,
    encode_packed_double,
)


@dataclass(frozen=True)
class PackedDoubleFixture:
    """Simple structure that records a packed double and its decoded payload."""

    raw_double: float
    expected_value: int
    expected_flags: int


def _build_chunk_from_fixtures(fixtures: Iterable[PackedDoubleFixture]) -> SerializedChunk:
    fixtures = list(fixtures)
    constants = [fixture.raw_double for fixture in fixtures]
    instructions = [[fixture.raw_double for fixture in reversed(fixtures)]]
    descriptor = SerializedChunkDescriptor(
        buffer_name="payload",
        initial_offset=0,
        helper_functions={},
    )
    prototype = SerializedPrototype(
        constants=constants,
        instructions=instructions,
        prototypes=[],
    )
    return SerializedChunk(
        descriptor=descriptor,
        prototypes=[prototype],
    )


def _make_fixture(value: int, *, flags: int = 0) -> PackedDoubleFixture:
    return PackedDoubleFixture(
        raw_double=encode_packed_double(value, flags=flags),
        expected_value=value,
        expected_flags=flags,
    )


# ``DOUBLE_FLAG_MASK`` reflects the theoretical payload width, but the decoded flag
# range is slightly narrower once the loader's prefix bits are subtracted.  The
# helper below captures the effective maximum so the tests encode the largest
# representable flag value while still having a deterministic expectation.
_MAX_EFFECTIVE_FLAGS = decode_packed_double(
    encode_packed_double(0, flags=DOUBLE_FLAG_MASK)
).flags


EXTREME_FIXTURES = (
    _make_fixture(-(1 << 31)),
    _make_fixture((1 << 31) - 1, flags=0),
    _make_fixture(0, flags=_MAX_EFFECTIVE_FLAGS),
)


def test_unpacker_decodes_fixture_constants_and_instructions() -> None:
    chunk = _build_chunk_from_fixtures(EXTREME_FIXTURES)

    apply_double_constant_unpacker(chunk)

    prototype = chunk.prototypes[0]
    for decoded, fixture in zip(prototype.constants, EXTREME_FIXTURES):
        assert isinstance(decoded, Constant)
        assert decoded.kind == "number"
        assert decoded.value == fixture.expected_value
        assert isinstance(decoded.raw_value, DecodedDoubleValue)
        assert decoded.raw_value.flags == fixture.expected_flags
        assert decoded.raw_value.raw_double == fixture.raw_double

    for decoded, fixture in zip(prototype.instructions[0], reversed(EXTREME_FIXTURES)):
        assert isinstance(decoded, DecodedDoubleValue)
        assert decoded.value == fixture.expected_value
        assert decoded.flags == fixture.expected_flags
        assert decoded.raw_double == fixture.raw_double


def test_unpacker_is_idempotent_and_preserves_metadata() -> None:
    chunk = _build_chunk_from_fixtures(EXTREME_FIXTURES)

    apply_double_constant_unpacker(chunk)
    first_pass_constants = list(chunk.prototypes[0].constants)

    apply_double_constant_unpacker(chunk)

    assert chunk.prototypes[0].constants == first_pass_constants
    for decoded, fixture in zip(chunk.prototypes[0].constants, EXTREME_FIXTURES):
        assert isinstance(decoded, Constant)
        assert decoded.raw_value.raw_double == fixture.raw_double


def test_chunk_builder_emits_decoded_doubles_with_expected_metadata() -> None:
    fixtures = [
        _make_fixture(1),
        _make_fixture(-1, flags=1),
        _make_fixture(123456789, flags=0x155),
    ]

    loader_ir = PrototypeLoaderIR(
        prototypes=[
            PrototypeIRPrototype(
                constants=tuple(fixture.raw_double for fixture in fixtures),
                instructions=tuple(),
                prototypes=tuple(),
            )
        ]
    )
    descriptor = SerializedChunkDescriptor(
        buffer_name="payload",
        initial_offset=4,
        helper_functions={},
    )

    chunk = build_serialized_chunk_model(
        descriptor,
        loader_ir,
        script_key="session",
    )

    decoded_constants = chunk.prototypes[0].constants
    assert len(decoded_constants) == len(fixtures)
    for decoded, fixture in zip(decoded_constants, fixtures):
        assert isinstance(decoded, Constant)
        assert decoded.kind == "number"
        assert decoded.value == fixture.expected_value
        assert isinstance(decoded.raw_value, DecodedDoubleValue)
        assert decoded.raw_value.flags == fixture.expected_flags
        assert decoded.raw_value.raw_double == fixture.raw_double


def test_unpacker_handles_duplicate_occurrences_without_state_leakage() -> None:
    fixture = _make_fixture(42, flags=7)
    chunk = SerializedChunk(
        descriptor=SerializedChunkDescriptor(
            buffer_name="payload",
            initial_offset=0,
            helper_functions={},
        ),
        prototypes=[
            SerializedPrototype(
                constants=[fixture.raw_double, fixture.raw_double],
                instructions=[[fixture.raw_double, fixture.raw_double]],
                prototypes=[
                    SerializedPrototype(
                        constants=[fixture.raw_double],
                        instructions=[],
                        prototypes=[],
                    )
                ],
            )
        ],
    )

    apply_double_constant_unpacker(chunk)

    root = chunk.prototypes[0]
    decoded_constants: List[Constant] = []
    decoded_constants.extend(root.constants)
    decoded_constants.append(root.prototypes[0].constants[0])

    for decoded in decoded_constants:
        assert isinstance(decoded, Constant)
        assert decoded.kind == "number"
        assert decoded.value == fixture.expected_value
        assert isinstance(decoded.raw_value, DecodedDoubleValue)
        assert decoded.raw_value.flags == fixture.expected_flags
        assert decoded.raw_value.raw_double == fixture.raw_double

    for operand in root.instructions[0]:
        assert isinstance(operand, DecodedDoubleValue)
        assert operand.value == fixture.expected_value
        assert operand.flags == fixture.expected_flags
        assert operand.raw_double == fixture.raw_double

