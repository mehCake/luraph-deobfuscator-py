"""Verifiers that ensure the v14.3 spec/decoder stay aligned."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest

from pattern_analyzer import Constant
from src.versions import v14_3_loader
from src.versions.v14_3_writer_sim import (
    PrototypeSpec,
    simulate_v14_3_writer,
)


def _collect_constant_values(prototype):
    values = []
    for constant in prototype.constants:
        assert isinstance(constant, Constant)
        values.append((constant.kind, constant.value))
    return values


def _iter_constants(prototype) -> Iterable[Constant]:
    for constant in prototype.constants:
        assert isinstance(constant, Constant)
        yield constant


def _load_native_chunk():
    snapshot = simulate_v14_3_writer()
    chunk = v14_3_loader.decode_v14_3_chunk(snapshot["buf"])
    assert chunk.prototypes, "expected decoded chunk to expose prototypes"
    return chunk


def _load_obfuscated4_payload() -> bytes:
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    descriptor, data = v14_3_loader.extract_v14_3_serialized_chunk_bytes_from_source(
        source
    )
    assert descriptor.initial_offset >= 0
    assert descriptor.initial_offset < len(data)
    return data[descriptor.initial_offset :]
SIMULATED_SPEC = PrototypeSpec(
    constants=(
        {"kind": "nil"},
        {"kind": "boolean", "value": False},
        {"kind": "integer", "value": -13},
        {"kind": "double", "value": 6.5},
        {"kind": "string", "value": "simulated"},
        {"kind": "bytes", "value": b"\x99"},
    ),
    instructions=(b"\xaa\xbb",),
    children=(
        PrototypeSpec(
            constants=(
                {"kind": "integer", "value": 1024},
            ),
            instructions=(),
            children=(),
        ),
    ),
)


def test_simulated_writer_buffer_round_trips_through_decoder() -> None:
    snapshot = simulate_v14_3_writer([SIMULATED_SPEC])
    chunk = v14_3_loader.decode_v14_3_chunk(snapshot["buf"])
    assert len(chunk.prototypes) == 1

    prototype = chunk.prototypes[0]
    values = _collect_constant_values(prototype)
    assert values == [
        ("nil", None),
        ("boolean", False),
        ("number", -13),
        ("number", 6.5),
        ("string", "simulated"),
        ("bytes", b"\x99"),
    ]

    assert len(prototype.instructions) == 1
    assert bytes(prototype.instructions[0]) == b"\xaa\xbb"

    assert len(prototype.prototypes) == 1
    child = prototype.prototypes[0]
    assert _collect_constant_values(child) == [("number", 1024)]


def test_native_payload_decodes_without_placeholders() -> None:
    chunk = _load_native_chunk()
    prototype = chunk.prototypes[0]

    constants = list(_iter_constants(prototype))
    assert constants, "expected decoded constants for native payload"

    placeholder_roles = {"raw_blob", "header_probe", "constants_probe", "decoder_error"}
    roles = {
        constant.metadata.get("role")
        for constant in constants
        if isinstance(constant.metadata, dict)
    }
    assert not (roles & placeholder_roles), "native payload should not expose RE placeholders"

    kinds = {constant.kind for constant in constants}
    assert kinds & {"number", "string", "bytes"}, "expected decoded constants"

    expected_count = getattr(prototype, "serialized_constant_count", len(constants))
    assert expected_count == len(constants), "constant count mismatch"


def test_obfuscated4_payload_parses_natively() -> None:
    payload = _load_obfuscated4_payload()

    chunk = v14_3_loader._parse_real_serialized_chunk(payload)  # type: ignore[attr-defined]
    assert chunk.prototypes, "expected native parser to expose prototypes"

    prototype = chunk.prototypes[0]
    constants = list(_iter_constants(prototype))
    assert constants, "obfuscated4 payload should expose decoded constants"

    placeholder_roles = {"raw_blob", "header_probe", "constants_probe", "decoder_error"}
    assert not any(
        isinstance(constant.metadata, dict)
        and constant.metadata.get("role") in placeholder_roles
        for constant in constants
    ), "native parser should not emit RE placeholder constants"

    kinds = {constant.kind for constant in constants}
    assert kinds & {"number", "string", "bytes"}, "expected diverse constant kinds"
