"""Regression tests for the v14.3 serialized constant parsing helpers."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Tuple

import pytest

from pattern_analyzer import Constant
from src.versions import v14_3_loader
from src.versions.v14_3_writer_sim import simulate_v14_3_writer


DOUBLE_PREFIX_MASK = v14_3_loader.DOUBLE_PREFIX_MASK
DOUBLE_ENCODED_PREFIX = v14_3_loader.DOUBLE_ENCODED_PREFIX


def _load_native_chunk() -> Tuple[v14_3_loader.SerializedChunk, bytes]:
    snapshot = simulate_v14_3_writer()
    data = snapshot["buf"]
    chunk = v14_3_loader.decode_v14_3_chunk(data)
    assert chunk.prototypes, "expected decoded chunk to expose prototypes"
    return chunk, data


def _load_native_prototype():
    chunk, _ = _load_native_chunk()
    return chunk.prototypes[0]


def _load_obfuscated4_prototype(*, attach_re_probes: bool = False):
    source = Path("Obfuscated4.lua").read_text(encoding="utf-8", errors="ignore")
    descriptor, data = v14_3_loader.extract_v14_3_serialized_chunk_bytes_from_source(
        source
    )
    chunk = v14_3_loader.build_v14_3_serialized_chunk_from_bytes(
        descriptor,
        data,
        attach_re_probes=attach_re_probes,
        allow_re_fallback=attach_re_probes,
    )
    assert chunk.prototypes, "expected decoded chunk to expose prototypes"
    return chunk.prototypes[0]


def _constant_value(candidate: Constant | object) -> object:
    if isinstance(candidate, Constant):
        return candidate.value
    return candidate


def _looks_like_packed_double(candidate: Constant | object) -> bool:
    value = _constant_value(candidate)
    if not isinstance(value, float):
        return False
    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    return (bits & DOUBLE_PREFIX_MASK) == DOUBLE_ENCODED_PREFIX


def _iter_constants(constants: Iterable[Constant]) -> Iterable[Constant]:
    for entry in constants:
        assert isinstance(entry, Constant)
        yield entry


def test_v14_3_constants_are_decoded_from_obfuscated4() -> None:
    prototype = _load_obfuscated4_prototype()
    constants = list(_iter_constants(prototype.constants))
    assert constants, "expected the serialized chunk to expose at least one constant"

    expected_count = getattr(prototype, "serialized_constant_count", None)
    assert expected_count >= len(constants)

    kinds = {constant.kind for constant in constants}
    assert "bytes" in kinds

    for constant in constants:
        assert constant.kind in {"nil", "boolean", "number", "string", "bytes"}
        assert not _looks_like_packed_double(constant)



def test_v14_3_native_payload_decodes_constants() -> None:
    prototype = _load_native_prototype()
    constants = list(_iter_constants(prototype.constants))
    assert constants, "real payload should expose decoded constants"

    placeholder_roles = {"raw_blob", "header_probe", "constants_probe", "decoder_error"}
    assert all(
        constant.metadata.get("role") not in placeholder_roles
        for constant in constants
        if isinstance(constant.metadata, dict)
    ), "decoded constants should not include RE placeholders"

    kinds = {constant.kind for constant in constants}
    assert kinds & {"number", "string", "bytes"}, "expected diverse constant kinds"


def test_v14_3_obfuscated4_payload_can_attach_re_probes() -> None:
    prototype = _load_obfuscated4_prototype(attach_re_probes=True)
    constants = list(_iter_constants(prototype.constants))
    roles = {
        constant.metadata.get("role")
        for constant in constants
        if isinstance(constant.metadata, dict)
    }
    assert {"raw_blob", "header_probe", "constants_probe"} <= roles


def test_v14_3_obfuscated4_payload_decodes_without_re_probes() -> None:
    prototype = _load_obfuscated4_prototype()
    constants = list(_iter_constants(prototype.constants))
    assert constants, "obfuscated4 chunk should expose decoded constants"

    placeholder_roles = {"raw_blob", "header_probe", "constants_probe", "decoder_error"}
    for constant in constants:
        metadata = constant.metadata or {}
        assert metadata.get("role") not in placeholder_roles
        assert not _looks_like_packed_double(constant)

def _constant_matches_tag(constant: Constant, tag: int) -> bool:
    if tag == 0x01:
        return constant.kind == "nil"
    if tag == 0x02:
        return constant.kind == "boolean"
    if tag == 0x03:
        return constant.kind == "number" and isinstance(constant.value, int)
    if tag == 0x04:
        return constant.kind == "number" and isinstance(constant.value, float)
    if tag == 0x05:
        return constant.kind == "string"
    if tag == 0x06:
        return constant.kind == "bytes" and isinstance(constant.value, (bytes, bytearray))
    if tag in v14_3_loader._OPAQUE_CONSTANT_TAGS:  # type: ignore[attr-defined]
        metadata = constant.metadata or {}
        return metadata.get("v14_3_tag") == f"0x{tag:02x}"
    return False


def test_v14_3_native_payload_covers_all_constant_tags() -> None:
    chunk, data = _load_native_chunk()
    prototype = chunk.prototypes[0]
    constants = list(_iter_constants(prototype.constants))
    summary = v14_3_loader.scan_v14_3_constant_tags(data)

    missing_tags = []
    for tag in summary["unique_tags"]:
        if any(_constant_matches_tag(constant, tag) for constant in constants):
            continue
        missing_tags.append(tag)

    assert not missing_tags, f"decoder failed to expose constants for tags: {missing_tags}"
