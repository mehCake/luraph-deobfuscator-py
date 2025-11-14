"""Tests for heuristic helpers."""

from __future__ import annotations

import binascii
import zlib

from src.tools.heuristics import (
    ChecksumResult,
    HeuristicSignal,
    detect_checksums,
    detect_endianness,
    detect_vm_style,
    likely_lph_variant,
    looks_like_perm_table,
    looks_like_prga,
    looks_like_vm_dispatch,
)
from src.tools.parser_tracer import TransformOperation
from src.vm.disassembler import Instruction


def test_detect_endianness_big_sequence() -> None:
    payload = bytes(range(1, 65))
    endianness, score = detect_endianness(payload)
    assert endianness == "big"
    assert score >= 0.5


def test_detect_endianness_little_sequence() -> None:
    payload = b"\x04\x03\x02\x01" * 20
    endianness, score = detect_endianness(payload)
    assert endianness == "little"
    assert score >= 0.5


def test_detect_endianness_unknown_for_noise() -> None:
    payload = bytes([0x5A, 0x10, 0xE3, 0x7C] * 12)
    endianness, score = detect_endianness(payload)
    assert endianness == "unknown"
    assert score == 0.0


def test_detect_checksums_crc32_big_endian() -> None:
    body = b"checksum-test" * 3
    crc = zlib.crc32(body) & 0xFFFFFFFF
    payload = body + crc.to_bytes(4, "big")
    results = detect_checksums(payload)
    assert any(result.name == "crc32-be" and result.valid for result in results)


def test_detect_checksums_crc16_little_endian() -> None:
    body = bytes(range(40))
    crc16 = binascii.crc_hqx(body, 0)
    payload = body + crc16.to_bytes(2, "little")
    results = detect_checksums(payload)
    assert any(result.name == "crc16-le" and result.valid for result in results)


def test_detect_checksums_simple_sum_and_xor() -> None:
    body = bytes(range(1, 64))
    sum_payload = body + bytes([sum(body) & 0xFF])
    xor_payload = body + bytes([_xor(body)])
    sum_results = detect_checksums(sum_payload)
    xor_results = detect_checksums(xor_payload)
    assert any(result.name == "sum8" and result.valid for result in sum_results)
    assert any(result.name == "xor8" and result.valid for result in xor_results)


def test_detect_checksums_reports_mismatch() -> None:
    body = b"checksum-test" * 2
    crc = zlib.crc32(body) & 0xFFFFFFFF
    expected = crc.to_bytes(4, "big")
    mutated = expected[:-1] + bytes([(expected[-1] + 1) % 256])
    payload = body + mutated
    results = detect_checksums(payload)
    assert any(
        isinstance(result, ChecksumResult)
        and result.name.startswith("crc32")
        and not result.valid
        for result in results
    )


def test_detect_vm_style_register_bias() -> None:
    instructions = [
        Instruction(index=i, raw=0, opcode=0, a=10 + i, b=(i * 3) % 50, c=(i * 5) % 60)
        for i in range(24)
    ]
    score = detect_vm_style(instructions)
    assert score.style == "register"
    assert score.confidence >= 0.4
    assert score.max_operand >= 40


def test_detect_vm_style_stack_bias() -> None:
    pattern = [0, 1, 2, 1]
    instructions = [
        Instruction(index=i, raw=0, opcode=1, a=pattern[i % len(pattern)], b=0, c=1)
        for i in range(32)
    ]
    score = detect_vm_style(instructions)
    assert score.style == "stack"
    assert score.confidence >= 0.4
    assert score.max_operand <= 3


def test_looks_like_prga_detects_rotate_and_xor() -> None:
    operations = [
        TransformOperation(type="rotate", offset=0, source="bit32.lrotate(x, 11)", args={"bits": "11"}),
        TransformOperation(type="xor", offset=12, source="bit32.bxor(a, b)", args={}),
        TransformOperation(type="permute", offset=24, source="permute(state)", args={}),
        TransformOperation(type="mask", offset=36, source="bit32.band(v, 0xff)", args={}),
    ]
    signal = looks_like_prga(operations)
    assert isinstance(signal, HeuristicSignal)
    assert signal.confidence >= 0.7
    assert signal.version_hint == "v14.4.2"
    assert any("rotate amounts" in note for note in signal.reasons)


def test_looks_like_perm_table_scores_contiguous_range() -> None:
    table = list(range(256))
    signal = looks_like_perm_table(table)
    assert signal.confidence > 0.7
    assert signal.version_hint == "v14.4.1"
    assert "all entries unique" in signal.reasons[-1]


def test_looks_like_vm_dispatch_detects_if_chain() -> None:
    snippet = """
    while true do
        if opcode == 3 then handler_a()
        elseif opcode == 5 then handler_b()
        elseif opcode == 7 then handler_c()
        end
    end
    """
    signal = looks_like_vm_dispatch(snippet)
    assert signal.confidence >= 0.6
    assert signal.version_hint == "v14.4.2"
    assert any("opcode equality" in reason for reason in signal.reasons)


def test_likely_lph_variant_prefers_v1442_signatures() -> None:
    observations = {
        "rotate_amounts": [11, 13],
        "permute_block": 512,
        "endianness": "little",
    }
    signal = likely_lph_variant(observations)
    assert signal.version_hint == "v14.4.2"
    assert signal.confidence >= 0.7
    assert any("0x200" in reason or "512" in reason for reason in signal.reasons)


def _xor(data: bytes) -> int:
    value = 0
    for byte in data:
        value ^= byte
    return value
