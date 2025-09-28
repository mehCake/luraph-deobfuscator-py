"""Unit tests for the LPH decoder helpers."""

from __future__ import annotations

import os

import pytest

from src.utils.lph_decoder import decode_lph_payload, parse_escaped_lua_string, try_xor


PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
INITV4_PATH = os.path.join(PROJECT_ROOT, "initv4.lua")


@pytest.mark.parametrize(
    "literal, expected_prefix",
    [
        ("\\57\\166\\86", b"9\xa6V"),
        ("3AF01", bytes.fromhex("AF AF AF 01".replace(" ", ""))),
        ("LPH!3AF01", bytes.fromhex("AF AF AF 01".replace(" ", ""))),
    ],
)
def test_parse_known_sequences(literal: str, expected_prefix: bytes) -> None:
    decoded = parse_escaped_lua_string(literal)
    assert decoded.startswith(expected_prefix)


def test_decode_lph_payload_repeater() -> None:
    payload = "LPH!2FF03AA01"
    decoded = decode_lph_payload(payload)
    expected = bytes.fromhex("FF FF AA AA AA 01")
    assert decoded == expected


def test_parse_initv4_payload_extracts_bytes() -> None:
    assert os.path.exists(INITV4_PATH), "initv4.lua fixture missing"
    with open(INITV4_PATH, "r", encoding="utf-8", errors="ignore") as handle:
        text = handle.read()
    marker = 'superflow_bytecode_ext0 = "'
    start = text.find(marker)
    assert start != -1, "expected superflow payload in initv4.lua"
    start += len(marker)
    end = text.find('"', start)
    raw_literal = text[start:end]
    decoded = parse_escaped_lua_string(raw_literal)
    assert isinstance(decoded, bytes)
    assert len(decoded) > 0


def test_try_xor_repeats_key() -> None:
    key = b"zkzhqwk4b58pjnudvikpf"
    data = bytes(range(16))
    result = try_xor(data, key)
    assert result != data
    assert try_xor(result, key) == data
