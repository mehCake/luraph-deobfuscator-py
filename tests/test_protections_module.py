import zlib

from src import protections


def _collect_types(findings):
    return {entry["type"] for entry in findings}


def test_single_byte_xor_detection():
    plaintext = b"function test() return 1 end"
    encoded = bytes(byte ^ 0x5A for byte in plaintext)
    findings = protections.analyse_protections([
        protections.BufferObservation(data=encoded, label="xor")
    ])
    types = _collect_types(findings)
    assert "xor" in types


def test_repeating_xor_detection():
    key = b"ABC"
    data = b"local script_key = 'value'"
    encoded = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    findings = protections.analyse_protections([
        protections.BufferObservation(data=encoded, label="repeating")
    ])
    types = _collect_types(findings)
    assert "repeating_xor" in types


def test_compression_detection():
    payload = zlib.compress(b"return function() return 42 end")
    findings = protections.analyse_protections([
        protections.BufferObservation(data=payload, label="compressed")
    ])
    types = _collect_types(findings)
    assert "compression" in types
