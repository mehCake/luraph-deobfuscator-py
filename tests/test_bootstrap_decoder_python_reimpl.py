"""Unit tests covering the pure-Python bootstrap decoder pipeline."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from src.bootstrap_decoder import BootstrapDecoder


def _encode_initv4_like(payload: bytes, alphabet: str, key: bytes) -> bytes:
    """Produce a blob using the inverse of the Python decode pipeline.

    The Python implementation in :mod:`src.bootstrap_decoder` applies the
    operations in the order ``alphabet map`` -> ``key xor`` -> ``index xor``
    when it successfully decodes initv4 blobs.  Because XOR is its own
    inverse we can reapply the same transforms in reverse order to obtain a
    stable encoded form for tests.
    """

    out = bytearray(payload)
    for index in range(len(out)):
        out[index] ^= index & 0xFF
    if key:
        key_len = len(key)
        for index in range(len(out)):
            out[index] ^= key[index % key_len]
    alphabet_len = len(alphabet)
    encoded = bytearray()
    for value in out:
        if value >= alphabet_len:
            raise ValueError("value outside alphabet range")
        encoded.append(ord(alphabet[value]))
    return bytes(encoded)


def test_python_reimpl_decodes_known_vector(tmp_path: Path) -> None:
    """The Python heuristics should decode a simple initv4-style payload."""

    alphabet = "".join(chr(i) for i in range(256))
    key = b"initv4-test-key"
    original = b"local function decoded()\n    return 'ok'\nend\n"
    blob = _encode_initv4_like(original, alphabet, key)

    bootstrap_path = tmp_path / "bootstrap.lua"
    bootstrap_path.write_text("return 0\n", encoding="utf-8")

    ctx = SimpleNamespace(debug_bootstrap=False, logs_dir=tmp_path / "logs")
    decoder = BootstrapDecoder(ctx, str(bootstrap_path), key.decode("ascii"))
    decoder._candidate_alphabets = [alphabet]

    result = decoder.python_reimpl_decode(blob)

    assert result.success, f"python pipeline failed: {result.notes}"
    assert result.decoded == original
    assert "pipeline" in " ".join(result.notes)

