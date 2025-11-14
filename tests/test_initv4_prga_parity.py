"""Parity tests for the initv4 PRGA pipeline."""

from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from lupa import LuaRuntime

from src.decoders.initv4_prga import apply_prga, _rol8 as prga_rol8, _ror8 as prga_ror8
from src.decoders.lph85 import decode_lph85
from src.decoders.lph_reverse import _rol8 as lph_rol8, _ror8 as lph_ror8
from src.tools.parity_test import _bruteforce_small_keys


REPO_ROOT = Path(__file__).resolve().parents[1]
INITV4_PATH = REPO_ROOT / "initv4.lua"
LUA_REF_PATH = REPO_ROOT / "lua" / "initv4_prga_ref.lua"
SCRIPT_KEY = "zkzhqwk4b58pjnudvikpf"


def _u32_le_chunks(data: bytes, n_words: int) -> list[int]:
    if len(data) < n_words * 4:
        raise ValueError("buffer shorter than requested number of words")
    fmt = "<" + "I" * n_words
    return list(struct.unpack(fmt, data[: n_words * 4]))


def _load_lua_ref():
    lua = LuaRuntime(unpack_returned_tuples=True)
    source = LUA_REF_PATH.read_text(encoding="utf-8")
    lua.execute(source)
    module = lua.eval("initv4_prga_ref")
    if module is None:
        raise AssertionError("failed to load initv4_prga_ref module")
    return module


def _extract_lph_sample(n_bytes: int) -> bytes:
    text = INITV4_PATH.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r"LPH![!-~]{40,}", text)
    if not match:
        raise AssertionError("failed to locate LPH payload in initv4.lua")
    decoded = decode_lph85(match.group(0))
    if len(decoded) < n_bytes:
        raise AssertionError("decoded LPH sample shorter than requested size")
    return decoded[:n_bytes]


def _assert_byte_parity(py_bytes: bytes, lua_bytes: bytes) -> None:
    if len(py_bytes) != len(lua_bytes):
        raise AssertionError(
            f"Length mismatch: py={len(py_bytes)} bytes lu={len(lua_bytes)} bytes"
        )

    for index, (py_val, lua_val) in enumerate(zip(py_bytes, lua_bytes)):
        if py_val != lua_val:
            start = max(0, index - 8)
            end = min(len(py_bytes), index + 9)
            context_py = py_bytes[start:end].hex()
            context_lu = lua_bytes[start:end].hex()
            raise AssertionError(
                "Mismatch at byte {idx}: py={py:02x} lu={lu:02x}\n"
                "py[{start}:{end}]: {py_ctx}\n"
                "lu[{start}:{end}]: {lu_ctx}".format(
                    idx=index,
                    py=py_val,
                    lu=lua_val,
                    start=start,
                    end=end,
                    py_ctx=context_py,
                    lu_ctx=context_lu,
                )
            )


def test_prga_parity_byte_exact() -> None:
    lua_module = _load_lua_ref()
    apply_lua = lua_module["apply_prga_ref"]

    decoded_lph = _extract_lph_sample(n_bytes=128)
    key = SCRIPT_KEY.encode("utf-8")

    py_bytes = apply_prga(decoded_lph, key)
    lua_bytes = apply_lua(decoded_lph, key)

    _assert_byte_parity(py_bytes, lua_bytes)

    n_words = 16
    py_u32 = _u32_le_chunks(py_bytes, n_words)
    lua_u32 = _u32_le_chunks(lua_bytes, n_words)
    assert py_u32 == lua_u32, (
        "Endianness/word mismatch in first {n} u32s:\npy={py}\nlu={lu}".format(
            n=n_words, py=py_u32, lu=lua_u32
        )
    )


def _apply_prga_alt_reference(decoded_lph: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must be non-empty")
    total = len(decoded_lph)
    key_len = len(key)
    out = bytearray(total)
    for index in range(total):
        key_byte = key[index % key_len]
        mask = ((key_byte << 1) | (key_byte >> 7)) & 0xFF
        permuted_index = (index ^ mask) % total if total else index
        permuted_value = decoded_lph[permuted_index]
        xored = permuted_value ^ mask
        rotation = ((key_byte >> 1) ^ index) & 7
        out[index] = prga_rol8(xored, rotation)
    return bytes(out)


@pytest.fixture(scope="module")
def lua_bit32() -> dict:
    runtime = LuaRuntime(unpack_returned_tuples=True)
    return runtime.eval("bit32")


def _lua_ror_byte(lua_bit32: dict, value: int, rotation: int) -> int:
    word = (value & 0xFF) * 0x01010101
    rotated = lua_bit32["rrotate"](word, rotation)
    return rotated & 0xFF


def _lua_rol_byte(lua_bit32: dict, value: int, rotation: int) -> int:
    word = (value & 0xFF) * 0x01010101
    rotated = lua_bit32["lrotate"](word, rotation)
    return rotated & 0xFF


@pytest.mark.parametrize(
    "byte_sequence",
    [
        bytes([0x00, 0x01, 0x7F, 0x80]),
        bytes([0x80, 0x7F, 0x01, 0x00]),
        bytes([0xF3, 0x80, 0xFF, 0x01]),
    ],
)
@pytest.mark.parametrize("rotation", range(8))
def test_byte_rotations_match_lua_bit32(
    lua_bit32: dict, byte_sequence: bytes, rotation: int
) -> None:
    for value in byte_sequence:
        expected_r = _lua_ror_byte(lua_bit32, value, rotation)
        expected_l = _lua_rol_byte(lua_bit32, value, rotation)

        assert expected_r == prga_ror8(value, rotation)
        assert expected_r == lph_ror8(value, rotation)
        assert expected_l == lph_rol8(value, rotation)


def test_prga_alt_variant_matches_reference() -> None:
    decoded_lph = _extract_lph_sample(n_bytes=96)
    key = SCRIPT_KEY.encode("utf-8")

    py_bytes = apply_prga(decoded_lph, key, params={"variant": "initv4 alt"})
    reference_bytes = _apply_prga_alt_reference(decoded_lph, key)

    assert py_bytes == reference_bytes


def test_apply_prga_rejects_config_key_source() -> None:
    payload = bytes(range(8))
    with pytest.raises(ValueError, match="refuses to read keys"):
        apply_prga(payload, b"k", params={"key_path": "./secret"})


def test_apply_prga_rejects_long_keys() -> None:
    payload = bytes(range(4))
    long_key = b"A" * 513
    with pytest.raises(ValueError, match="exceeds 512-byte"):
        apply_prga(payload, long_key)


def test_apply_prga_debug_stage_dumps(tmp_path: Path) -> None:
    payload = bytes(range(16))
    key = b"key"

    result = apply_prga(payload, key, params={"debug": True, "debug_dir": tmp_path})
    assert result

    stage_dir = tmp_path / "initv4"
    assert stage_dir.is_dir()

    stages = sorted(stage_dir.glob("initv4_stage*.bin"))
    assert stages, "debug mode should emit stage files"

    stage_data = {path.name: path.read_bytes() for path in stages}
    assert stage_data.get("initv4_stage0.bin") == payload
    final_stage = stage_data.get("initv4_stage3.bin")
    assert final_stage == result
    for blob in stage_data.values():
        assert len(blob) == len(payload)


def test_bruteforce_small_key_discovers_match() -> None:
    decoded = bytes(range(16))
    true_key = b"\x05"

    def lua_apply(payload: str, key: str) -> bytes:
        payload_bytes = payload.encode("latin1")
        key_bytes = key.encode("latin1")
        reference_key = true_key
        reference_bytes = apply_prga(payload_bytes, reference_key)
        if key_bytes == reference_key:
            return reference_bytes
        # Simulate a mismatched configuration by perturbing the output when the
        # probed key differs from the reference key.
        perturbed = bytearray(reference_bytes)
        if perturbed:
            perturbed[0] ^= 0xFF
        return bytes(perturbed)

    outcome = _bruteforce_small_keys(
        decoded,
        decoded.decode("latin1"),
        lua_apply,
        params=None,
        limit=16,
        max_attempts=64,
        key_lengths=[1],
        skip_keys=(),
    )

    assert outcome.success is True
    assert outcome.best_prefix == 16
    assert outcome.best_key_length == len(true_key)

