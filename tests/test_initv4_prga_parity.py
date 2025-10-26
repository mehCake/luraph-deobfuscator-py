"""Parity tests for the initv4 PRGA pipeline."""

from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

from lupa import LuaRuntime

from src.decoders.initv4_prga import apply_prga
from src.decoders.lph85 import decode_lph85
from utils import byte_diff


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
    diff = byte_diff(py_bytes, lua_bytes)
    if diff["match"]:
        return

    index = diff["index"]
    if index is None:
        index = 0
    a_len = diff["a_len"]
    b_len = diff["b_len"]
    start = max(0, index - 8)
    end = min(max(a_len, b_len), index + 9)
    raise AssertionError(
        "Mismatch at byte {idx}: py={py} lu={lu}\n"
        "py[{start}:{end}]: {py_ctx}\n"
        "lu[{start}:{end}]: {lu_ctx}".format(
            idx=index,
            py=f"{diff['a_byte']:02x}" if diff["a_byte"] is not None else "None",
            lu=f"{diff['b_byte']:02x}" if diff["b_byte"] is not None else "None",
            start=start,
            end=end,
            py_ctx=diff["a_context"],
            lu_ctx=diff["b_context"],
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

