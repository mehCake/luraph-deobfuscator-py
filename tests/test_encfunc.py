from src.lifter.encfunc import rehydrate_encfunc


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes((byte ^ key[i % key_len]) & 0xFF for i, byte in enumerate(data))


def test_rehydrate_encfunc_xor_lua_source():
    plain = b"function decrypted() return 123 end"
    key = b"\x10\x20\x30"
    blob = _xor_encrypt(plain, key)

    result = rehydrate_encfunc(blob, key, "xor")

    assert result.lua_source is not None
    assert "return 123" in result.lua_source
    assert result.recovery_method.lower() == "xor"
    assert result.confidence == "high"
    assert "xor" in [method.lower() for method in result.metadata.get("attempted_methods", [])]
