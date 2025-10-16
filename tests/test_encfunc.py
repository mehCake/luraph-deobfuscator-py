import hashlib
import json

from src.lifter.encfunc import rehydrate_encfunc
from src.lifter.lifter import lift_program


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


def test_rehydrate_encfunc_digest_matches_plaintext_proto():
    proto = {
        "instructions": [
            {"pc": 0, "mnemonic": "LOADK", "A": 0, "Bx": 0},
            {"pc": 1, "mnemonic": "CALL", "A": 0, "B": 1, "C": 1},
            {"pc": 2, "mnemonic": "RETURN", "A": 0, "B": 2},
        ],
        "constants": ["hello"],
        "prototypes": [],
        "upvalues": [
            {"type": "upvalue", "index": 0},
            {"type": "register", "index": 1},
        ],
    }
    plain = json.dumps(proto).encode("utf-8")
    key = b"jqufagtci8ln9080bgars"
    blob = _xor_encrypt(plain, key)

    result = rehydrate_encfunc(blob, key, "xor")

    assert result.proto is not None
    digest = result.metadata.get("rehydration_digest")
    assert digest

    lift_output = lift_program(
        result.proto.get("instructions", []),
        result.proto.get("constants", []),
        {},
        prototypes=result.proto.get("prototypes", []),
    )
    assert lift_output.lua_source

    control_output = lift_program(
        proto["instructions"],
        proto["constants"],
        {},
        prototypes=proto.get("prototypes", []),
    )
    assert control_output.lua_source

    control_digest = hashlib.sha1(
        f"{len(proto['instructions'])}|{len(proto['constants'])}|{len(proto['upvalues'])}".encode("ascii")
    ).hexdigest()

    assert digest == control_digest
