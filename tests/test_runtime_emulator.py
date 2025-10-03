import pytest

from src.runtime_capture.emulator import EmulationRequest, emulate_decoder


def test_emulator_xor_loop():
    pytest.importorskip("unicorn")
    code = bytes.fromhex("300648ffc6e2f9c3")
    plaintext = b"hello world"
    key = 0x55
    encoded = bytes(byte ^ key for byte in plaintext)
    request = EmulationRequest(
        code=code,
        capture_address=0x400000,
        capture_size=len(encoded),
        base_address=0x1000,
        stack_address=0x200000,
        prefill=encoded,
        initial_registers={
            "RSI": 0x400000,
            "RCX": len(encoded),
            "RAX": key,
        },
    )
    result = emulate_decoder(request)
    decoded = bytes(byte ^ key for byte in result.buffer[: len(encoded)])
    assert decoded == plaintext
