from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.tools.param_tuner import hill_climb_parameters, main as tuner_main


def _rotate_right(byte: int, amount: int) -> int:
    amount &= 7
    if amount == 0:
        return byte & 0xFF
    return ((byte >> amount) | ((byte << (8 - amount)) & 0xFF)) & 0xFF


def _obfuscate_payload(payload: bytes, *, rotation: int, block_size: int, block_shift: int) -> bytes:
    if block_size > 1 and len(payload) >= block_size:
        buffer = bytearray(payload)
        shift = block_shift % block_size
        if shift:
            for offset in range(0, len(buffer), block_size):
                block = buffer[offset : offset + block_size]
                if len(block) < block_size:
                    break
                rotated = block[shift:] + block[:shift]
                buffer[offset : offset + block_size] = rotated
        payload = bytes(buffer)

    if rotation % 8:
        payload = bytes(_rotate_right(byte, rotation) for byte in payload)
    return payload


def test_hill_climb_recovers_expected_parameters() -> None:
    plain = ("local function demo(a, b)\n" "    return a + b\n" "end\n").encode("utf-8")
    plain *= 16  # ensure we have enough data for the permutation

    rotation = 11
    block_size = 256
    block_shift = 3

    payload = _obfuscate_payload(plain, rotation=rotation, block_size=block_size, block_shift=block_shift)

    result = hill_climb_parameters(
        payload,
        version_hint="v14.4.2",
        seed=1234,
        max_iterations=24,
    )

    best = result.best
    assert best.candidate.rotate == rotation
    assert best.candidate.block_size in {256, 384, 512}
    assert 0 <= best.candidate.block_shift < best.candidate.block_size
    assert best.score > 0.5
    assert result.seed == 1234

    # Ensure the ground-truth candidate was explored during the search
    assert any(
        step.candidate.block_size == block_size and step.candidate.block_shift == block_shift
        for step in result.history
    )

    # Deterministic for the same seed
    repeat = hill_climb_parameters(payload, version_hint="v14.4.2", seed=1234, max_iterations=24)
    assert repeat.best.candidate == best.candidate
    assert repeat.best.score == pytest.approx(best.score, rel=1e-6)


def test_cli_requires_confirm(tmp_path: Path) -> None:
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(b"demo")

    with pytest.raises(SystemExit):
        tuner_main([str(payload_path)])


def test_cli_writes_output(tmp_path: Path) -> None:
    payload = b"return 1\n" * 32
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)

    output_path = tmp_path / "result.json"

    exit_code = tuner_main(
        [
            str(payload_path),
            "--confirm",
            "--output",
            str(output_path),
            "--max-iterations",
            "4",
            "--seed",
            "1",
        ]
    )

    assert exit_code == 0
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert "best" in data
    assert data["seed"] == 1
    assert data["iterations"] >= 1
