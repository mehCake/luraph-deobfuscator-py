import json
from pathlib import Path

import pytest

from src.tools.fuzzy_param_search import FuzzyCandidate, guided_search, main as fuzzy_main, score_payload


def _obfuscate(payload: bytes, *, rotation: int, block_size: int, block_shift: int, xor_seed: int) -> bytes:
    mask = bytes(((xor_seed & 0xFF) + index) & 0xFF for index in range(len(payload)))
    stage = bytes(byte ^ mask_byte for byte, mask_byte in zip(payload, mask))

    if block_size > 1 and len(stage) >= block_size:
        buffer = bytearray(stage)
        shift = block_shift % block_size
        if shift:
            for offset in range(0, len(buffer), block_size):
                block = buffer[offset : offset + block_size]
                if len(block) < block_size:
                    break
                rotated = block[-shift:] + block[:-shift]
                buffer[offset : offset + block_size] = rotated
        stage = bytes(buffer)

    if rotation % 8:
        amount = rotation % 8
        stage = bytes(((byte >> amount) | ((byte << (8 - amount)) & 0xFF)) & 0xFF for byte in stage)

    return stage


def test_guided_search_finds_expected_candidate():
    plaintext = (
        "local function demo(a, b)\n" "    if a > b then\n" "        return a\n" "    end\n" "end\n"
    ).encode("utf-8")

    rotation = 2
    block_size = 4
    block_shift = 1
    xor_seed = 5

    obfuscated = _obfuscate(
        plaintext,
        rotation=rotation,
        block_size=block_size,
        block_shift=block_shift,
        xor_seed=xor_seed,
    )

    results = guided_search(
        obfuscated,
        key=None,
        variants=("initv4 default",),
        rotations=(0, rotation),
        block_sizes=(1, block_size),
        block_shifts=(0, 1, 2),
        xor_seeds=tuple(range(0, 8)),
        max_tries=120,
        timeout=2.0,
        top=5,
    )

    assert results, "expected at least one candidate"
    best = results[0]
    assert isinstance(best.candidate, FuzzyCandidate)
    assert best.candidate.rotation_adjust == rotation
    assert best.candidate.block_size == block_size
    assert best.candidate.block_shift == block_shift
    assert best.candidate.xor_seed == xor_seed
    assert best.score > 0.8
    assert best.ascii_ratio > 0.9
    assert best.token_ratio > 0.3


def test_guided_search_respects_max_tries():
    payload = bytes(range(64))
    results = guided_search(
        payload,
        rotations=(0, 1, 2),
        block_sizes=(1, 2),
        block_shifts=(0, 1),
        xor_seeds=(0, 1, 2, 3),
        max_tries=3,
        timeout=5.0,
        top=10,
    )
    assert results
    assert all(result.attempt <= 3 for result in results)


def test_cli_writes_results(tmp_path: Path):
    payload = b"return 1\n"
    payload_path = tmp_path / "payload.bin"
    payload_path.write_bytes(payload)

    output_path = tmp_path / "candidates.json"

    exit_code = fuzzy_main(
        [
            str(payload_path),
            "--max-tries",
            "4",
            "--timeout",
            "1",
            "--top",
            "2",
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    assert output_path.is_file()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert data, "expected at least one candidate"
    assert all("score" in entry for entry in data)


@pytest.mark.parametrize(
    "payload",
    [
        b"local x=1",
        b"\x00\x01\x02",
    ],
)
def test_score_payload_returns_expected_shape(payload: bytes):
    score, ascii_ratio, token_ratio, lua_density = score_payload(payload)
    assert 0.0 <= score <= 1.0
    assert 0.0 <= ascii_ratio <= 1.0
    assert 0.0 <= token_ratio <= 1.0
    assert lua_density >= 0.0
