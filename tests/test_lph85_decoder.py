from pathlib import Path

import pytest

from src.bootstrap.lph_scan import scan_lph_blocks
from src.decoders.lph85 import decode_lph85
from src.main import _candidate_script_keys, _DEFAULT_TEST_KEYS


@pytest.mark.parametrize(
    "path,prefix,expected_words",
    [
        (
            Path("initv4.lua"),
            "LPH!",
            [0x920700BA, 0xC07DEA2B, 0xFFFFFFFF, 0x480171BA],
        ),
        (
            Path("Obfuscated.json"),
            "LPH~",
            [0xA2930400, 0x35014710, 0x00000040, 0x9C436041],
        ),
    ],
)
def test_decode_lph85_words(path: Path, prefix: str, expected_words: list[int]) -> None:
    text = path.read_text("utf-8", errors="ignore")
    blocks = [block for block in scan_lph_blocks(text, source=str(path)) if block.header.startswith(prefix)]
    assert blocks, f"expected at least one block starting with {prefix}"
    payload = decode_lph85(blocks[0].text)
    assert len(payload) >= 16
    words = [int.from_bytes(payload[i : i + 4], "big") for i in range(0, 16, 4)]
    assert words == expected_words


def test_lph85_output_is_non_trivial(tmp_path: Path) -> None:
    sample = "LPH!" + "!" * 15
    result = decode_lph85(sample)
    assert result == b"\x00\x00\x00\x00" * 3

    noisy = "LPH~" + "!!!??@ABCDE"
    output = decode_lph85(noisy)
    assert output.startswith(b"\x00\x00") is True


def test_candidate_script_keys_detects_contextual_tokens() -> None:
    text = (
        "--[[\n"
        "local payload = [=[LPH!ABCDE]=]\n"
        "local key = 'koqzpaexlygm9b227uy'\n"
        "]=]"
    )
    candidates = _candidate_script_keys(text)
    assert candidates
    assert candidates[0] == "koqzpaexlygm9b227uy"
    assert _DEFAULT_TEST_KEYS[0] in candidates
