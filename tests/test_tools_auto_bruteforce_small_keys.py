import json
from pathlib import Path

import pytest

from src.decoders.initv4_prga import apply_prga
from src.tools.auto_bruteforce_small_keys import bruteforce_small_keys, main


@pytest.fixture()
def sample_payload(tmp_path: Path) -> Path:
    plain = b"local function demo() return 42 end\n"
    key = b"AB"
    encoded = apply_prga(plain, key, params={"variant": "initv4 default"})
    payload_path = tmp_path / "encoded.bin"
    payload_path.write_bytes(encoded)
    return payload_path


def test_requires_explicit_allow_flag(sample_payload: Path) -> None:
    payload = sample_payload.read_bytes()
    with pytest.raises(PermissionError):
        bruteforce_small_keys(payload, allow_bruteforce=False)


def test_bruteforce_recovers_expected_key(sample_payload: Path) -> None:
    payload = sample_payload.read_bytes()
    report = bruteforce_small_keys(
        payload,
        allow_bruteforce=True,
        alphabet="AB",
        max_length=2,
        max_tries=10,
        timeout=2.0,
        top=10,
    )
    assert report.total_attempts == 6
    best = max(report.attempts, key=lambda attempt: attempt.score)
    assert best.key == "AB"
    assert best.length == 2


def test_cli_creates_report(tmp_path: Path, sample_payload: Path, monkeypatch) -> None:
    output_dir = tmp_path / "reports"
    argv = [
        str(sample_payload),
        "--allow-bruteforce",
        "--alphabet",
        "AB",
        "--max-length",
        "2",
        "--max-tries",
        "10",
        "--output-dir",
        str(output_dir),
        "--candidate-name",
        "sample",
    ]

    # Ensure stdout writes do not pollute test output
    monkeypatch.setenv("PYTHONWARNINGS", "ignore")

    result = main(argv)
    assert result == 0

    output_file = output_dir / "sample.json"
    assert output_file.exists()
    data = json.loads(output_file.read_text(encoding="utf-8"))
    keys = [entry["key"] for entry in data["attempts"]]
    assert "AB" in keys
