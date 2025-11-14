from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.vm.disassembler import (
    DEFAULT_CONFIGS,
    analyse_disassembly,
    build_config_from_split,
)


def _pack(op: int, a: int, b: int, c: int) -> int:
    return op | (a << 8) | (b << 16) | (c << 24)


def _make_blob() -> bytes:
    words = [
        _pack(1, 2, 3, 4),
        _pack(5, 6, 7, 8),
        _pack(9, 10, 11, 12),
    ]
    return b"".join(word.to_bytes(4, "little") for word in words)


def test_default_profiles_have_valid_splits() -> None:
    for name, config in DEFAULT_CONFIGS.items():
        split = config.split_signature()
        assert sum(split) == config.word_size, f"profile {name} has inconsistent split"


def test_analyse_disassembly_prefers_correct_split() -> None:
    blob = _make_blob()
    configs = [
        ("correct", build_config_from_split((8, 8, 8, 8))),
        ("wrong", build_config_from_split((12, 10, 5, 5))),
    ]
    results = analyse_disassembly(blob, configs)
    assert results
    assert results[0].name == "correct"
    # Operand b should look constant-like because the values stay below 256.
    assert pytest.approx(results[0].operand_stats["b"].constant_ratio) == 1.0


def test_cli_generates_json_report(tmp_path: Path) -> None:
    blob_path = tmp_path / "payload.bin"
    blob_path.write_bytes(_make_blob())
    report_path = tmp_path / "report.json"

    cmd = [
        sys.executable,
        "-m",
        "src.vm.disassembler",
        str(blob_path),
        "--split",
        "8/8/8/8",
        "--json-out",
        str(report_path),
        "--top",
        "1",
    ]
    subprocess.run(cmd, check=True, capture_output=True)

    payload = json.loads(report_path.read_text(encoding="utf8"))
    assert payload
    assert payload[0]["split"] == [8, 8, 8, 8]
    assert payload[0]["operand_stats"]["opcode"]["distinct"] == 3
