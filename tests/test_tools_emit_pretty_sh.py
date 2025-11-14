import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path("src/tools/emit_pretty.sh")


@pytest.mark.skipif(not SCRIPT.exists(), reason="emit_pretty.sh script missing")
def test_emit_pretty_pipeline(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    unpacked = {
        "array": [
            None,
            None,
            None,
            [
                {"opcode": 1, "A": 0, "B": 0, "C": 0},
                {"opcode": 3, "A": 0, "B": 0, "C": 0},
            ],
            ["hello", "world"],
        ]
    }
    unpacked_path = out_dir / "unpacked_dump.json"
    unpacked_path.write_text(json.dumps(unpacked), encoding="utf-8")

    const_dir = out_dir / "constants"
    const_dir.mkdir()
    constants_path = const_dir / "sample.json"
    constants_payload = {
        "candidate": "sample",
        "constants": ["hello", "world"],
        "stats": {"constant_count": 2},
    }
    constants_path.write_text(json.dumps(constants_payload), encoding="utf-8")

    profile_path = out_dir / "transform_profile.json"
    profile_path.write_text(
        json.dumps({"version": "1.0", "metadata": {"version_hint": "v14.4.2"}}),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(Path.cwd()))

    result = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--out-dir",
            str(out_dir),
            "--unpacked",
            str(unpacked_path),
            "--constants",
            str(constants_path),
            "--profile",
            str(profile_path),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )

    output_path = out_dir / "deobfuscated_pretty.lua"
    assert output_path.exists()
    text = output_path.read_text(encoding="utf-8")
    assert text.startswith("-- Licensed under the MIT License")
    assert "hello" in text
    assert "-- PROVENANCE" in text
    assert "Beautified pseudo-Lua written" in result.stdout
    assert (out_dir / "LICENSE").exists()


@pytest.mark.skipif(not SCRIPT.exists(), reason="emit_pretty.sh script missing")
def test_emit_pretty_respects_overwrite_guard(tmp_path):
    out_dir = tmp_path / "analysis"
    out_dir.mkdir()

    unpacked = {
        "array": [
            None,
            None,
            None,
            [
                {"opcode": 1, "A": 0, "B": 0, "C": 0},
            ],
            ["value"],
        ]
    }
    unpacked_path = out_dir / "unpacked_dump.json"
    unpacked_path.write_text(json.dumps(unpacked), encoding="utf-8")

    const_dir = out_dir / "constants"
    const_dir.mkdir()
    constants_path = const_dir / "sample.json"
    constants_path.write_text(json.dumps({"constants": ["value"]}), encoding="utf-8")

    env = os.environ.copy()
    env.setdefault("PYTHONPATH", str(Path.cwd()))

    cmd = [
        "bash",
        str(SCRIPT),
        "--out-dir",
        str(out_dir),
        "--unpacked",
        str(unpacked_path),
        "--constants",
        str(constants_path),
    ]

    subprocess.run(cmd, check=True, capture_output=True, text=True, env=env)

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert result.returncode != 0
    assert "Refusing to overwrite" in result.stderr
