import subprocess
import sys
from pathlib import Path

import pytest


SAMPLES = [
    Path("example_obfuscated.lua"),
    Path("examples/json_wrapped.lua"),
    Path("examples/complex_obfuscated"),
]


@pytest.mark.parametrize("sample", SAMPLES)
def test_cli_smoke(tmp_path, sample):
    out = tmp_path / "out.lua"
    artifacts = tmp_path / "artifacts"
    cmd = [sys.executable, "main.py", "-i", str(sample), "-o", str(out), "--write-artifacts", str(artifacts)]
    subprocess.check_call(cmd)
    text = out.read_text()
    assert text
    assert ("script_key" in text) or ("hello world" in text.lower())
    # ensure per-pass logs are written
    assert (artifacts / "detect.log").exists()
    assert (artifacts / "decode.log").exists()
