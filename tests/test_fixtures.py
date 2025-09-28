import os
import shutil
import subprocess

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def have_luajit():
    exe = shutil.which("luajit")
    return exe if exe else None


def test_min_fixture_lifter_runs():
    exe = have_luajit()
    if not exe:
        pytest.skip("luajit not installed; skipping lifter integration test")

    proc = subprocess.run(
        [exe, "tools/test_lifter_min.lua"],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Instructions:" in proc.stdout
    assert "OPCODES_SEEN=4" in proc.stdout
    assert "Unknown opcodes" in proc.stdout
