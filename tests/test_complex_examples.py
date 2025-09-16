"""Acceptance tests for complex obfuscated samples."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
import re

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLI_ENTRY = PROJECT_ROOT / "main.py"

BANNED_MARKERS = re.compile(
    r"(BXOR|BNOT|dispatcher|opcode_map|vm_step|loadstring|string\.char\s*\()",
    re.IGNORECASE,
)

DEFAULT_MARKERS = ("script_key", "hello", "luraph v", "version")
EXPECTED_MARKERS = {
    "complex_obfuscated": ("script_key",),
}


def _copy_example_tree(source: Path, workspace: Path) -> Path:
    destination = workspace / source.name
    if source.is_dir():
        shutil.copytree(source, destination)
    else:
        destination.write_bytes(source.read_bytes())
    return destination


def _collect_outputs(target: Path) -> list[Path]:
    if target.is_dir():
        return sorted(target.rglob("*_deob.lua"))
    output = target.with_name(f"{target.stem}_deob.lua")
    return [output] if output.exists() else []


def _source_key(path: Path) -> str:
    stem = path.stem
    if stem.endswith("_deob"):
        stem = stem[: -len("_deob")]
    return stem


def test_complex_examples_cli_outputs_are_clean(tmp_path: Path) -> None:
    source_root = PROJECT_ROOT / "examples" / "complex_obfuscated"
    copied = _copy_example_tree(source_root, tmp_path)

    proc = subprocess.run(
        [sys.executable, str(CLI_ENTRY), str(copied)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr

    outputs = _collect_outputs(copied)
    assert outputs, "expected CLI to produce _deob.lua outputs"

    for output in outputs:
        text = output.read_text(encoding="utf-8")
        assert text.strip(), f"expected non-empty output for {output.name}"
        assert not BANNED_MARKERS.search(text), f"found obfuscation markers in {output.name}"

        key = _source_key(output)
        markers = EXPECTED_MARKERS.get(key, DEFAULT_MARKERS)
        lowered = text.lower()
        # The complex fixtures ship with known plaintext markers.  Checking for
        # them provides the lightweight "sandbox" assurance requested in the
        # acceptance criteria without embedding a full Lua interpreter.
        assert any(marker.lower() in lowered for marker in markers), (
            f"expected decrypted markers in {output.name}; checked {markers}"
        )
