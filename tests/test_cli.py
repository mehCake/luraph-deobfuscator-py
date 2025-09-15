import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(target: Path, workdir: Path, *extra: str) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PROJECT_ROOT / "main.py"), str(target), *extra]
    return subprocess.run(cmd, cwd=workdir, check=True, capture_output=True)


def test_cli_emits_output_for_single_file(tmp_path):
    source = PROJECT_ROOT / "example_obfuscated.lua"
    target = tmp_path / source.name
    target.write_text(source.read_text())

    _run_cli(target, tmp_path)

    output = target.with_name(f"{target.stem}_deob.lua")
    assert output.exists()
    assert output.read_text().strip()


def test_cli_accepts_directory(tmp_path):
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    sources = [
        PROJECT_ROOT / "example_obfuscated.lua",
        PROJECT_ROOT / "examples" / "json_wrapped.lua",
    ]
    for src in sources:
        (sample_dir / src.name).write_text(src.read_text())

    _run_cli(sample_dir, tmp_path)

    outputs = list(sample_dir.glob("*_deob.lua"))
    assert outputs, "expected deobfuscated files in directory"
    for produced in outputs:
        assert produced.read_text().strip()


def test_cli_smoke_complex_sample(tmp_path):
    complex_source = PROJECT_ROOT / "examples" / "complex_obfuscated"
    local_copy = tmp_path / "complex_obfuscated"
    local_copy.write_bytes(complex_source.read_bytes())

    _run_cli(local_copy, tmp_path)

    output = local_copy.with_name("complex_obfuscated_deob.lua")
    assert output.exists()
    assert output.stat().st_size > 0
