from __future__ import annotations

from pathlib import Path

from src.runtime_capture import frida_hook


def test_frida_file_mode(tmp_path: Path) -> None:
    source = tmp_path / "buffer.bin"
    source.write_bytes(b"test-data")
    result = frida_hook.capture_with_frida(
        f"file://{source.as_posix()}",
        output_dir=tmp_path / "out",
    )
    assert result.dumps
    dump_path = result.dumps[0]
    assert dump_path.exists()
    assert dump_path.read_bytes() == b"test-data"
