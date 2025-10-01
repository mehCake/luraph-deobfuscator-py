"""Helpers for launching the LuaJIT wrapper with extra diagnostics."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ..sandbox_runner import _find_luajit  # type: ignore


@dataclass
class LuajitCapture:
    command: Sequence[str]
    returncode: int
    stdout: str
    stderr: str
    dumps: list[Path]

    def to_json(self) -> dict:
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "dumps": [path.as_posix() for path in self.dumps],
        }


def run_wrapper(out_dir: Path, script_key: str, json_path: Path, timeout: int = 10) -> LuajitCapture:
    """Execute the LuaJIT wrapper and collect dumps/logs."""

    luajit_cmd = _find_luajit()
    if not luajit_cmd:
        raise RuntimeError("luajit executable not found; cannot perform wrapper capture")

    wrapper = Path(__file__).resolve().parents[2] / "tools" / "devirtualize_v3.lua"
    if not wrapper.exists():
        raise RuntimeError("tools/devirtualize_v3.lua missing")

    env = os.environ.copy()
    env["SCRIPT_KEY"] = script_key
    command = list(luajit_cmd) + [str(wrapper), script_key, str(json_path), str(out_dir)]
    proc = subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    dumps: list[Path] = []
    manifest = out_dir / "unpacked_dump.json"
    if manifest.exists():
        dumps.append(manifest)
    return LuajitCapture(command, proc.returncode, proc.stdout, proc.stderr, dumps)


__all__ = ["LuajitCapture", "run_wrapper"]
