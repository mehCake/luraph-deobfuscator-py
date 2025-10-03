"""Windows-safe LuaJIT wrapper orchestration."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Sequence

from .luajit_paths import find_luajit
from .trace_to_unpacked import convert_file

REPO_ROOT = Path(__file__).resolve().parents[2]
WRAPPER_PATH = REPO_ROOT / "tools" / "devirtualize_v3.lua"
SHIM_PATH = REPO_ROOT / "tools" / "shims" / "initv4_shim.lua"


@dataclass(slots=True)
class LuajitCapture:
    """Result information collected from a LuaJIT wrapper run."""

    command: Sequence[str]
    returncode: int | None
    stdout: str
    stderr: str
    dumps: List[Path]
    diagnostics: List[str] = field(default_factory=list)

    def to_json(self) -> dict:  # pragma: no cover - trivial serialiser
        return {
            "command": list(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "dumps": [path.as_posix() for path in self.dumps],
            "diagnostics": list(self.diagnostics),
        }


def _classify_errors(stderr: str) -> List[str]:
    lowered = stderr.lower()
    diagnostics: List[str] = []
    if "winerror 216" in lowered or "not a valid win32" in lowered:
        diagnostics.append("luajit binary incompatible with host architecture")
    if "module 'lupa'" in lowered:
        diagnostics.append("missing LuaJIT dependencies")
    if "shim" in lowered and "failed" in lowered:
        diagnostics.append("initv4 shim failed to load")
    return diagnostics


def _prepare_environment(out_dir: Path) -> dict:
    env = os.environ.copy()
    lua_path = env.get("LUA_PATH", "")
    shim_paths = [
        str(REPO_ROOT / "tools" / "?.lua"),
        str(REPO_ROOT / "tools" / "?/init.lua"),
        str(REPO_ROOT / "tools" / "shims" / "?.lua"),
    ]
    path_sep = ";" if os.name == "nt" else ":"
    lua_path = path_sep.join(shim_paths + ([lua_path] if lua_path else []))
    env["LUA_PATH"] = lua_path
    env["LUA_CPATH"] = env.get("LUA_CPATH", "")
    env["LURAPH_OUT_DIR"] = str(out_dir)
    env["INITV4_SHIM"] = str(SHIM_PATH)
    return env


def run_wrapper(out_dir: Path, script_key: str, json_path: Path, timeout: int = 10) -> LuajitCapture:
    """Execute the LuaJIT bootstrap wrapper with the initv4 shim preloaded."""

    luajit_cmd = find_luajit()
    if not luajit_cmd:
        raise RuntimeError("luajit executable not found; cannot perform wrapper capture")
    if not WRAPPER_PATH.exists():
        raise RuntimeError("tools/devirtualize_v3.lua missing")
    out_dir.mkdir(parents=True, exist_ok=True)

    env = _prepare_environment(out_dir)
    env["SCRIPT_KEY"] = script_key

    command = list(luajit_cmd) + [str(WRAPPER_PATH), script_key, str(json_path), str(out_dir)]

    try:
        proc = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        returncode: int | None = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        return LuajitCapture(command, None, exc.stdout or "", exc.stderr or "", [], [f"timeout after {timeout}s"])
    except OSError as exc:
        raise RuntimeError(f"luajit invocation failed: {exc}")

    diagnostics = _classify_errors(stderr)
    dumps: List[Path] = []
    unpacked_json = out_dir / "unpacked_dump.json"
    if unpacked_json.exists():
        dumps.append(unpacked_json)
    shim_json = out_dir / "unpacked_dump.lua.json"
    if shim_json.exists():
        dumps.append(shim_json)

    # Validate dumps by attempting to convert to the canonical structure.
    valid_dumps: List[Path] = []
    for dump in dumps:
        try:
            convert_file(dump)
        except Exception as exc:  # pragma: no cover - conversion errors are reported to diagnostics
            diagnostics.append(f"failed to normalise {dump.name}: {exc}")
        else:
            valid_dumps.append(dump)
    if valid_dumps:
        dumps = valid_dumps

    return LuajitCapture(command, returncode, stdout, stderr, dumps, diagnostics)


__all__ = ["LuajitCapture", "run_wrapper"]
