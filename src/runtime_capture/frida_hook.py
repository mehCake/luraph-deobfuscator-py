"""Frida helpers for capturing decoded buffers from LuaJIT processes."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

DEFAULT_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "tools" / "frida-scripts" / "luraph_hook.js"

try:  # pragma: no cover - optional dependency
    import frida  # type: ignore
except Exception:  # pragma: no cover
    frida = None  # type: ignore


@dataclass(slots=True)
class CaptureResult:
    """Record of a runtime capture performed via Frida."""

    method: str
    dumps: List[Path]
    metadata: dict

    def to_json(self) -> dict:  # pragma: no cover - trivial serialiser
        return {
            "method": self.method,
            "dumps": [path.as_posix() for path in self.dumps],
            "metadata": self.metadata,
        }


def _ensure_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)


def _load_script_source(script_path: Path | None, script_source: str | None) -> str:
    if script_source:
        return script_source
    path = script_path or DEFAULT_SCRIPT_PATH
    return path.read_text(encoding="utf-8")


def _attach_session(target: str, *, spawn: bool) -> tuple["frida.Session", int | None]:  # type: ignore[name-defined]
    if frida is None:  # pragma: no cover - optional dependency
        raise RuntimeError("frida module is not installed")

    pid: int | None = None
    if spawn:
        argv = target if isinstance(target, list) else [target]
        pid = frida.spawn(argv)
        session = frida.attach(pid)
    else:
        # Allow numeric PID strings, otherwise treat as process name
        try:
            pid = int(target)
            session = frida.attach(pid)
        except ValueError:
            session = frida.attach(target)
    return session, pid


def capture_with_frida(
    target: str,
    *,
    symbols: Iterable[str] | None = None,
    output_dir: Path,
    timeout: int = 10,
    script_source: str | None = None,
    spawn: bool | None = None,
) -> CaptureResult:
    """Attach to ``target`` using Frida and dump decoded buffers."""

    _ensure_output_dir(output_dir)

    if target.startswith("file://"):
        dummy_path = Path(target[7:])
        if not dummy_path.exists():
            raise FileNotFoundError(dummy_path)
        dump_path = output_dir / f"frida_{int(time.time()*1000)}.bin"
        dump_path.write_bytes(dummy_path.read_bytes())
        metadata = {
            "target": target,
            "symbols": list(symbols or []),
            "timestamp": time.time(),
            "offline": True,
        }
        return CaptureResult("frida-file", [dump_path], metadata)

    if frida is None:  # pragma: no cover - optional dependency path
        raise RuntimeError("frida module not available; install `frida` to enable runtime capture")

    script_text = _load_script_source(DEFAULT_SCRIPT_PATH, script_source)

    spawn_flag = bool(spawn)
    if spawn is None:
        path_candidate = Path(target)
        if path_candidate.exists():
            spawn_flag = True
    session, spawned_pid = _attach_session(target, spawn=spawn_flag)
    script = session.create_script(script_text)

    dumps: List[Path] = []
    metadata: dict = {
        "target": target,
        "symbols": list(symbols or []),
        "timestamp": time.time(),
    }

    if spawned_pid is not None:
        metadata["spawned_pid"] = spawned_pid

    def on_message(message, data):  # pragma: no cover - integration tested
        if message["type"] == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                msg_type = payload.get("type")
                if msg_type == "buffer":
                    raw: bytes = data or b""
                    dump_path = output_dir / f"frida_{int(time.time()*1000)}.bin"
                    dump_path.write_bytes(raw)
                    dumps.append(dump_path)
                elif msg_type == "ready":
                    metadata.setdefault("messages", []).append(payload)
                else:
                    metadata.setdefault("messages", []).append(payload)
        elif message["type"] == "error":
            metadata.setdefault("errors", []).append(message)

    script.on("message", on_message)
    script.load()

    if symbols:
        try:
            script.exports.configure(list(symbols))
        except frida.InvalidOperationError:  # pragma: no cover - script lacks exports
            pass

    if spawned_pid is not None:
        frida.resume(spawned_pid)

    start = time.time()
    while time.time() - start < timeout:
        if dumps:
            break
        time.sleep(0.1)

    session.detach()

    if not dumps:
        raise RuntimeError("frida hook completed without producing dumps")

    manifest_path = output_dir / f"frida_capture_{int(start)}.json"
    manifest_path.write_text(
        json.dumps({"dumps": [d.as_posix() for d in dumps], "metadata": metadata}, indent=2),
        encoding="utf-8",
    )
    metadata["manifest"] = manifest_path.as_posix()
    return CaptureResult("frida", dumps, metadata)


__all__ = ["CaptureResult", "capture_with_frida"]
