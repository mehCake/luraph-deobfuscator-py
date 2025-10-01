"""Helpers for capturing decoded buffers via Frida."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "tools" / "frida-scripts" / "default_hook.js"

try:  # pragma: no cover - optional dependency
    import frida  # type: ignore
except Exception:  # pragma: no cover - the module is optional
    frida = None  # type: ignore


@dataclass
class CaptureResult:
    method: str
    dumps: list[Path]
    metadata: dict

    def to_json(self) -> dict:
        return {
            "method": self.method,
            "dumps": [path.as_posix() for path in self.dumps],
            "metadata": self.metadata,
        }


def _ensure_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)


def capture_with_frida(
    target: str,
    *,
    symbols: Iterable[str] | None = None,
    output_dir: Path,
    timeout: int = 10,
    script_source: str | None = None,
) -> CaptureResult:
    """Attach to ``target`` using Frida and dump decoded buffers.

    Parameters
    ----------
    target:
        Process name or pid accepted by ``frida.attach``/``frida.spawn``.
    symbols:
        Symbols to hook inside the runtime. The default script handles common
        Lua APIs and generic buffer-producing functions if empty.
    output_dir:
        Directory where captured buffers and metadata are written.
    timeout:
        Maximum time to wait for the script to produce captures.
    script_source:
        Optional Frida JavaScript. If ``None`` the bundled default script is used.
    """

    if target.startswith("file://"):
        dummy_path = Path(target[7:])
        if not dummy_path.exists():
            raise FileNotFoundError(dummy_path)
        _ensure_output_dir(output_dir)
        dump_path = output_dir / f"frida_{int(time.time()*1000)}.bin"
        dump_path.write_bytes(dummy_path.read_bytes())
        metadata = {"target": target, "symbols": list(symbols or []), "timestamp": time.time(), "offline": True}
        return CaptureResult("frida-file", [dump_path], metadata)

    if frida is None:  # pragma: no cover - optional dependency path
        raise RuntimeError("frida module not available; install `frida` to enable runtime capture")

    _ensure_output_dir(output_dir)
    if script_source is None:
        script_source = DEFAULT_SCRIPT_PATH.read_text(encoding="utf-8")

    dumps: list[Path] = []
    metadata: dict = {
        "target": target,
        "symbols": list(symbols or []),
        "timestamp": time.time(),
    }

    session = frida.attach(target)
    script = session.create_script(script_source)

    def on_message(message, data):  # pragma: no cover - exercised in integration tests only
        if message["type"] == "send":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("type") == "buffer":
                raw: bytes = data or payload.get("data", b"")
                dump_path = output_dir / f"frida_{int(time.time()*1000)}.bin"
                dump_path.write_bytes(raw)
                dumps.append(dump_path)
            else:
                metadata.setdefault("messages", []).append(payload)
        elif message["type"] == "error":
            metadata.setdefault("errors", []).append(message)

    script.on("message", on_message)
    script.load()

    if symbols:
        script.post({"type": "configure", "symbols": list(symbols)})

    session.enable_debugger()

    start = time.time()
    while time.time() - start < timeout:
        if dumps:
            break
        time.sleep(0.1)

    session.detach()

    if not dumps:
        raise RuntimeError("frida hook completed without producing dumps")

    manifest_path = output_dir / f"frida_capture_{int(start)}.json"
    manifest_path.write_text(json.dumps({"dumps": [d.as_posix() for d in dumps], "metadata": metadata}, indent=2), encoding="utf-8")
    metadata["manifest"] = manifest_path.as_posix()
    return CaptureResult("frida", dumps, metadata)


__all__ = ["CaptureResult", "capture_with_frida"]
