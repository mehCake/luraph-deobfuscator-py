"""Convert runtime capture traces into unpacked dump structures."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict

LUA_BYTECODE_MAGIC = b"\x1bLua"
LUAJIT_MAGIC = b"\x1bLJ"


def _try_json(data: bytes) -> Dict[str, Any] | None:
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception:
        return None
    if isinstance(obj, (dict, list)):
        return obj  # type: ignore[return-value]
    return None


def _decode_vm_words(data: bytes) -> Dict[str, Any]:
    if len(data) % 8 != 0:
        raise ValueError("captured buffer length is not aligned to 8 bytes")
    instructions = []
    for idx in range(0, len(data), 8):
        chunk = data[idx : idx + 8]
        opcode = int.from_bytes(chunk[2:4], "little")
        instructions.append([None, None, opcode])
    return {"4": instructions, "5": []}


def convert_bytes(data: bytes) -> Dict[str, Any]:
    """Convert raw capture data into the unpacked dump format."""

    json_payload = _try_json(data)
    if json_payload is not None:
        return json_payload

    if data.startswith(LUA_BYTECODE_MAGIC) or data.startswith(LUAJIT_MAGIC):
        return {
            "format": "lua_bytecode",
            "blob_b64": base64.b64encode(data).decode("ascii"),
        }

    return _decode_vm_words(data)


def convert_file(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    return convert_bytes(data)


__all__ = ["convert_bytes", "convert_file"]
