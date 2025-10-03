"""Convert runtime capture traces into ``unpacked_dump`` payloads."""

from __future__ import annotations

import base64
import binascii
import json
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence

LUA_BYTECODE_MAGIC = b"\x1bLua"
LUAJIT_MAGIC = b"\x1bLJ"


class ConversionError(ValueError):
    """Raised when a capture cannot be converted into an unpacked dump."""


def _try_json(data: bytes) -> Any | None:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _try_decompress(data: bytes) -> bytes | None:
    for decoder in (zlib.decompress,):
        try:
            return decoder(data)
        except Exception:
            continue
    return None


def _maybe_index(key: Any) -> int | None:
    if isinstance(key, int) and key > 0:
        return key
    if isinstance(key, str) and key.isdigit():
        value = int(key)
        return value if value > 0 else None
    return None


def _normalise_sequence(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        if "array" in value and isinstance(value["array"], list):
            return value["array"]
        result: List[Any] = []
        for key, entry in value.items():
            idx = _maybe_index(key)
            if idx is None:
                continue
            while len(result) < idx:
                result.append(None)
            result[idx - 1] = entry
        return result
    return []


def _normalise_dump(obj: Any) -> Dict[str, Any]:
    if isinstance(obj, Mapping):
        instructions = obj.get("4") or obj.get(4)
        constants = obj.get("5") or obj.get(5)
        meta: MutableMapping[str, Any] = dict(obj)
        normalised = {
            "4": _normalise_sequence(instructions),
            "5": _normalise_sequence(constants),
        }
        for key in ("map", "constants", "bytecode"):
            if key in meta:
                normalised[key] = meta[key]
        if "instructions" in meta and not normalised["4"]:
            normalised["4"] = _normalise_sequence(meta["instructions"])
        if "consts" in meta and not normalised["5"]:
            normalised["5"] = _normalise_sequence(meta["consts"])
        return normalised
    if isinstance(obj, Sequence):
        return {"4": _normalise_sequence(obj), "5": []}
    raise ConversionError("JSON payload is not a recognised unpackedData shape")


def _decode_vm_words(data: bytes) -> Dict[str, Any]:
    if len(data) % 8 != 0:
        raise ConversionError("captured buffer length is not aligned to 8 bytes")
    instructions: List[List[Any]] = []
    for idx in range(0, len(data), 8):
        chunk = data[idx : idx + 8]
        opcode = int.from_bytes(chunk[2:4], "little")
        instructions.append([None, None, opcode])
    return {"4": instructions, "5": []}


def _convert_lua_bytecode(data: bytes) -> Dict[str, Any]:
    encoded = base64.b64encode(data).decode("ascii")
    return {"format": "lua_bytecode", "blob_b64": encoded}


def _validate_dump(dump: Mapping[str, Any]) -> None:
    instructions = dump.get("4")
    if not isinstance(instructions, list) or not instructions:
        raise ConversionError("unpacked dump lacks instruction table")
    first = instructions[0]
    if isinstance(first, list):
        if len(first) < 3 or not isinstance(first[2], int):
            raise ConversionError("first instruction missing opcode")
    elif isinstance(first, Mapping):
        opcode = first.get("3") or first.get(3) or first.get("opcode")
        if not isinstance(opcode, int):
            raise ConversionError("first instruction missing opcode")
    else:
        raise ConversionError("instruction table has unsupported layout")


def convert_bytes(data: bytes) -> Dict[str, Any]:
    """Convert raw capture data into the unpacked dump format."""

    json_payload = _try_json(data)
    if json_payload is not None:
        dump = _normalise_dump(json_payload)
        _validate_dump(dump)
        return dump

    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error):  # type: ignore[name-defined]
        decoded = None
    if decoded and decoded != data:
        try:
            return convert_bytes(decoded)
        except ConversionError:
            pass

    decompressed = _try_decompress(data)
    if decompressed:
        json_payload = _try_json(decompressed)
        if json_payload is not None:
            dump = _normalise_dump(json_payload)
            _validate_dump(dump)
            return dump
        if decompressed.startswith(LUA_BYTECODE_MAGIC) or decompressed.startswith(LUAJIT_MAGIC):
            return _convert_lua_bytecode(decompressed)

    if data.startswith(LUA_BYTECODE_MAGIC) or data.startswith(LUAJIT_MAGIC):
        return _convert_lua_bytecode(data)

    dump = _decode_vm_words(data)
    _validate_dump(dump)
    return dump


def convert_file(path: Path) -> Dict[str, Any]:
    data = path.read_bytes()
    return convert_bytes(data)


__all__ = ["convert_bytes", "convert_file", "ConversionError"]
