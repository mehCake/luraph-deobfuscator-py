"""Best-effort reconstruction of readable Lua source from the IR."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, MutableMapping


def _read_json(path: str | os.PathLike[str]) -> Any:
    with open(path, "rb") as handle:
        return json.load(handle)


def _normalise(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, MutableMapping):
        if set(value.keys()) == {"array"} and isinstance(value["array"], list):
            return [_normalise(v) for v in value["array"]]
        return {k: _normalise(v) for k, v in value.items()}
    return value


def _lua_index(container: Any, index: int) -> Any:
    if isinstance(container, list):
        idx = index - 1
        if 0 <= idx < len(container):
            return container[idx]
        return None
    if isinstance(container, MutableMapping):
        return container.get(str(index), container.get(index))
    return None


def _const_to_lua(value: Any) -> str:
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        return f'"{escaped}"'
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "nil"
    return str(value)


def _load_opmap(path: str | os.PathLike[str]) -> Dict[int, Dict[str, Any]]:
    payload = _read_json(path)
    result: Dict[int, Dict[str, Any]] = {}
    for key, value in payload.items():
        try:
            opnum = int(key)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            result[opnum] = value
    return result


def reconstruct(
    unpacked_json: str | os.PathLike[str],
    opcode_map_json: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    chunk_lines: int = 800,
) -> Dict[str, Any]:
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    data = _normalise(_read_json(unpacked_json))
    instrs = _lua_index(data, 4)
    consts = _lua_index(data, 5)
    if not isinstance(instrs, list):
        return {"status": "error", "message": "instruction table missing"}
    if not isinstance(consts, list):
        consts = []

    opcode_map = _load_opmap(opcode_map_json)

    lines: List[str] = []
    lines.append("-- deobfuscated scaffold\n")

    for pc, raw in enumerate(instrs, start=1):
        if isinstance(raw, list):
            op = raw[2] if len(raw) >= 3 else None
            A = raw[5] if len(raw) >= 6 else None
            B = raw[6] if len(raw) >= 7 else None
            C = raw[7] if len(raw) >= 8 else None
        elif isinstance(raw, dict):
            op = raw.get("3", raw.get(3))
            A = raw.get("6", raw.get(6))
            B = raw.get("7", raw.get(7))
            C = raw.get("8", raw.get(8))
        else:
            op = A = B = C = None

        op_meta = opcode_map.get(int(op)) if isinstance(op, int) else None
        mnemonic = op_meta.get("mnemonic") if isinstance(op_meta, dict) else None
        mnemonic = mnemonic or (f"OP_{op}" if op is not None else "OP_UNKNOWN")

        line: str
        if mnemonic == "LOADK" and isinstance(A, int):
            const_index = B if isinstance(B, int) and 1 <= B <= len(consts) else None
            if const_index is None and isinstance(raw, list):
                for value in raw:
                    if isinstance(value, int) and 1 <= value <= len(consts):
                        const_index = value
                        break
            if const_index is not None and 1 <= const_index <= len(consts):
                line = f"R[{A}] = {_const_to_lua(consts[const_index - 1])}  -- [{pc}] LOADK\n"
            else:
                line = f"-- [{pc}] LOADK A={A}, B={B}, C={C}\n"
        elif mnemonic == "MOVE" and isinstance(A, int) and isinstance(B, int):
            line = f"R[{A}] = R[{B}]  -- [{pc}] MOVE\n"
        else:
            line = f"-- [{pc}] {mnemonic} A={A}, B={B}, C={C}\n"

        lines.append(line)

    chunks = []
    for offset in range(0, len(lines), chunk_lines):
        chunk_index = len(chunks) + 1
        chunk_lines_data = lines[offset : offset + chunk_lines]
        chunk_path = out_path / f"deobfuscated.part{chunk_index:02d}.lua"
        chunk_path.write_text("".join(chunk_lines_data), encoding="utf-8")
        chunks.append(chunk_path)

    total_lines = len(lines)
    if total_lines <= 3000:
        (out_path / "deobfuscated.full.lua").write_text("".join(lines), encoding="utf-8")

    return {"status": "ok", "chunks": len(chunks), "total_lines": total_lines}


__all__ = ["reconstruct"]

