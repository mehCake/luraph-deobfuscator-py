"""Best-effort reconstruction of readable Lua source from the IR."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, MutableMapping

from . import simple_graph as nx
from .utils import write_text


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

    register_alias: Dict[int, str] = {}
    defined_aliases: set[str] = set()

    def alias_for(index: int) -> str:
        name = register_alias.get(index)
        if name is None:
            name = f"r{index}"
            register_alias[index] = name
        return name

    entries: List[Dict[str, Any]] = []
    for pc, raw in enumerate(instrs, start=1):
        if isinstance(raw, list):
            op = raw[2] if len(raw) >= 3 else None
            A = raw[5] if len(raw) >= 6 else None
            B = raw[6] if len(raw) >= 7 else None
            C = raw[7] if len(raw) >= 8 else None
            extra = raw
        elif isinstance(raw, dict):
            op = raw.get("3", raw.get(3))
            A = raw.get("6", raw.get(6))
            B = raw.get("7", raw.get(7))
            C = raw.get("8", raw.get(8))
            extra = list(raw.values())
        else:
            op = A = B = C = None
            extra = []

        op_meta = opcode_map.get(int(op)) if isinstance(op, int) else None
        mnemonic = op_meta.get("mnemonic") if isinstance(op_meta, dict) else None
        mnemonic = mnemonic or (f"OP_{op}" if op is not None else "OP_UNKNOWN")

        line: str
        terminates = mnemonic in {"RETURN"}
        if mnemonic == "LOADK" and isinstance(A, int):
            const_index: int | None = None
            if isinstance(B, int) and 1 <= B <= len(consts):
                const_index = B
            else:
                for value in extra:
                    if isinstance(value, int) and 1 <= value <= len(consts):
                        const_index = value
                        break
            if const_index is not None:
                alias = alias_for(A)
                prefix = "local " if alias not in defined_aliases else ""
                defined_aliases.add(alias)
                line = f"{prefix}{alias} = {_const_to_lua(consts[const_index - 1])}  -- [{pc}] LOADK\n"
            else:
                line = f"-- [{pc}] LOADK unresolved constant A={A}, B={B}, C={C}\n"
        elif mnemonic == "MOVE" and isinstance(A, int) and isinstance(B, int):
            dest = alias_for(A)
            src = alias_for(B)
            prefix = "local " if dest not in defined_aliases else ""
            defined_aliases.add(dest)
            line = f"{prefix}{dest} = {src}  -- [{pc}] MOVE\n"
        else:
            if mnemonic.startswith("OP_"):
                line = f"-- [{pc}] unresolved {mnemonic} A={A}, B={B}, C={C}\n"
            else:
                line = f"-- [{pc}] {mnemonic} A={A}, B={B}, C={C}\n"
            terminates = terminates or mnemonic.startswith("OP_")

        entries.append({"pc": pc, "line": line, "terminates": terminates})

    graph = nx.Graph()
    block_nodes: List[int] = []
    for entry in entries:
        pc = entry["pc"]
        graph.add_node(pc)
        block_nodes.append(pc)
        if entry["terminates"]:
            for left, right in zip(block_nodes, block_nodes[1:]):
                graph.add_edge(left, right)
            block_nodes = []
    if block_nodes:
        for left, right in zip(block_nodes, block_nodes[1:]):
            graph.add_edge(left, right)

    entry_map = {entry["pc"]: entry for entry in entries}
    ordered_blocks = []
    for component in nx.connected_components(graph):
        block = sorted(component)
        if block:
            ordered_blocks.append(block)
    ordered_blocks.sort(key=lambda block: block[0])

    output_lines: List[str] = ["-- deobfuscated scaffold\n"]
    for index, block in enumerate(ordered_blocks, start=1):
        output_lines.append(f"-- block {index} (pc {block[0]}-{block[-1]})\n")
        for pc in block:
            output_lines.append(entry_map[pc]["line"])
        output_lines.append("\n")
    if output_lines and output_lines[-1] == "\n":
        output_lines.pop()

    chunks: List[Path] = []
    for offset in range(0, len(output_lines), chunk_lines):
        chunk_index = len(chunks) + 1
        chunk_lines_data = output_lines[offset : offset + chunk_lines]
        chunk_path = out_path / f"deobfuscated.part{chunk_index:02d}.lua"
        write_text(chunk_path, "".join(chunk_lines_data))
        chunks.append(chunk_path)

    full_text = "".join(output_lines)
    total_lines = len(full_text.splitlines())
    if total_lines <= 3000:
        write_text(out_path / "deobfuscated.full.lua", full_text)

    return {"status": "ok", "chunks": len(chunks), "total_lines": total_lines}


__all__ = ["reconstruct"]

