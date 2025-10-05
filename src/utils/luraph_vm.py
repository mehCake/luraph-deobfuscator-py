"""Helpers for rebuilding Lua bytecode from ``unpackedData`` tables."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

__all__ = [
    "VMRebuildResult",
    "MinimalVMInstruction",
    "rebuild_vm_bytecode",
    "looks_like_vm_bytecode",
    "canonicalise_opcode_name",
]


_FIELD_ALIASES: Mapping[str, Tuple[object, ...]] = {
    "opcode": (3, "opcode", "op", "Op", "OP"),
    "A": (6, "A", "a", "RA", "ra"),
    "B": (7, "B", "b", "RB", "rb", "argB", "rkB", "rk_b"),
    "C": (8, "C", "c", "RC", "rc", "argC", "rkC", "rk_c"),
    "Bx": (9, "Bx", "bx", "Index", "index", "idx", "const", "k"),
    "sBx": (10, "sBx", "sbx", "offset", "jmp", "jump"),
}

_SBX_BIAS = 131071  # 2^17 - 1


@dataclass
class MinimalVMInstruction:
    """Very small representation of an instruction for smoke tests."""

    opcode: int
    mnemonic: str
    a: int
    b: int
    c: int
    pc: int


@dataclass
class VMRebuildResult:
    """Container returned by :func:`rebuild_vm_bytecode`."""

    bytecode: bytes
    instructions: List[Dict[str, Any]]
    constants: List[Any]
    micro_instructions: List[MinimalVMInstruction] = field(default_factory=list)


_CANONICAL_OPCODE_ALIASES: Mapping[str, str] = {
    "LOADB": "LOADBOOL",
    "PUSHK": "LOADK",
}


def canonicalise_opcode_name(name: Optional[str]) -> Optional[str]:
    """Normalise bootstrap mnemonics to canonical Lua 5.1 names."""

    if not name:
        return None
    upper = str(name).strip().upper()
    if not upper:
        return None
    return _CANONICAL_OPCODE_ALIASES.get(upper, upper)


def looks_like_vm_bytecode(
    blob: Sequence[int] | bytes,
    *,
    opcode_map: Optional[Mapping[int, Any]] = None,
) -> bool:
    """Quick heuristic to decide whether ``blob`` resembles Lua bytecode."""

    if not blob:
        return False

    data = bytes(blob)
    if len(data) < 16 or len(data) % 4:
        return False

    printable = sum(1 for b in data if 32 <= b < 127)
    if printable > len(data) // 2:
        return False

    raw_opcodes = [data[index] for index in range(0, len(data), 4)]
    if len({value for value in raw_opcodes}) < 4:
        return False

    unique = {value & 0x3F for value in raw_opcodes}

    if opcode_map:
        try:
            probe = {int(key, 0) if isinstance(key, str) else int(key) for key in opcode_map.keys()}
        except Exception:
            probe = set()
        if probe:
            overlap = len(unique & {value & 0x3F for value in probe})
            return overlap >= max(3, len(probe) // 8)

    return True


def rebuild_vm_bytecode(
    unpacked: Mapping[Any, Any] | Sequence[Any],
    opcode_map: Optional[Mapping[int, str]] = None,
) -> VMRebuildResult:
    """Return a :class:`VMRebuildResult` built from an ``unpackedData`` table."""

    instruction_table = _table_lookup(unpacked, 4)
    constant_table = _table_lookup(unpacked, 5)

    instructions = _normalise_sequence(instruction_table)
    constants = _normalise_sequence(constant_table)

    opcode_lookup = _normalise_opcode_map(opcode_map)

    encoded = bytearray()
    rows: List[Dict[str, Any]] = []
    micro_rows: List[MinimalVMInstruction] = []

    for index, raw in enumerate(instructions):
        if raw is None:
            continue
        normalised = _normalise_instruction(raw, opcode_lookup)
        if normalised is None:
            continue
        encoded.extend(_encode_instruction(normalised))
        normalised.setdefault("pc", index * 4)
        normalised.setdefault("index", index)
        rows.append(normalised)
        mini = _minimal_instruction(normalised)
        if mini is not None:
            micro_rows.append(mini)

    return VMRebuildResult(
        bytecode=bytes(encoded),
        instructions=rows,
        constants=constants,
        micro_instructions=micro_rows,
    )


# ---------------------------------------------------------------------------
# Helpers


def _table_lookup(table: Mapping[Any, Any] | Sequence[Any], index: int) -> Any:
    if isinstance(table, Mapping):
        # Common structures returned by ``_convert_lua_table``
        if "array" in table:
            array = table.get("array")
            if isinstance(array, Sequence):
                value = _sequence_get(array, index)
                if value is not None:
                    return value
        if "map" in table and isinstance(table["map"], Mapping):
            value = table["map"].get(index)
            if value is None:
                value = table["map"].get(str(index))
            if value is not None:
                return value
        value = table.get(index)
        if value is None:
            value = table.get(str(index))
        if value is not None:
            return value
    if isinstance(table, Sequence):
        return _sequence_get(table, index)
    return None


def _sequence_get(seq: Sequence[Any], lua_index: int) -> Any:
    index = lua_index - 1
    if 0 <= index < len(seq):
        return seq[index]
    return None


def _normalise_sequence(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, Mapping):
        if "array" in value and isinstance(value["array"], list):
            return value["array"]
        result: List[Any] = []
        for key, item in value.items():
            idx = _maybe_index(key)
            if idx is None:
                continue
            while len(result) < idx:
                result.append(None)
            result[idx - 1] = item
        return result
    return []


def _maybe_index(key: Any) -> Optional[int]:
    if isinstance(key, int) and key > 0:
        return key
    if isinstance(key, str) and key.isdigit():
        try:
            value = int(key)
        except ValueError:
            return None
        return value if value > 0 else None
    return None


def _normalise_instruction(raw: Any, opcode_map: Optional[Mapping[int, str]]) -> Optional[Dict[str, Any]]:
    if raw is None:
        return None

    array: Sequence[Any] = []
    mapping: MutableMapping[Any, Any] = {}

    if isinstance(raw, Mapping):
        if "array" in raw and isinstance(raw["array"], Sequence):
            array = raw["array"]
            if isinstance(raw.get("map"), Mapping):
                mapping = dict(raw["map"])
            else:
                mapping = {k: v for k, v in raw.items() if k != "array"}
        else:
            mapping = dict(raw)
    elif isinstance(raw, Sequence):
        array = raw

    def _resolve(field: str) -> Optional[int]:
        candidates = _FIELD_ALIASES.get(field, ())
        for key in candidates:
            value = None
            if isinstance(key, int) and array:
                value = _sequence_get(array, key)
            elif mapping and key in mapping:
                value = mapping.get(key)
            elif mapping and isinstance(key, str):
                value = mapping.get(str(key))
            if value is None:
                continue
            coerced = _coerce_int(value)
            if coerced is not None:
                return coerced
        return None

    opcode = _resolve("opcode")
    if opcode is None:
        return None

    a_val = _resolve("A") or 0
    bx_val = _resolve("Bx")
    sbx_val = _resolve("sBx")
    b_val = _resolve("B")
    c_val = _resolve("C")

    if sbx_val is not None:
        bx_val = sbx_val + _SBX_BIAS
    if bx_val is not None:
        b_val = (bx_val >> 9) & 0x1FF
        c_val = bx_val & 0x1FF

    b_val = 0 if b_val is None else b_val
    c_val = 0 if c_val is None else c_val

    opcode_num = opcode & 0x3F

    info = {
        "opcode": opcode_num,
        "A": a_val & 0xFF,
        "B": b_val & 0x1FF,
        "C": c_val & 0x1FF,
    }

    if bx_val is not None:
        info["Bx"] = bx_val & 0x3FFFF
    if sbx_val is not None:
        info["sBx"] = int(sbx_val)

    mnemonic: Optional[str] = None
    if opcode_map and opcode_num in opcode_map:
        mnemonic = canonicalise_opcode_name(opcode_map[opcode_num])

    if not mnemonic:
        mnemonic = f"OP_{opcode_num:02X}"

    info["mnemonic"] = mnemonic
    info["op"] = mnemonic
    info["raw"] = raw

    return info


def _encode_instruction(inst: Mapping[str, int]) -> bytes:
    opcode = inst.get("opcode", 0) & 0x3F
    a_val = inst.get("A", 0) & 0xFF
    b_val = inst.get("B", 0) & 0x1FF
    c_val = inst.get("C", 0) & 0x1FF

    word = opcode | (a_val << 6) | (c_val << 14) | (b_val << 23)
    return word.to_bytes(4, byteorder="little", signed=False)


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            return int(text, 10)
        except ValueError:
            return None
    return None


def _normalise_opcode_map(mapping: Optional[Mapping[Any, Any]]) -> Dict[int, str]:
    if not isinstance(mapping, Mapping):
        return {}
    normalised: Dict[int, str] = {}
    for key, value in mapping.items():
        try:
            if isinstance(key, str):
                opcode = int(key, 16) if key.lower().startswith("0x") else int(key)
            else:
                opcode = int(key)
        except (TypeError, ValueError):
            continue
        normalised[opcode & 0x3F] = str(value)
    return normalised


_MINI_LIFT_OPS = {"LOADK", "MOVE", "CALL", "RETURN"}


def _minimal_instruction(data: Mapping[str, Any]) -> Optional[MinimalVMInstruction]:
    mnemonic = data.get("op") or data.get("mnemonic")
    if not mnemonic:
        return None
    name = str(mnemonic).upper()
    if name not in _MINI_LIFT_OPS:
        return None
    try:
        opcode = int(data.get("opcode", 0)) & 0x3F
        a_val = int(data.get("A", 0)) & 0xFF
        b_val = int(data.get("B", 0)) & 0x1FF
        c_val = int(data.get("C", 0)) & 0x1FF
        pc_val = int(data.get("pc", 0))
    except Exception:
        return None
    return MinimalVMInstruction(
        opcode=opcode,
        mnemonic=name,
        a=a_val,
        b=b_val,
        c=c_val,
        pc=pc_val,
    )

