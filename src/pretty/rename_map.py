"""Rename map helpers for presenting lifted VM IR."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple, Union

from ..vm.lifter import BasicBlock, IRProgram, IROp, IROperand

LOGGER = logging.getLogger(__name__)

RegisterKey = str
RenameMap = Dict[RegisterKey, str]

_STRINGY_OPS = {
    "LOADK",
    "CONCAT",
    "SETGLOBAL",
    "SETUPVAL",
}
_ARRAY_OPS = {
    "NEWTABLE",
    "GETTABLE",
    "SETTABLE",
    "GETTABUP",
    "SETTABUP",
    "SETLIST",
}
_FUNCTION_OPS = {"CALL", "TAILCALL", "CLOSURE"}
_BOOLEAN_OPS = {"TEST", "TESTSET"}
_NUMERIC_OPS = {"ADD", "SUB", "MUL", "DIV", "MOD", "POW"}

_CATEGORY_PRIORITY = (
    "function",
    "array",
    "string",
    "number",
    "boolean",
    "local",
)
_PREFIXES = {
    "function": "fn",
    "array": "arr",
    "string": "str",
    "number": "num",
    "boolean": "flag",
    "local": "loc",
}
_DEFAULT_PREFIX = "loc"


@dataclass
class _RegisterUsage:
    categories: Set[str]
    reads: int = 0
    writes: int = 0


def propose_rename_map(
    program: IRProgram,
    *,
    version_hint: Optional[str] = None,
    existing: Optional[Mapping[str, str]] = None,
) -> RenameMap:
    """Return a deterministic rename map for *program*.

    The heuristic inspects how registers participate in the lifted IR.  Registers
    that primarily operate on strings become ``str_X`` while those that look like
    array/table carriers become ``arr_X``.  Function-like registers (``CALL`` or
    ``CLOSURE`` destinations) are labelled ``fn_X``.  Remaining registers fall
    back to ``loc_X`` so that every referenced register has a stable name.

    The result merges ``existing`` mappings while preserving deterministic
    ordering.  A ``version_hint`` of ``"v14.4.2"`` slightly favours array
    classifications for common permutation helpers observed in that release.
    """

    usage = _collect_register_usage(program, version_hint=version_hint)

    rename_map: RenameMap = {}
    if existing:
        for key in sorted(existing):
            rename_map[key] = existing[key]

    counters = Counter({prefix: 0 for prefix in _PREFIXES.values()})

    for reg_index in sorted(usage):
        key = _register_key(reg_index)
        if key in rename_map:
            continue
        category = _select_category(usage[reg_index].categories)
        prefix = _PREFIXES.get(category, _DEFAULT_PREFIX)
        counters[prefix] += 1
        rename_map[key] = f"{prefix}_{counters[prefix]}"

    function_map = _collect_function_candidates(program)
    fn_prefix = _PREFIXES["function"]
    for func_key in sorted(function_map):
        if func_key in rename_map:
            continue
        counters[fn_prefix] += 1
        rename_map[func_key] = f"{fn_prefix}_{counters[fn_prefix]}"

    return rename_map


def apply_rename_map(
    ir: Union[IRProgram, Mapping[str, object]],
    rename_map: Mapping[str, str],
) -> Union[IRProgram, Mapping[str, object]]:
    """Return *ir* with ``rename_map`` annotations applied.

    ``IRProgram`` instances are copied so that operand aliases land in the
    instruction metadata without mutating the caller's objects.  Mapping inputs
    are deep-copied dictionaries that receive ``alias`` markers on each operand
    entry.  The original input is never modified.
    """

    if isinstance(ir, IRProgram):
        return _apply_to_program(ir, rename_map)

    if isinstance(ir, Mapping):
        return _apply_to_mapping(ir, rename_map)

    raise TypeError("Unsupported IR container: expected IRProgram or mapping")


def save_rename_map(
    rename_map: Mapping[str, str],
    *,
    out_dir: Union[str, Path] = "out/rename_maps",
    name: str = "candidate",
    overwrite: bool = False,
) -> Path:
    """Persist ``rename_map`` to ``out_dir`` if explicitly requested.

    The helper never runs implicitly from :func:`propose_rename_map` – callers
    must opt-in by invoking this function.  Existing files are preserved unless
    ``overwrite`` is ``True``.
    """

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.json"

    if path.exists() and not overwrite:
        raise FileExistsError(path)

    payload = {"rename_map": dict(rename_map)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOGGER.info("Wrote rename map to %s", path)
    return path


# ---------------------------------------------------------------------------
# internal helpers


def _collect_register_usage(
    program: IRProgram,
    *,
    version_hint: Optional[str],
) -> Dict[int, _RegisterUsage]:
    usage: Dict[int, _RegisterUsage] = {}

    for block in program.blocks:
        for op in block.ops:
            for index, operand in enumerate(op.operands):
                if operand.kind.lower() != "reg" or operand.value is None:
                    continue
                reg_index = int(operand.value)
                record = usage.setdefault(reg_index, _RegisterUsage(set()))
                categories = _infer_categories(op, index, operand, version_hint)
                record.categories.update(categories)
                if _is_write_position(op, index):
                    record.writes += 1
                else:
                    record.reads += 1

    for record in usage.values():
        if not record.categories:
            record.categories.add("local")

    return usage


def _collect_function_candidates(program: IRProgram) -> Dict[str, str]:
    candidates: Dict[str, str] = {}

    for block in program.blocks:
        for op in block.ops:
            if op.mnemonic.upper() != "CLOSURE":
                continue
            proto_index = op.metadata.get("proto_index") if op.metadata else None
            if isinstance(proto_index, int):
                key = f"PROTO_{proto_index}"
                candidates[key] = "closure"

    return candidates


def _infer_categories(
    op: IROp,
    operand_index: int,
    operand: IROperand,
    version_hint: Optional[str],
) -> Set[str]:
    mnemonic = op.mnemonic.upper()
    categories: Set[str] = set()

    resolved_values = [child.resolved for child in op.operands if child.resolved is not None]

    if any(isinstance(value, str) for value in resolved_values):
        categories.add("string")
    if any(isinstance(value, (list, tuple, dict)) for value in resolved_values):
        categories.add("array")
    if any(isinstance(value, (int, float)) for value in resolved_values):
        categories.add("number")
    if any(isinstance(value, bool) for value in resolved_values):
        categories.add("boolean")

    if mnemonic in _STRINGY_OPS and operand_index == 0:
        categories.add("string")
    if mnemonic in _ARRAY_OPS:
        categories.add("array")
    if mnemonic in _FUNCTION_OPS and operand_index == 0:
        categories.add("function")
    if mnemonic == "CLOSURE" and operand_index == 0:
        categories.add("function")
    if mnemonic in _BOOLEAN_OPS and operand_index == 0:
        categories.add("boolean")
    if mnemonic in _NUMERIC_OPS and operand_index == 0:
        categories.add("number")

    if version_hint and "14.4.2" in version_hint:
        hint = (op.metadata or {}).get("category")
        if hint in {"permute", "vm_unpack", "dispatch"}:
            categories.add("array")

    if not categories:
        categories.add("local")

    return categories


def _is_write_position(op: IROp, operand_index: int) -> bool:
    if operand_index == 0:
        return True
    mnemonic = op.mnemonic.upper()
    if mnemonic in {"SETTABLE", "SETTABUP", "SETLIST"} and operand_index == 1:
        return True
    return False


def _select_category(categories: Iterable[str]) -> str:
    candidates = list(dict.fromkeys(categories))
    for preferred in _CATEGORY_PRIORITY:
        if preferred in candidates:
            return preferred
    return candidates[0] if candidates else "local"


def _register_key(index: int) -> str:
    return f"R{int(index)}"


def _alias_for_operand(operand: IROperand, rename_map: Mapping[str, str]) -> Optional[str]:
    if operand.kind.lower() != "reg" or operand.value is None:
        return None
    key = _register_key(int(operand.value))
    return rename_map.get(key)


def _apply_to_program(program: IRProgram, rename_map: Mapping[str, str]) -> IRProgram:
    new_blocks: List[BasicBlock] = []

    for block in program.blocks:
        new_ops: List[IROp] = []
        for op in block.ops:
            alias_map: Dict[str, str] = {}
            new_operands: List[IROperand] = []
            for operand in op.operands:
                new_operand = replace(operand)
                alias = _alias_for_operand(new_operand, rename_map)
                if alias:
                    field = operand.field or f"op_{len(alias_map)}"
                    alias_map[field] = alias
                    setattr(new_operand, "alias", alias)
                new_operands.append(new_operand)

            metadata = dict(op.metadata) if op.metadata else {}
            if alias_map:
                metadata["rename_aliases"] = alias_map
            new_ops.append(replace(op, operands=new_operands, metadata=metadata))

        block_meta = dict(block.metadata) if block.metadata else {}
        if rename_map:
            existing = block_meta.get("rename_map")
            if isinstance(existing, Mapping):
                merged = dict(existing)
                merged.update(rename_map)
                block_meta["rename_map"] = merged
            else:
                block_meta["rename_map"] = dict(rename_map)

        new_blocks.append(
            replace(
                block,
                ops=new_ops,
                metadata=block_meta,
            )
        )

    program_meta = dict(program.metadata) if program.metadata else {}
    program_meta.setdefault("rename_map", {}).update(rename_map)

    return IRProgram(blocks=new_blocks, metadata=program_meta, entry_block=program.entry_block)


def _apply_to_mapping(
    ir: Mapping[str, object],
    rename_map: Mapping[str, str],
) -> Mapping[str, object]:
    cloned = json.loads(json.dumps(ir))
    metadata = cloned.setdefault("metadata", {})
    rename_section = metadata.setdefault("rename_map", {})
    rename_section.update(rename_map)

    for block in cloned.get("blocks", []):
        for op in block.get("ops", []):
            alias_map: Dict[str, str] = {}
            for operand in op.get("operands", []):
                alias_info = _alias_for_operand_dict(operand, rename_map)
                if alias_info:
                    _, alias = alias_info
                    operand["alias"] = alias
                    field = operand.get("field") or f"op_{len(alias_map)}"
                    alias_map[field] = alias
            if alias_map:
                op.setdefault("metadata", {}).setdefault("rename_aliases", {}).update(alias_map)

        block_meta = block.setdefault("metadata", {})
        block_meta.setdefault("rename_map", {}).update(rename_map)

    return cloned


def _alias_for_operand_dict(
    operand: MutableMapping[str, object],
    rename_map: Mapping[str, str],
) -> Optional[Tuple[str, str]]:
    kind = str(operand.get("kind", ""))
    if kind.lower() != "reg":
        return None
    value = operand.get("value")
    if value is None:
        return None
    try:
        index = int(value)
    except (TypeError, ValueError):
        return None
    key = _register_key(index)
    alias = rename_map.get(key)
    if not alias:
        return None
    operand["register"] = key
    return key, alias


__all__ = [
    "apply_rename_map",
    "propose_rename_map",
    "save_rename_map",
]
