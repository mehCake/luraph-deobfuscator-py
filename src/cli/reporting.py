"""Helpers for enriching CLI reports with lifter outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..lifter.debug_dump import LifterDebugDump
from ..lifter.runner import run_lifter_safe
from ..utils import ensure_directory, write_json, write_text
from ..utils.luraph_vm import canonicalise_opcode_name, rebuild_vm_bytecode

_TRUST_RANK: Dict[str, int] = {"high": 3, "medium": 2, "low": 1}


def _coerce_opcode_entry(value: Any) -> Dict[str, Any]:
    if value is None:
        return {}
    if is_dataclass(value):
        entry = asdict(value)
    elif isinstance(value, Mapping):
        entry = dict(value)
    else:
        entry = {"mnemonic": str(value)}
    mnemonic = entry.get("mnemonic") or entry.get("op") or entry.get("name")
    if isinstance(mnemonic, str):
        canon = canonicalise_opcode_name(mnemonic)
        if canon:
            entry["mnemonic"] = canon
            entry["op"] = canon
        else:
            upper = mnemonic.upper()
            entry["mnemonic"] = upper
            entry.setdefault("op", upper)
    return entry


def _merge_opcode_entries(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    if not existing:
        return dict(incoming)
    result = dict(existing)
    mnemonic = incoming.get("mnemonic") or incoming.get("op")
    if isinstance(mnemonic, str) and mnemonic:
        canon = canonicalise_opcode_name(mnemonic) or mnemonic.upper()
        result["mnemonic"] = canon
        result["op"] = canon
    operands = incoming.get("operands")
    if operands and not result.get("operands"):
        result["operands"] = operands
    trust_value = incoming.get("trust")
    if isinstance(trust_value, str):
        new_rank = _TRUST_RANK.get(trust_value.lower(), 0)
        current_rank = _TRUST_RANK.get(str(result.get("trust", "")).lower(), 0)
        if new_rank >= current_rank:
            result["trust"] = trust_value
    for key in ("source", "source_snippet", "offset", "keyword_counts"):
        incoming_value = incoming.get(key)
        if incoming_value and not result.get(key):
            result[key] = incoming_value
    return result


def _collect_opcode_table(ctx: "Context") -> Dict[int, Dict[str, Any]]:
    tables: List[Mapping[Any, Any]] = []
    vm_ir = getattr(ctx, "vm_ir", None)
    if vm_ir is not None:
        table = getattr(vm_ir, "opcode_map", None)
        if isinstance(table, Mapping):
            tables.append(table)
    vm_meta = getattr(ctx, "vm_metadata", None)
    if isinstance(vm_meta, Mapping):
        table = vm_meta.get("opcode_map")
        if isinstance(table, Mapping):
            tables.append(table)
    options = getattr(ctx, "options", None)
    if isinstance(options, Mapping):
        manual = options.get("manual_opcode_map")
        if isinstance(manual, Mapping):
            tables.append(manual)

    merged: Dict[int, Dict[str, Any]] = {}
    for table in tables:
        for key, value in table.items():
            try:
                opcode = int(key, 0) if isinstance(key, str) else int(key)
            except (TypeError, ValueError):
                continue
            opcode &= 0x3F
            entry = _coerce_opcode_entry(value)
            existing = merged.get(opcode)
            if existing is None:
                merged[opcode] = entry
            else:
                merged[opcode] = _merge_opcode_entries(existing, entry)
    return merged

try:  # pragma: no cover - typing only
    from ..pipeline import Context
except Exception:  # pragma: no cover - avoid circular import during typing
    Context = Any  # type: ignore


@dataclass
class LifterArtifacts:
    decoded_output: Path
    metadata: Path
    stack: Path

    def as_json(self) -> Dict[str, str]:
        return {
            "decoded_output": str(self.decoded_output),
            "metadata": str(self.metadata),
            "stack": str(self.stack),
        }


def _collect_opcode_map(ctx: "Context") -> Dict[int, str]:
    table = _collect_opcode_table(ctx)
    mapping: Dict[int, str] = {}
    for opcode, entry in table.items():
        mnemonic = entry.get("mnemonic") or entry.get("op")
        if not mnemonic:
            continue
        canon = canonicalise_opcode_name(mnemonic)
        if canon:
            mapping[opcode] = canon
        elif isinstance(mnemonic, str):
            mapping[opcode] = mnemonic.upper()
    return mapping


def _script_key_from_context(ctx: "Context") -> Optional[str]:
    options = getattr(ctx, "options", None)
    if isinstance(options, Mapping):
        key = options.get("script_key")
        if isinstance(key, str) and key.strip():
            return key.strip()
    report = getattr(ctx, "report", None)
    script_key = getattr(report, "script_key_used", None)
    if isinstance(script_key, str) and script_key.strip():
        return script_key.strip()
    deob = getattr(ctx, "deobfuscator", None)
    internal = getattr(deob, "_script_key", None)
    if isinstance(internal, str) and internal.strip():
        return internal.strip()
    return None


def _prepare_artifact_paths(output_path: Path, source_path: Path) -> LifterArtifacts:
    base_dir = output_path.parent / f"{source_path.stem}_lifter"
    ensure_directory(base_dir)
    decoded = (base_dir / "decoded_output.lua").resolve()
    metadata = (base_dir / "lift_metadata.json").resolve()
    stack = (base_dir / "lift_stack.json").resolve()
    return LifterArtifacts(decoded_output=decoded, metadata=metadata, stack=stack)


def _write_artifacts(paths: LifterArtifacts, lift_output) -> None:
    write_text(paths.decoded_output, lift_output.lua_source)
    write_json(paths.metadata, lift_output.metadata)
    write_json(paths.stack, lift_output.stack_trace)


def run_lifter_for_cli(
    ctx: "Context",
    *,
    source_path: Path,
    output_path: Path,
    mode: str = "accurate",
    debug: bool = False,
    debug_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute the requested lifter mode and return metadata for reporting."""

    metadata: Dict[str, Any] = {"mode": mode}
    artifacts: Dict[str, str] = {}
    lift_metadata: Dict[str, Any] | None = None
    stack_trace: Sequence[Mapping[str, Any]] | Sequence[Any] = []
    opcode_table = _collect_opcode_table(ctx)
    opcode_map = _collect_opcode_map(ctx)
    debug_dump: Optional[LifterDebugDump] = None
    trace_logger = None
    debug_directory: Optional[Path] = None

    if debug and mode == "accurate":
        base_dir = debug_dir or (Path("out") / "debug")
        debug_directory = (base_dir / source_path.stem).resolve()
        debug_dump = LifterDebugDump(debug_directory)
        debug_dump.dump_opcode_table(opcode_table)
        debug_dump.dump_handler_snippets(opcode_table)

    if mode != "accurate":
        ir_module = getattr(ctx, "ir_module", None)
        if ir_module is not None:
            metadata.setdefault("functions", getattr(ir_module, "block_count", 0))
            metadata.setdefault("instructions", getattr(ir_module, "instruction_count", 0))
        return {
            "metadata": metadata,
            "artifacts": artifacts,
            "lift_metadata": lift_metadata,
            "stack_trace": list(stack_trace),
        }

    vm_ir = getattr(ctx, "vm_ir", None)
    if vm_ir is None or not getattr(vm_ir, "bytecode", None):
        metadata["status"] = "skipped"
        return {
            "metadata": metadata,
            "artifacts": artifacts,
            "lift_metadata": lift_metadata,
            "stack_trace": list(stack_trace),
        }

    bytecode_data = getattr(vm_ir, "bytecode", None)
    constants_data = getattr(vm_ir, "constants", None)

    instructions: List[Dict[str, Any]]
    constants: Sequence[Any]

    if isinstance(bytecode_data, list) and bytecode_data and isinstance(bytecode_data[0], Mapping):
        instructions = [dict(row) for row in bytecode_data if isinstance(row, Mapping)]
        constants = list(constants_data or [])
    else:
        unpacked = {4: bytecode_data, 5: constants_data}
        rebuild = rebuild_vm_bytecode(unpacked, opcode_map if opcode_map else None)
        instructions = rebuild.instructions
        constants = rebuild.constants or []

    if not instructions:
        metadata["status"] = "skipped"
        return {
            "metadata": metadata,
            "artifacts": artifacts,
            "lift_metadata": lift_metadata,
            "stack_trace": list(stack_trace),
        }

    if debug_dump is not None:
        debug_dump.dump_raw_instructions(instructions)
        trace_logger = debug_dump.trace_logger()
        trace_logger.debug("Debug lifter run for %s", source_path)

    script_key = _script_key_from_context(ctx)
    try:
        lift_output = run_lifter_safe(
            instructions,
            constants,
            opcode_map,
            prototypes=getattr(vm_ir, "prototypes", None) or [],
            script_key=script_key,
            debug_logger=trace_logger,
        )
    finally:
        if debug_dump is not None:
            debug_dump.close()

    paths = _prepare_artifact_paths(output_path, source_path)
    _write_artifacts(paths, lift_output)

    artifacts = paths.as_json()
    lift_metadata = dict(lift_output.metadata)
    stack_trace = list(lift_output.stack_trace)

    metadata.update(
        {
            "functions": lift_output.metadata.get("function_count", 0),
            "opcode_coverage": lift_output.metadata.get("opcode_coverage", {}),
            "rehydrated_functions": lift_output.metadata.get("rehydrated_functions", 0),
            "artifacts": artifacts,
        }
    )
    if lift_output.metadata.get("partial"):
        metadata["partial"] = True
        if lift_output.metadata.get("partial_kind"):
            metadata["partial_kind"] = lift_output.metadata.get("partial_kind")
        if lift_output.metadata.get("partial_reason"):
            metadata["partial_reason"] = lift_output.metadata.get("partial_reason")
    if debug_directory is not None:
        metadata["debug_path"] = str(debug_directory)

    return {
        "metadata": metadata,
        "artifacts": artifacts,
        "lift_metadata": lift_metadata,
        "stack_trace": stack_trace,
    }
