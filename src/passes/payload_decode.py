"""Payload decoding helpers for version-specific handling."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from .. import utils
from ..deobfuscator import VMIR
from ..versions import PayloadInfo, VersionHandler, get_handler

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..pipeline import Context


ConstPool = List[Any]


def run(ctx: "Context") -> Dict[str, Any]:
    """Decode payloads and enrich context metadata."""

    ctx.ensure_raw_input()
    deob = ctx.deobfuscator
    assert deob is not None

    text = ctx.stage_output or ctx.raw_input
    if not text:
        ctx.stage_output = ""
        return {"empty": True}

    version = ctx.detected_version or deob.detect_version(text, from_json=ctx.from_json)
    ctx.detected_version = version
    features = version.features if version.features else None

    script_key: Any = getattr(ctx, "script_key", None)
    if not isinstance(script_key, str) and isinstance(ctx.options, dict):
        script_key = ctx.options.get("script_key")

    result = deob.decode_payload(
        text,
        version=version,
        features=features,
        script_key=script_key if isinstance(script_key, str) else None,
        bootstrapper=ctx.bootstrapper_path,
    )
    handler_instance = getattr(deob, "last_handler", None)
    if isinstance(handler_instance, VersionHandler):
        ctx.version_handler = handler_instance
    else:
        ctx.version_handler = None
    output_text = result.text or ""
    ctx.stage_output = output_text
    if output_text:
        ctx.decoded_payloads.append(output_text)

    metadata: Dict[str, Any] = dict(result.metadata)
    vm_ir = metadata.pop("vm_ir", None)
    if isinstance(vm_ir, VMIR):
        ctx.vm_ir = vm_ir
        if vm_ir.constants and not ctx.vm.const_pool:
            ctx.vm.const_pool = list(vm_ir.constants)
        metadata["vm_ir"] = {
            "constants": len(vm_ir.constants),
            "bytecode": len(vm_ir.bytecode),
            "prototypes": len(vm_ir.prototypes or []),
        }

    if version.name == "luraph_v14_2_json":
        handler_meta = _populate_v142_json_payload(ctx, text)
        if handler_meta:
            metadata.update(handler_meta)

    _apply_vm_bytecode(ctx, metadata, version.name)

    report = getattr(ctx, "report", None)
    if report is not None:
        if ctx.script_key:
            report.script_key_used = ctx.script_key
        payload_meta = metadata.get("handler_payload_meta")
        if isinstance(payload_meta, dict):
            key_value = payload_meta.get("script_key")
            if isinstance(key_value, str) and key_value:
                report.script_key_used = key_value
            bootstrap_meta = payload_meta.get("bootstrapper")
            if isinstance(bootstrap_meta, dict):
                path_value = bootstrap_meta.get("path") or bootstrap_meta.get("source")
                if isinstance(path_value, str) and path_value:
                    report.bootstrapper_used = path_value
        if ctx.bootstrapper_path:
            report.bootstrapper_used = str(ctx.bootstrapper_path)

        lengths: List[int] = []
        byte_len = metadata.get("handler_bytecode_bytes")
        if isinstance(byte_len, int) and byte_len >= 0:
            lengths.append(byte_len)
        payload_len = metadata.get("handler_payload_bytes")
        if isinstance(payload_len, int) and payload_len >= 0:
            lengths.append(payload_len)
        raw_bytes = metadata.get("handler_vm_bytecode")
        if not lengths and isinstance(raw_bytes, (bytes, bytearray)):
            lengths.append(len(raw_bytes))
        chunk_count = metadata.get("handler_payload_chunks")
        if isinstance(chunk_count, int) and chunk_count > 0:
            report.blob_count += chunk_count
        elif lengths:
            report.blob_count += len(lengths)

        if lengths:
            report.decoded_bytes += sum(lengths)
        elif isinstance(metadata.get("handler_chunk_decoded_bytes"), list):
            chunk_bytes = [
                value
                for value in metadata.get("handler_chunk_decoded_bytes", [])
                if isinstance(value, int) and value >= 0
            ]
            if chunk_bytes:
                report.decoded_bytes += sum(chunk_bytes)

        warnings = metadata.get("warnings")
        if isinstance(warnings, list):
            report.warnings.extend(str(item) for item in warnings if item)

    return metadata


def _populate_v142_json_payload(ctx: "Context", text: str) -> Dict[str, Any]:
    """Extract bytecode details for the JSON-based v14.2 handler."""

    try:
        handler = get_handler("luraph_v14_2_json")
    except KeyError:
        return {}
    if not isinstance(handler, VersionHandler):
        return {}

    payload = handler.locate_payload(text)
    if payload is None:
        return {}

    try:
        raw_bytes = handler.extract_bytecode(payload)
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("failed to extract v14.2 JSON bytecode: %s", exc, exc_info=True)
        return {"handler_bytecode_error": str(exc)}

    _write_opcode_dump(raw_bytes)

    data = _payload_mapping(payload)

    const_pool: ConstPool = _ensure_list(data.get("constants"))
    ctx.vm.const_pool = const_pool

    proto_candidates = _ensure_list(
        data.get("prototypes") if isinstance(data, dict) else None
    )
    if not proto_candidates and isinstance(data, dict):
        proto_candidates = _ensure_list(data.get("protos"))
    proto_count = len(proto_candidates)

    endianness = "little"
    if isinstance(data, dict):
        raw_endian = data.get("endianness") or data.get("endian")
        if isinstance(raw_endian, str) and raw_endian:
            endianness = raw_endian.lower()

    initial_pc = 0
    if isinstance(data, dict):
        initial_pc = _first_int(data, "initial_pc", "pc", "start_pc")

    ctx.vm.bytecode = raw_bytes
    ctx.vm.meta.clear()
    ctx.vm.meta.update(
        {
            "endianness": endianness,
            "proto_count": proto_count,
            "initial_pc": initial_pc,
        }
    )

    opcodes = list(raw_bytes)
    if opcodes:
        op_min = min(opcodes)
        op_max = max(opcodes)
        ctx.vm.meta["opcode_min"] = op_min
        ctx.vm.meta["opcode_max"] = op_max
        op_range = f"0x{op_min:02x}-0x{op_max:02x}"
    else:
        op_range = "n/a"

    LOG.debug(
        "luraph_v14_2_json payload extracted: size=%d protos=%d range=%s",
        len(raw_bytes),
        proto_count,
        op_range,
    )

    metadata: Dict[str, Any] = {
        "handler_payload_bytes": len(raw_bytes),
        "handler_proto_count": proto_count,
        "handler_endianness": endianness,
        "handler_initial_pc": initial_pc,
        "handler_const_count": len(const_pool),
    }
    if opcodes:
        metadata["handler_opcode_min"] = min(opcodes)
        metadata["handler_opcode_max"] = max(opcodes)

    return metadata


def _apply_vm_bytecode(ctx: "Context", metadata: Dict[str, Any], version_name: str) -> None:
    """Populate ``ctx.vm`` with handler-provided bytecode metadata."""

    script_payload = bool(metadata.get("script_payload"))
    raw_bytes = metadata.pop("handler_vm_bytecode", None)
    if not script_payload and isinstance(raw_bytes, (bytes, bytearray)) and raw_bytes:
        if not ctx.vm.bytecode:
            ctx.vm.bytecode = bytes(raw_bytes)
        elif ctx.vm.bytecode != bytes(raw_bytes):
            ctx.vm.meta.setdefault("alternate_bytecode", True)

    payload_meta = metadata.get("handler_payload_meta")
    if isinstance(payload_meta, dict):
        clean_meta = {key: value for key, value in payload_meta.items() if key != "script_key"}
        if clean_meta:
            for key, value in clean_meta.items():
                ctx.vm.meta.setdefault(key, value)
    if ctx.vm.bytecode:
        ctx.vm.meta.setdefault("handler", version_name)


def _write_opcode_dump(data: bytes) -> None:
    try:
        out_dir = Path("out")
        utils.ensure_directory(out_dir)
        hex_text = " ".join(f"{byte:02X}" for byte in data)
        (out_dir / "opcodes.hex").write_text(hex_text, encoding="utf-8")
    except Exception as exc:  # pragma: no cover - debugging aid only
        LOG.debug("failed to write opcode dump: %s", exc)


def _payload_mapping(payload: PayloadInfo) -> Dict[str, Any]:
    if payload.data and isinstance(payload.data, dict):
        return payload.data
    try:
        data = json.loads(payload.text)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _ensure_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return list(value)
    return []


def _first_int(data: Dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = data.get(key)
        if isinstance(value, int):
            return value
    return 0


__all__ = ["run"]
