"""Instruction lifting helpers that translate VM bytecode into readable Lua."""

from __future__ import annotations

import base64
import bz2
import json
import logging
import lzma
import zlib
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
)

from lua_literal_parser import LuaTable, parse_lua_expression

from src.utils.luraph_vm import canonicalise_opcode_name
from src.lifter.cfg import CFGBuilder
from src.lifter.emit_structured import StructuredEmitter
from src.lifter.emulator import VMEmulator

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .runner import LifterLimits

LOG = logging.getLogger(__name__)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(data)
    key_len = len(key)
    return bytes((b ^ key[i % key_len]) & 0xFF for i, b in enumerate(data))


def _rolling_xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(data)
    key_len = len(key)
    out = bytearray(len(data))
    prev = 0
    for idx, byte in enumerate(data):
        key_byte = key[idx % key_len]
        plain = (byte ^ key_byte ^ prev) & 0xFF
        out[idx] = plain
        prev = plain
    return bytes(out)


def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(data)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = 0
    j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(byte ^ k)
    return bytes(out)


@dataclass
class LiftOutput:
    """Container returned by :func:`lift_program`."""

    lua_source: str
    ir_entries: List[Dict[str, Any]]
    stack_trace: List[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class TranslationResult:
    lines: List[str]
    comment: str
    metadata: Optional[Dict[str, Any]] = None


def _partial_output_from_limits(
    limits: "LifterLimits", *, root: bool
) -> LiftOutput:
    reason = getattr(limits, "partial_reason", None) or "analysis limits reached"
    instructions = getattr(limits, "instructions", 0)
    lines: List[str] = []
    if root:
        lines.extend(
            [
                "-- lift_ir.lua (partial output)",
                "local R = {}",
                "local stack = {}",
                "local frames = {}",
                "",
            ]
        )
    lines.append(f"-- lifter aborted early: {reason}")
    if root:
        lines.append("")
        lines.append("return { registers = R, stack = stack, frames = frames }")
    metadata: Dict[str, Any] = {
        "partial": True,
        "instructions_processed": instructions,
        "function_count": 0,
        "opcode_coverage": {"seen": []},
    }
    kind = getattr(limits, "partial_kind", None)
    if kind:
        metadata["partial_kind"] = kind
    if reason:
        metadata["partial_reason"] = reason
    return LiftOutput(
        lua_source="\n".join(lines).rstrip() + "\n",
        ir_entries=[],
        stack_trace=[],
        metadata=metadata,
    )


def lift_program(
    instructions: Iterable[Mapping[str, Any]],
    constants: Sequence[Any] | None,
    opcode_map: Optional[Mapping[int, str]] = None,
    *,
    prototypes: Sequence[Any] | None = None,
    root: bool = True,
    script_key: Optional[str | bytes] = None,
    rehydration_state: Optional[Dict[str, Any]] = None,
    limits: "LifterLimits | None" = None,
    debug_logger: Optional[logging.Logger] = None,
) -> LiftOutput:
    """Convert *instructions* into a textual IR listing and structured JSON."""

    limits_entered = False
    if limits is not None:
        if not limits.allow_recursion():
            return _partial_output_from_limits(limits, root=root)
        limits_entered = True

    context = _LiftContext(
        instructions,
        constants or [],
        opcode_map or {},
        prototypes=prototypes or [],
        root=root,
        script_key=script_key,
        rehydration_state=rehydration_state,
        limits=limits,
        debug_logger=debug_logger,
    )
    try:
        output = context.build()
    finally:
        if limits_entered and limits is not None:
            limits.release_recursion()

    if limits is not None:
        if limits.partial:
            output.metadata.setdefault("partial", True)
            reason = getattr(limits, "partial_reason", None)
            if reason:
                output.metadata.setdefault("partial_reason", reason)
            kind = getattr(limits, "partial_kind", None)
            if kind:
                output.metadata.setdefault("partial_kind", kind)
        output.metadata.setdefault("instructions_processed", getattr(limits, "instructions", 0))

    return output


class _LiftContext(VMEmulator):
    def __init__(
        self,
        instructions: Iterable[Mapping[str, Any]],
        constants: Sequence[Any],
        opcode_map: Mapping[int, str],
        *,
        prototypes: Sequence[Any],
        root: bool,
        script_key: Optional[str | bytes],
        rehydration_state: Optional[Dict[str, Any]],
        limits: "LifterLimits | None" = None,
        debug_logger: Optional[logging.Logger] = None,
    ) -> None:
        self._original: List[Dict[str, Any]] = [dict(row) for row in instructions]
        super().__init__(constants, prototypes)
        self._limits: "LifterLimits | None" = limits
        self._debug_logger = debug_logger
        self._opcode_map = {
            int(key): canonicalise_opcode_name(value)
            for key, value in opcode_map.items()
            if canonicalise_opcode_name(value)
        }
        self._root = bool(root)
        if isinstance(script_key, bytes):
            self._script_key_bytes = bytes(script_key)
        elif isinstance(script_key, str):
            self._script_key_bytes = script_key.encode("utf-8", errors="ignore")
        else:
            self._script_key_bytes = b""
        self._rehydration_state = rehydration_state if isinstance(rehydration_state, dict) else {}
        self._rehydration_state.setdefault("counter", 0)
        self._rehydration_state.setdefault("count", 0)
        self._rehydrated_info: Dict[int, Dict[str, Any]] = {}
        self._local_rehydrated_count = 0
        self._metadata: Dict[str, Any] = {}
        self._lines: List[str] = []
        self._ir_rows: List[Dict[str, Any]] = []
        self._labels: Dict[int, str] = {}
        self._block_order: Dict[int, int] = {}
        self._loop_start_to_end: Dict[int, List[int]] = {}
        self._loop_end_to_start: Dict[int, int] = {}
        self._loop_stack: List[tuple[int, int]] = []
        self._active_loops: List[tuple[int, int]] = []
        self._pending_conditionals: Dict[int, Dict[str, Any]] = {}
        self._function_count = 1
        self._function_prototypes: set[int] = set()
        self._processed_instructions = 0

        if self._debug_logger is not None:
            self._debug_logger.debug(
                "Initialising lift context (root=%s, instructions=%d)",
                self._root,
                len(self._original),
            )

        if not self._script_key_bytes:
            detected_key = self._detect_script_key()
            if detected_key:
                self._script_key_bytes = detected_key

        self._rehydrate_encrypted_functions()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _debug(self, message: str, *args: Any) -> None:
        if self._debug_logger is not None:
            self._debug_logger.debug(message, *args)

    def _mark_partial_from_limits(self) -> None:
        if not self._limits:
            return
        self._metadata.setdefault("partial", True)
        reason = getattr(self._limits, "partial_reason", None)
        if reason and "partial_reason" not in self._metadata:
            self._metadata["partial_reason"] = reason
        kind = getattr(self._limits, "partial_kind", None)
        if kind and "partial_kind" not in self._metadata:
            self._metadata["partial_kind"] = kind
        if self._limits and self._limits.partial:
            self._debug(
                "Partial flag set (kind=%s, reason=%s)",
                getattr(self._limits, "partial_kind", None),
                getattr(self._limits, "partial_reason", None),
            )

    def _consume_budget(self) -> bool:
        if not self._limits:
            return True
        if self._limits.consume():
            return True
        self._debug(
            "Instruction budget exhausted at %d instructions",
            getattr(self._limits, "instructions", 0),
        )
        self._mark_partial_from_limits()
        return False

    def _should_abort(self) -> bool:
        if not self._limits:
            return False
        if not self._limits.check_time():
            self._debug("Time limit exceeded during lifting")
            self._mark_partial_from_limits()
            return True
        if self._limits.partial:
            self._debug(
                "Aborting due to limit (kind=%s, reason=%s)",
                self._limits.partial_kind,
                self._limits.partial_reason,
            )
            self._mark_partial_from_limits()
            return True
        return False

    def _render_partial(self, translations: Sequence[TranslationResult]) -> None:
        fragments: List[str] = []
        for item in translations:
            fragments.extend(item.lines)
        rendered = self._format_lines(fragments)
        self._lines.clear()
        if self._root:
            self._lines.extend(
                [
                    "-- lift_ir.lua (auto-generated)",
                    "local R = {}",
                    "local stack = {}",
                    "local frames = {}",
                    "",
                ]
            )
        if rendered:
            self._lines.extend(rendered.splitlines())
        reason = self._metadata.get("partial_reason") or "analysis limits reached"
        self._debug("Rendering partial output: %s", reason)
        self._lines.append(f"-- lifter aborted early: {reason}")
        if self._root:
            self._lines.append("")
            self._lines.append("return { registers = R, stack = stack, frames = frames }")

    def build(self) -> LiftOutput:
        self._prepare_instructions()
        self._prepare_labels()
        self._discover_loops()
        translations = self._render()
        lua_source = "\n".join(self._lines).rstrip() + "\n"
        if self._root:
            self._metadata.setdefault(
                "rehydrated_functions", self._rehydration_state.get("count", 0)
            )
        else:
            self._metadata.setdefault("rehydrated_functions", self._local_rehydrated_count)
        seen = sorted(
            {
                int(entry["opcode"])
                for entry in self._original
                if isinstance(entry.get("opcode"), int)
            }
        )
        coverage = {"seen": seen}
        if self._opcode_map:
            missing = sorted(set(self._opcode_map) - set(seen))
            coverage["missing"] = missing
        self._metadata.setdefault("function_count", self._function_count)
        self._metadata.setdefault("distinct_opcodes", len(seen))
        self._metadata.setdefault("opcode_coverage", coverage)
        if self._limits and self._limits.partial:
            self._mark_partial_from_limits()
        self._debug(
            "Lift finished (functions=%d, distinct_opcodes=%d, partial=%s)",
            self._function_count,
            self._metadata.get("distinct_opcodes"),
            self._metadata.get("partial", False),
        )
        return LiftOutput(
            lua_source=lua_source,
            ir_entries=self._ir_rows,
            stack_trace=self._state_trace,
            metadata=dict(self._metadata),
        )

    # ------------------------------------------------------------------
    # Preparation helpers
    # ------------------------------------------------------------------

    def _detect_script_key(self) -> Optional[bytes]:
        def visitor(value: Any) -> Optional[bytes]:
            if isinstance(value, (bytes, bytearray)):
                return bytes(value)
            if isinstance(value, str):
                candidate = value.strip()
                if candidate:
                    return candidate.encode("utf-8", errors="ignore")
                return None
            if isinstance(value, Mapping):
                for key, item in value.items():
                    key_lower = str(key).lower()
                    if key_lower in {"script_key", "scriptkey", "key"}:
                        coerced = self._coerce_key_bytes(item)
                        if coerced is not None:
                            return coerced
                    nested = visitor(item)
                    if nested:
                        return nested
                return None
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                for item in value:
                    nested = visitor(item)
                    if nested:
                        return nested
            return None

        for container in (self._original, self._constants, self._prototypes):
            key = visitor(container)
            if key:
                return key
        return None

    def _coerce_key_bytes(self, value: Any) -> Optional[bytes]:
        if isinstance(value, bytes):
            return bytes(value)
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return b""
            stripped = text.replace(" ", "")
            try:
                decoded = base64.b64decode(stripped, validate=True)
            except Exception:
                decoded = None
            if decoded:
                return decoded
            if all(ch in "0123456789abcdefABCDEF" for ch in stripped) and len(stripped) % 2 == 0:
                try:
                    return bytes.fromhex(stripped)
                except ValueError:
                    pass
            return text.encode("utf-8", errors="ignore")
        if isinstance(value, Mapping) and "array" in value:
            return self._coerce_key_bytes(value.get("array"))
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            result = bytearray()
            for item in value:
                if isinstance(item, int):
                    result.append(item & 0xFF)
                elif isinstance(item, str) and item.isdigit():
                    result.append(int(item) & 0xFF)
                else:
                    return None
            return bytes(result)
        return None

    def _coerce_bytes(self, value: Any) -> Optional[bytes]:
        if isinstance(value, bytes):
            return bytes(value)
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return b""
            compressed = text.replace("\n", "").replace("\r", "").replace("\t", "").replace(" ", "")
            try:
                decoded = base64.b64decode(compressed, validate=True)
            except Exception:
                decoded = None
            if decoded:
                return decoded
            if all(ch in "0123456789abcdefABCDEF" for ch in compressed) and len(compressed) % 2 == 0:
                try:
                    return bytes.fromhex(compressed)
                except ValueError:
                    pass
            return text.encode("utf-8", errors="ignore")
        if isinstance(value, Mapping) and "array" in value:
            return self._coerce_bytes(value.get("array"))
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            result = bytearray()
            for item in value:
                if isinstance(item, int):
                    result.append(item & 0xFF)
                elif isinstance(item, str) and item.isdigit():
                    result.append(int(item) & 0xFF)
                else:
                    return None
            return bytes(result)
        return None

    def _looks_like_instruction_table(self, value: Any) -> bool:
        if isinstance(value, list):
            if not value:
                return False
            first = value[0]
            if isinstance(first, list):
                return len(first) >= 3
            if isinstance(first, Mapping):
                opcode = first.get("3") or first.get(3) or first.get("opcode")
                return isinstance(opcode, int)
        if isinstance(value, Mapping):
            sample = value.get("1") or value.get(1)
            if isinstance(sample, Mapping):
                opcode = sample.get("3") or sample.get(3) or sample.get("opcode")
                return isinstance(opcode, int)
        return False

    def _lua_to_python(self, value: Any) -> Any:
        if isinstance(value, LuaTable):
            mapping = value.to_python()
            # Determine if table can be represented as a pure array.
            array_keys = [key for key in mapping if isinstance(key, int) and key > 0]
            array_keys.sort()
            if array_keys and array_keys == list(range(1, len(array_keys) + 1)):
                return [self._lua_to_python(mapping[index]) for index in array_keys]
            return {
                self._lua_to_python(key): self._lua_to_python(val)
                for key, val in mapping.items()
            }
        if isinstance(value, list):
            return [self._lua_to_python(item) for item in value]
        if isinstance(value, dict):
            return {self._lua_to_python(key): self._lua_to_python(val) for key, val in value.items()}
        return value

    def _normalise_rehydrated_payload(self, payload: Any) -> Optional[Dict[str, Any]]:
        if isinstance(payload, LuaTable):
            payload = self._lua_to_python(payload)
        if isinstance(payload, Mapping):
            instructions = (
                payload.get("instructions")
                or payload.get("bytecode")
                or payload.get("code")
            )
            constants = payload.get("constants") or payload.get("consts") or []
            prototypes = payload.get("prototypes") or []
            if instructions is None:
                array_data = payload.get("array")
                if isinstance(array_data, list) and len(array_data) >= 4:
                    maybe_instr = array_data[3]
                    maybe_consts = array_data[4] if len(array_data) >= 5 else []
                    maybe_protos = array_data[5] if len(array_data) >= 6 else []
                    if self._looks_like_instruction_table(maybe_instr):
                        instructions = maybe_instr
                        constants = maybe_consts
                        prototypes = maybe_protos
            if instructions is None:
                instructions = payload.get("4") or payload.get(4)
                if instructions is not None:
                    constants = payload.get("5") or payload.get(5) or constants
                    prototypes = payload.get("6") or payload.get(6) or prototypes
            if instructions is not None:
                const_list = []
                if isinstance(constants, Sequence):
                    const_list = [self._lua_to_python(item) for item in constants]
                proto_list = []
                if isinstance(prototypes, Sequence):
                    proto_list = [self._lua_to_python(item) for item in prototypes]
                return {
                    "instructions": self._ensure_instruction_dicts(instructions),
                    "constants": const_list,
                    "prototypes": proto_list,
                }
        if isinstance(payload, list) and payload and self._looks_like_instruction_table(payload):
            return {
                "instructions": self._ensure_instruction_dicts(payload),
                "constants": [],
                "prototypes": [],
            }
        return None

    def _apply_encfunc_method(
        self,
        data: bytes,
        method: Optional[str],
        key_bytes: bytes,
        header: Mapping[str, Any],
    ) -> bytes:
        available_key = self._coerce_key_bytes(header.get("key")) or key_bytes
        label = (method or header.get("method") or header.get("cipher") or "").lower()
        candidates = []
        if label:
            candidates.append(label)
        for alias in ("xor", "rolling_xor", "rc4", "none"):
            if alias not in candidates:
                candidates.append(alias)

        for name in candidates:
            if name in {"none", "plain", "identity"}:
                return data
            if name in {"xor", "simple_xor", "keyxor"}:
                return _xor_bytes(data, available_key or key_bytes)
            if name in {"rolling_xor", "rolling-xor", "rolling", "rxor"}:
                return _rolling_xor_bytes(data, available_key or key_bytes)
            if name in {"rc4", "rc-4", "arc4"}:
                return _rc4_crypt(data, available_key or key_bytes)
        return data

    def _interpret_rehydrated_payload(
        self, data: bytes, header: Mapping[str, Any]
    ) -> tuple[Optional[Any], Optional[str], Dict[str, Any]]:
        attempts: List[tuple[str, bytes]] = [("raw", data)]
        compression = str(header.get("compression") or header.get("encoding") or "").lower()
        decompressors: List[tuple[str, Any]] = []
        if compression in {"zlib", "deflate"}:
            decompressors.append(("zlib", zlib.decompress))
        elif compression in {"bz2", "bzip2"}:
            decompressors.append(("bz2", bz2.decompress))
        elif compression in {"lzma", "xz"}:
            decompressors.append(("lzma", lzma.decompress))
        else:
            decompressors.extend(
                [("zlib", zlib.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)]
            )
        for label, func in decompressors:
            try:
                attempts.append((label, func(data)))
            except Exception:
                continue

        metadata = {"attempts": [label for label, _ in attempts]}

        for label, payload in attempts:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                text = None
            if text is not None:
                stripped = text.strip()
                if stripped:
                    try:
                        parsed_json = json.loads(stripped)
                    except json.JSONDecodeError:
                        parsed_json = None
                    if isinstance(parsed_json, (list, dict)):
                        metadata["decoded_with"] = label
                        return parsed_json, None, metadata
                    try:
                        parsed_lua = parse_lua_expression(stripped)
                    except Exception:
                        parsed_lua = None
                    if parsed_lua is not None:
                        metadata["decoded_with"] = label
                        return parsed_lua, None, metadata
                    if any(token in stripped for token in ("function", "local", "return")):
                        metadata["decoded_with"] = label
                        return None, text, metadata

        metadata["decoded_with"] = None
        return None, None, metadata

    def _extract_encfunc_blob(self, candidate: Any) -> Optional[Dict[str, Any]]:
        if isinstance(candidate, Mapping):
            lower_keys = {str(key).lower(): key for key in candidate.keys()}
            tag_value: Optional[str] = None
            for key in ("tag", "type", "kind", "name"):
                source_key = lower_keys.get(key)
                if source_key is not None:
                    value = candidate.get(source_key)
                    if isinstance(value, str) and "encfunc" in value.lower():
                        tag_value = value
                        break
            if tag_value is None:
                for key, original_key in lower_keys.items():
                    if "encfunc" in key:
                        tag_value = str(original_key)
                        candidate = candidate.get(original_key, candidate)
                        break
            blob_data: Any = None
            for field in ("data", "blob", "payload", "buffer", "bytes", "encoded", "value"):
                if field in candidate:
                    blob_data = candidate[field]
                    break
            if blob_data is None and "encfunc" in lower_keys:
                nested = candidate.get(lower_keys["encfunc"])
                if isinstance(nested, Mapping):
                    return self._extract_encfunc_blob(nested)
            if tag_value and blob_data is not None:
                header = candidate.get("header")
                header_map = header if isinstance(header, Mapping) else {}
                return {
                    "tag": tag_value,
                    "data": blob_data,
                    "method": candidate.get("method") or header_map.get("method") or header_map.get("cipher"),
                    "key": candidate.get("key") or candidate.get("script_key") or header_map.get("key"),
                    "header": header_map,
                    "raw": candidate,
                }
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes, bytearray)):
            if candidate and isinstance(candidate[0], str) and "encfunc" in candidate[0].lower():
                if len(candidate) >= 2 and isinstance(candidate[1], Mapping):
                    blob = dict(candidate[1])
                    blob.setdefault("tag", candidate[0])
                    return self._extract_encfunc_blob(blob)
        if isinstance(candidate, str) and "encfunc" in candidate.lower():
            return {"tag": "LPH_ENCFUNC", "data": candidate, "header": {}, "raw": candidate}
        return None

    def _rehydrate_encrypted_functions(self) -> None:
        for index, proto in enumerate(list(self._prototypes)):
            blob = self._extract_encfunc_blob(proto)
            if not blob:
                continue
            data_bytes = self._coerce_bytes(blob.get("data"))
            if data_bytes is None:
                continue
            key_candidate = self._coerce_key_bytes(blob.get("key")) or self._script_key_bytes
            try:
                decrypted = self._apply_encfunc_method(
                    data_bytes, blob.get("method"), key_candidate, blob.get("header", {})
                )
            except Exception as exc:
                LOG.debug("encfunc decode failed for proto %d: %s", index, exc)
                continue
            payload_obj, source_text, meta = self._interpret_rehydrated_payload(
                decrypted, blob.get("header", {})
            )
            normalised = None
            if payload_obj is not None:
                normalised = self._normalise_rehydrated_payload(payload_obj)
            payload: Dict[str, Any] = {}
            nested_output: Optional[LiftOutput] = None
            if normalised is not None:
                self._prototypes[index] = normalised
                try:
                    nested_output = lift_program(
                        normalised.get("instructions", []),
                        normalised.get("constants", []),
                        self._opcode_map,
                        prototypes=normalised.get("prototypes", []),
                        root=False,
                        script_key=self._script_key_bytes,
                        rehydration_state=self._rehydration_state,
                        limits=self._limits,
                        debug_logger=self._debug_logger,
                    )
                except Exception as exc:
                    LOG.debug("nested lift failed for rehydrated proto %d: %s", index, exc)
                    nested_output = None
                payload.update(normalised)
            elif source_text is not None:
                payload["lua_source"] = source_text
            else:
                payload["raw_bytes"] = base64.b64encode(decrypted).decode("ascii")

            if not payload:
                continue

            self._rehydration_state["counter"] += 1
            self._rehydration_state["count"] += 1
            self._local_rehydrated_count += 1
            func_name = f"decrypted_func_{self._rehydration_state['counter']}"
            info = {
                "name": func_name,
                "payload": payload,
                "metadata": meta,
                "blob": blob,
            }
            if nested_output is not None:
                info["lift_output"] = nested_output
            self._rehydrated_info[index] = info
            if normalised is None:
                self._prototypes[index] = payload
            detail = {
                "index": index,
                "name": func_name,
                "tag": blob.get("tag"),
                "decoded_with": meta.get("decoded_with"),
            }
            self._metadata.setdefault("rehydrated_details", []).append(detail)
        if self._local_rehydrated_count:
            self._metadata["rehydrated_functions"] = self._local_rehydrated_count

    def _prepare_instructions(self) -> None:
        for entry in self._original:
            opnum = entry.get("opcode")
            if opnum is None:
                opnum = entry.get("opnum")
            mnemonic: Optional[str] = None
            if isinstance(opnum, int):
                mnemonic = self._opcode_map.get(opnum)
            if not mnemonic:
                mnemonic = entry.get("mnemonic") or entry.get("op")
            mnemonic = canonicalise_opcode_name(mnemonic) or (
                f"OP_{int(opnum):02X}" if isinstance(opnum, int) else "OP_UNKNOWN"
            )
            entry["mnemonic"] = mnemonic
            if "opcode" not in entry and isinstance(opnum, int):
                entry["opcode"] = opnum
            if "opnum" not in entry and isinstance(opnum, int):
                entry["opnum"] = opnum
            if "pc" not in entry:
                index = entry.get("index")
                if isinstance(index, int):
                    entry["pc"] = index + 1

    def _prepare_labels(self) -> None:
        block_starts: set[int] = {0}
        for index, entry in enumerate(self._original):
            mnemonic = str(entry.get("mnemonic") or "").upper()
            if mnemonic in {"JMP", "RETURN"} and index + 1 < len(self._original):
                block_starts.add(index + 1)
            if mnemonic in {"EQ", "LT"} and index + 1 < len(self._original):
                block_starts.add(index + 1)
            if mnemonic == "JMP":
                target = self._jump_target(index, entry)
                if target is not None:
                    block_starts.add(target)
            next_entry = self._peek(index + 1)
            if mnemonic in {"EQ", "LT"} and next_entry:
                target = self._jump_target(index + 1, next_entry)
                if target is not None:
                    block_starts.add(target)

        ordered = sorted(i for i in block_starts if 0 <= i < len(self._original))
        self._labels = {idx: f"label_{idx + 1:04d}" for idx in ordered}
        self._block_order = {idx: pos + 1 for pos, idx in enumerate(ordered)}

    def _discover_loops(self) -> None:
        for index, entry in enumerate(self._original):
            mnemonic = str(entry.get("mnemonic") or "").upper()
            if mnemonic != "JMP":
                continue
            target = self._jump_target(index, entry)
            if target is None or target > index:
                continue
            self._loop_start_to_end.setdefault(target, []).append(index)
            self._loop_end_to_start[index] = target
        for ends in self._loop_start_to_end.values():
            ends.sort()

    # ------------------------------------------------------------------
    # Prototype helpers
    # ------------------------------------------------------------------

    def _resolve_prototype_payload(
        self, entry: Mapping[str, Any], proto_index: Optional[int]
    ) -> Optional[Dict[str, Any]]:
        if isinstance(proto_index, int) and proto_index in self._rehydrated_info:
            info = self._rehydrated_info.get(proto_index, {})
            payload = info.get("payload")
            if isinstance(payload, Mapping):
                normalised = self._normalise_prototype_candidate(payload)
                return normalised or payload  # type: ignore[return-value]
        candidates: List[Any] = []
        for key in ("prototype", "proto", "function", "body"):
            value = entry.get(key)
            if value is not None:
                candidates.append(value)
        embedded = entry.get("prototypes")
        if isinstance(embedded, Sequence):
            if isinstance(proto_index, int) and 0 <= proto_index < len(embedded):
                candidates.append(embedded[proto_index])
        if isinstance(proto_index, int):
            if 0 <= proto_index < len(self._prototypes):
                candidates.append(self._prototypes[proto_index])
        for candidate in candidates:
            payload = self._normalise_prototype_candidate(candidate)
            if payload:
                return payload
        return None

    def _normalise_prototype_candidate(self, candidate: Any) -> Optional[Dict[str, Any]]:
        if candidate is None:
            return None
        if isinstance(candidate, Mapping):
            instructions = (
                candidate.get("instructions")
                or candidate.get("bytecode")
                or candidate.get("code")
                or candidate.get("ops")
            )
            if instructions is None and "array" in candidate:
                maybe_list = candidate.get("array")
                if isinstance(maybe_list, list):
                    instructions = maybe_list
            constants = candidate.get("constants") or []
            prototypes = candidate.get("prototypes") or []
            if instructions is not None:
                return {
                    "instructions": instructions,
                    "constants": constants,
                    "prototypes": prototypes,
                }
        if isinstance(candidate, list):
            return {"instructions": candidate, "constants": [], "prototypes": []}
        if hasattr(candidate, "instructions"):
            proto_instructions: List[Any] = []
            for instr in getattr(candidate, "instructions", []):
                if isinstance(instr, Mapping):
                    proto_instructions.append(dict(instr))
                elif hasattr(instr, "ir") and isinstance(instr.ir, Mapping):
                    proto_instructions.append(dict(instr.ir))
                elif hasattr(instr, "__dict__"):
                    proto_instructions.append(dict(instr.__dict__))
            if not proto_instructions:
                return None
            constants = list(getattr(candidate, "constants", []))
            prototypes = list(getattr(candidate, "prototypes", []))
            return {
                "instructions": proto_instructions,
                "constants": constants,
                "prototypes": prototypes,
            }
        return None

    def _nested_function_name(self, proto_index: Optional[int]) -> str:
        if proto_index is None:
            return "closure_fn"
        info = None
        if isinstance(proto_index, int):
            info = self._rehydrated_info.get(proto_index)
        if info and isinstance(info.get("name"), str):
            return str(info["name"])
        return f"closure_{proto_index}"

    def _ensure_instruction_dicts(self, items: Iterable[Any]) -> List[Dict[str, Any]]:
        instructions: List[Dict[str, Any]] = []
        for item in items:
            if isinstance(item, Mapping):
                instructions.append(dict(item))
            elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
                instructions.append({"raw": list(item)})
            else:
                instructions.append({"value": item})
        return instructions

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self) -> List[TranslationResult]:
        translations: List[TranslationResult] = []
        instruction_records: List[Dict[str, Any]] = []
        partial_abort = False
        for index, entry in enumerate(self._original):
            if self._should_abort():
                partial_abort = True
                break
            if not self._consume_budget():
                partial_abort = True
                break
            self._active_loops = list(self._loop_stack)
            result = self._translate(entry, index)

            lua_render = self._format_lines(result.lines)
            record = {
                "pc": entry.get("pc"),
                "opcode": entry.get("opcode"),
                "op": entry.get("mnemonic"),
                "a": self._as_int(entry.get("A")),
                "b": self._as_int(entry.get("B")),
                "c": self._as_int(entry.get("C")),
                "comment": result.comment,
                "lua": lua_render,
            }
            if result.metadata:
                record.update(result.metadata)
            self._ir_rows.append(record)
            instruction_records.append(record)

            translations.append(result)
            self._log_instruction(index, entry, result)
            self._snapshot(index, entry, record)
            self._processed_instructions += 1

        self._metadata.setdefault(
            "processed_instructions", self._processed_instructions
        )

        if partial_abort or (self._limits and self._limits.partial):
            self._mark_partial_from_limits()
            self._render_partial(translations)
            return translations

        builder = CFGBuilder(
            self._original,
            translations,
            labels=self._labels,
            label_for=self._label_for,
        )
        cfg = builder.build()
        emitter = StructuredEmitter(
            cfg,
            translations,
        )
        structured_lines, instruction_lua = emitter.emit()

        for index, record in enumerate(instruction_records):
            record["lua"] = instruction_lua.get(index, record.get("lua", ""))

        self._lines.clear()
        if self._root:
            self._lines.extend(
                [
                    "-- lift_ir.lua (auto-generated)",
                    "local R = {}",
                    "local stack = {}",
                    "local frames = {}",
                    "",
                ]
            )

        self._lines.extend(structured_lines)

        if self._root:
            self._lines.append("")
            self._lines.append("return { registers = R, stack = stack, frames = frames }")

        return translations

    # ------------------------------------------------------------------
    # Translation helpers
    # ------------------------------------------------------------------

    def _translate(self, entry: Mapping[str, Any], index: int) -> TranslationResult:
        mnemonic = str(entry.get("mnemonic") or "").upper()
        translator = {
            "MOVE": self._translate_move,
            "LOADK": self._translate_loadk,
            "CALL": self._translate_call,
            "RETURN": self._translate_return,
            "GETTABLE": self._translate_gettable,
            "SETTABLE": self._translate_settable,
            "CLOSURE": self._translate_closure,
            "ADD": lambda e, i: self._translate_arith(e, i, "+"),
            "SUB": lambda e, i: self._translate_arith(e, i, "-"),
            "MUL": lambda e, i: self._translate_arith(e, i, "*"),
            "DIV": lambda e, i: self._translate_arith(e, i, "/"),
            "EQ": self._translate_eq,
            "LT": self._translate_lt,
            "JMP": self._translate_jmp,
        }.get(mnemonic)

        if translator is None:
            return self._translate_unknown(entry)
        return translator(entry, index)

    def _translate_move(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        dest = self._reg(A)
        src = self._reg(B)
        value = self._register_state.get(B, src)
        if isinstance(A, int):
            self._register_state[A] = value
        line = f"{dest} = {value}  -- MOVE"
        comment = f"MOVE {dest} <- {value}"
        return TranslationResult([line], comment)

    def _translate_loadk(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        const_index = self._infer_constant(entry)
        literal = self._format_constant(const_index)
        dest = self._reg(A)
        if isinstance(A, int):
            self._register_state[A] = literal
        if const_index is None:
            comment = f"LOADK {dest} <- {literal}"
        else:
            comment = f"LOADK {dest} <- K[{const_index}]"
        return TranslationResult([f"{dest} = {literal}  -- LOADK"], comment)

    def _translate_call(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        func = self._reg(A)
        args = self._call_args(A, B)
        call_expr = f"{func}({', '.join(args)})" if args else f"{func}()"
        stack_lines = [f"stack[#stack+1] = {arg}  -- arg" for arg in args]
        comment = f"CALL {func}"
        returns_meta: Any
        if C == 0:
            returns_meta = "vararg"
        else:
            returns_meta = max((C or 0) - 1, 0)
        self.push_frame(A, returns_meta, call_expr)
        if C == 0:
            frame_note = "frames[#frames+1] = { base = %s, returns = 'vararg' }" % (
                str(A) if isinstance(A, int) else "nil"
            )
            lines = stack_lines + [frame_note, f"{call_expr}  -- CALL (variadic returns)"]
            return TranslationResult(lines, comment + " -> variadic")
        if C == 1:
            frame_note = "frames[#frames+1] = { base = %s, returns = 0 }" % (
                str(A) if isinstance(A, int) else "nil"
            )
            lines = stack_lines + [frame_note, f"{call_expr}  -- CALL"]
            return TranslationResult(lines, comment)
        targets = [self._reg((A or 0) + offset) for offset in range((C or 1) - 1)]
        assign = ", ".join(targets)
        frame_note = "frames[#frames+1] = { base = %s, returns = %s }" % (
            str(A) if isinstance(A, int) else "nil",
            str((C or 1) - 1),
        )
        if isinstance(A, int) and isinstance(C, int) and C > 1:
            for offset in range(C - 1):
                target_index = A + offset
                if offset == 0:
                    self._register_state[target_index] = call_expr
                else:
                    self._register_state[target_index] = f"{call_expr}__{offset}"
        lines = stack_lines + [frame_note, f"{assign} = {call_expr}  -- CALL"]
        return TranslationResult(lines, comment + f" -> {assign}")

    def _translate_return(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        self.pop_frame()
        frame_pop = "frames[#frames] = nil"
        if B == 0:
            lines = [frame_pop, "return ...  -- RETURN"]
            return TranslationResult(lines, "RETURN varargs")
        if B == 1:
            lines = [frame_pop, "return  -- RETURN"]
            return TranslationResult(lines, "RETURN")
        values = [self._reg((A or 0) + offset) for offset in range((B or 1) - 1)]
        lines = [frame_pop, f"return {', '.join(values)}  -- RETURN"]
        return TranslationResult(lines, f"RETURN {values}")

    def _translate_gettable(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        dest = self._reg(A)
        table = self._reg(B)
        key = self._rk(C)
        expr = f"{table}[{key}]"
        if isinstance(A, int):
            self._register_state[A] = expr
        return TranslationResult([f"{dest} = {expr}  -- GETTABLE"], f"GETTABLE {dest} <- {expr}")

    def _translate_settable(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        table = self._reg(A)
        key = self._rk(B)
        value = self._rk(C)
        line = f"{table}[{key}] = {value}  -- SETTABLE"
        return TranslationResult([line], f"SETTABLE {table}[{key}] = {value}")

    def _translate_closure(self, entry: Mapping[str, Any], _: int) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        proto = self._as_int(entry.get("Bx"))
        dest = self._reg(A)
        payload = self._resolve_prototype_payload(entry, proto)
        metadata: Dict[str, Any] = {}
        if isinstance(proto, int) and proto not in self._function_prototypes:
            self._function_prototypes.add(proto)
            self._function_count += 1
        lines: List[str] = []
        info = self._rehydrated_info.get(proto) if isinstance(proto, int) else None
        if info:
            nested_name = self._nested_function_name(proto)
            body_lines: List[str]
            nested_output: Optional[LiftOutput] = info.get("lift_output")
            payload_map = info.get("payload", {})
            if nested_output:
                body_lines = nested_output.lua_source.strip().splitlines()
            elif isinstance(payload_map, Mapping) and isinstance(
                payload_map.get("lua_source"), str
            ):
                body_lines = str(payload_map.get("lua_source", "")).strip().splitlines()
            else:
                body_lines = ["-- unable to decode encrypted function"]
            metadata["closure"] = {
                "name": nested_name,
                "rehydrated": True,
                "metadata": info.get("metadata", {}),
            }
            if nested_output:
                metadata["closure"].update(
                    {
                        "lua": nested_output.lua_source,
                        "ir": nested_output.ir_entries,
                        "stack_trace": nested_output.stack_trace,
                        "lift_metadata": nested_output.metadata,
                    }
                )
            elif isinstance(payload_map, Mapping) and isinstance(
                payload_map.get("lua_source"), str
            ):
                metadata["closure"]["lua"] = str(payload_map["lua_source"])
            lines.append(f"local function {nested_name}()")
            lines.append("{INDENT}")
            for nested_line in body_lines:
                lines.append(nested_line)
            lines.append("{DEDENT}")
            lines.append("end")
            lines.append(f"{dest} = {nested_name}  -- CLOSURE")
            if isinstance(A, int):
                self._register_state[A] = nested_name
            metadata["rehydrated"] = True
            return TranslationResult(lines, f"CLOSURE {dest}", metadata=metadata)
        if payload is not None:
            nested_name = self._nested_function_name(proto)
            nested_output = lift_program(
                self._ensure_instruction_dicts(payload.get("instructions", [])),
                payload.get("constants", []),
                self._opcode_map,
                prototypes=payload.get("prototypes", []),
                root=False,
                script_key=self._script_key_bytes,
                rehydration_state=self._rehydration_state,
                limits=self._limits,
                debug_logger=self._debug_logger,
            )
            metadata["closure"] = {
                "name": nested_name,
                "lua": nested_output.lua_source,
                "ir": nested_output.ir_entries,
                "stack_trace": nested_output.stack_trace,
                "lift_metadata": nested_output.metadata,
            }
            lines.append(f"local function {nested_name}()")
            lines.append("{INDENT}")
            for nested_line in nested_output.lua_source.strip().splitlines():
                lines.append(nested_line)
            lines.append("{DEDENT}")
            lines.append("end")
            lines.append(f"{dest} = {nested_name}  -- CLOSURE")
            if isinstance(A, int):
                self._register_state[A] = nested_name
            return TranslationResult(lines, f"CLOSURE {dest}", metadata=metadata)
        literal = f"closure(proto_{proto if proto is not None else '???'})"
        if isinstance(A, int):
            self._register_state[A] = literal
        return TranslationResult([f"{dest} = {literal}  -- CLOSURE"], f"CLOSURE {dest}")

    def _translate_arith(
        self, entry: Mapping[str, Any], _: int, op: str
    ) -> TranslationResult:
        A = self._as_int(entry.get("A"))
        B = self._as_int(entry.get("B"))
        C = self._as_int(entry.get("C"))
        left = self._rk(B)
        right = self._rk(C)
        dest = self._reg(A)
        expr = f"{left} {op} {right}"
        if isinstance(A, int):
            self._register_state[A] = expr
        mnemonic = entry.get("mnemonic", op)
        return TranslationResult([f"{dest} = {expr}  -- {mnemonic}"], f"{mnemonic} {dest}")

    def _translate_eq(self, entry: Mapping[str, Any], index: int) -> TranslationResult:
        condition = self._comparison_condition(entry, "==")
        target_index = self._conditional_target_index(index)
        if self._is_loop_break(index, target_index):
            lines = [
                f"if {condition} then  -- EQ",
                "{INDENT}",
                "break",
                "{DEDENT}",
                "end",
            ]
            return TranslationResult(lines, "EQ -> break")

        false_target = self._conditional_fallthrough_index(index)
        if target_index is not None:
            self._pending_conditionals[index + 1] = {
                "condition": condition,
                "false_target": false_target,
                "guard_index": index,
            }
        comment = f"EQ condition -> {self._label_for(target_index)}"
        return TranslationResult([], comment, metadata={"condition": condition})

    def _translate_lt(self, entry: Mapping[str, Any], index: int) -> TranslationResult:
        condition = self._comparison_condition(entry, "<")
        target_index = self._conditional_target_index(index)
        if self._is_loop_break(index, target_index):
            lines = [
                f"if {condition} then  -- LT",
                "{INDENT}",
                "break",
                "{DEDENT}",
                "end",
            ]
            return TranslationResult(lines, "LT -> break")

        false_target = self._conditional_fallthrough_index(index)
        if target_index is not None:
            self._pending_conditionals[index + 1] = {
                "condition": condition,
                "false_target": false_target,
                "guard_index": index,
            }
        comment = f"LT condition -> {self._label_for(target_index)}"
        return TranslationResult([], comment, metadata={"condition": condition})

    def _translate_jmp(self, entry: Mapping[str, Any], index: int) -> TranslationResult:
        target = self._jump_target(index, entry)
        if target is None:
            return TranslationResult(["-- jump target unresolved"], "JMP unresolved")
        conditional = self._pending_conditionals.pop(index, None)
        if conditional:
            false_target = conditional.get("false_target")
            guard_index = conditional.get("guard_index")
            metadata = {
                "condition": conditional.get("condition"),
                "control": {
                    "type": "cond",
                    "condition": conditional.get("condition"),
                    "true_target": target,
                    "false_target": false_target,
                    "guard_index": guard_index,
                },
            }
            comment = f"COND -> {self._label_for(target)}"
            return TranslationResult([], comment, metadata=metadata)

        if index in self._loop_end_to_start:
            start = self._loop_end_to_start[index]
            label = self._label_for(start)
            lines = ["{DEDENT}", f"end  -- while loop {label}"]
            return TranslationResult(lines, f"JMP -> {label}", metadata={"loop_end": start})
        metadata = {"control": {"type": "jump", "target": target}}
        label = self._labels.get(target, f"label_{target + 1:04d}")
        return TranslationResult([], f"JMP -> {label}", metadata=metadata)

    def _translate_unknown(self, entry: Mapping[str, Any]) -> TranslationResult:
        opnum = entry.get("opcode") or entry.get("opnum")
        opcode_text = f"0x{int(opnum):02X}" if isinstance(opnum, int) else "<unknown>"
        line = (
            f"-- unknown opcode {opcode_text} (A={entry.get('A')}, B={entry.get('B')}, C={entry.get('C')})"
        )
        return TranslationResult([line], f"UNKNOWN {opcode_text}")

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _emit_line(self, text: str, indent: int) -> None:
        indent = max(indent, 0)
        if text == "":
            self._lines.append("")
        else:
            self._lines.append("  " * indent + text)

    def _format_lines(self, fragments: Iterable[str]) -> str:
        indent = 0
        rendered: List[str] = []
        for fragment in fragments:
            if fragment == "{DEDENT}":
                indent = max(indent - 1, 0)
                continue
            if fragment == "{INDENT}":
                indent += 1
                continue
            rendered.append("  " * indent + fragment)
        return "\n".join(rendered).rstrip()

    def _snapshot(self, index: int, entry: Mapping[str, Any], record: Mapping[str, Any]) -> None:
        self.snapshot(
            index,
            entry.get("pc"),
            entry.get("mnemonic"),
            record.get("comment"),
        )

    def _log_instruction(
        self,
        index: int,
        entry: Mapping[str, Any],
        result: TranslationResult,
    ) -> None:
        if self._debug_logger is None:
            return
        mnemonic = str(
            entry.get("mnemonic")
            or entry.get("op")
            or entry.get("opcode")
            or f"OP_{index:02X}"
        )
        operands: List[str] = []
        for key in ("A", "B", "C", "Bx", "sBx"):
            value = entry.get(key)
            if value is None:
                continue
            operands.append(f"{key}={value}")
        summary = " | ".join(line.strip() for line in result.lines if line.strip())
        if not summary:
            summary = result.comment or ""
        registers = ", ".join(
            f"{self.register_name(reg)}={value}"
            for reg, value in sorted(self._register_state.items())
        )
        self._debug_logger.debug(
            "[%04d] %s %s => %s || registers: %s",
            index,
            mnemonic,
            " ".join(operands).strip(),
            summary or "<no-op>",
            registers or "<empty>",
        )

    def _peek(self, index: int) -> Optional[Mapping[str, Any]]:
        if 0 <= index < len(self._original):
            return self._original[index]
        return None

    def _label_for(self, index: int) -> str:
        return self._labels.get(index, f"label_{index + 1:04d}")

    def _conditional_target(self, index: int) -> str:
        next_entry = self._peek(index + 1)
        if next_entry and str(next_entry.get("mnemonic") or "").upper() == "JMP":
            target = self._jump_target(index + 1, next_entry)
            if target is not None:
                return self._label_for(target)
        return self._label_for(index + 1)

    def _conditional_target_index(self, index: int) -> Optional[int]:
        next_entry = self._peek(index + 1)
        if next_entry and str(next_entry.get("mnemonic") or "").upper() == "JMP":
            target = self._jump_target(index + 1, next_entry)
            if target is not None:
                return target
        next_index = index + 1
        if next_index < len(self._original):
            return next_index
        return None

    def _conditional_fallthrough_index(self, index: int) -> Optional[int]:
        next_entry = self._peek(index + 1)
        if next_entry and str(next_entry.get("mnemonic") or "").upper() == "JMP":
            skip_index = index + 2
            if skip_index < len(self._original):
                return skip_index
            return None
        fallthrough = index + 1
        if fallthrough < len(self._original):
            return fallthrough
        return None

    def _jump_target(self, index: int, entry: Mapping[str, Any]) -> Optional[int]:
        sbx = entry.get("sBx")
        if not isinstance(sbx, int):
            return None
        target = index + 1 + sbx
        if 0 <= target < len(self._original):
            return target
        return None

    def _comparison_condition(self, entry: Mapping[str, Any], operator: str) -> str:
        lhs = self._rk(self._as_int(entry.get("B")))
        rhs = self._rk(self._as_int(entry.get("C")))
        expect_true = bool(self._as_int(entry.get("A")))
        if expect_true:
            return f"{lhs} {operator} {rhs}"
        return f"not ({lhs} {operator} {rhs})"

    def _is_loop_break(self, index: int, target: Optional[int]) -> bool:
        if target is None:
            return False
        for start, end in self._active_loops:
            if start <= index <= end and target == end + 1:
                return True
        return False

    def _call_args(self, base: int, count: Optional[int]) -> List[str]:
        return self.call_args(base, count)

    def _infer_constant(self, entry: Mapping[str, Any]) -> Optional[int]:
        bx = entry.get("Bx")
        if isinstance(bx, int) and bx >= 0:
            return bx
        b = entry.get("B")
        if isinstance(b, int) and b >= 0:
            return b
        raw = entry.get("raw")
        if isinstance(raw, list):
            for value in raw:
                if isinstance(value, int) and value >= 0:
                    return value
        if isinstance(raw, dict):
            for value in raw.values():
                if isinstance(value, int) and value >= 0:
                    return value
        return None

    def _rk(self, value: Optional[int]) -> str:
        return self.rk(value)

    def _format_constant(self, index: Optional[int]) -> str:
        return self.format_constant(index)

    def _lua_literal(self, value: Any) -> str:
        return self.lua_literal(value)

    @staticmethod
    def _as_int(value: Any) -> Optional[int]:
        return int(value) if isinstance(value, int) else None

    def _reg(self, index: Optional[int]) -> str:
        return self.reg(index)


__all__ = ["lift_program", "LiftOutput"]
