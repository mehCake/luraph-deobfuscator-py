"""Helpers for decoding ``LPH_ENCFUNC`` blobs into liftable payloads."""

from __future__ import annotations

import base64
import bz2
import hashlib
import json
import logging
import lzma
import zlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from lua_literal_parser import LuaTable, parse_lua_expression

LOG = logging.getLogger(__name__)


@dataclass
class EncFuncResult:
    """Result returned by :func:`rehydrate_encfunc`."""

    proto: Optional[Dict[str, Any]]
    lua_source: Optional[str]
    raw_bytes: Optional[bytes]
    recovery_method: str
    confidence: str
    metadata: Dict[str, Any]


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(data)
    key_len = len(key)
    return bytes((byte ^ key[i % key_len]) & 0xFF for i, byte in enumerate(data))


def _rolling_xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return bytes(data)
    out = bytearray(len(data))
    prev = 0
    key_len = len(key)
    for index, byte in enumerate(data):
        key_byte = key[index % key_len]
        plain = (byte ^ key_byte ^ prev) & 0xFF
        out[index] = plain
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


def coerce_key_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return b""
        try:
            return base64.b64decode(stripped, validate=True)
        except Exception:
            pass
        if all(ch in "0123456789abcdefABCDEF" for ch in stripped) and len(stripped) % 2 == 0:
            try:
                return bytes.fromhex(stripped)
            except ValueError:
                pass
        return stripped.encode("utf-8", errors="ignore")
    if isinstance(value, Mapping) and "array" in value:
        return coerce_key_bytes(value.get("array"))
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


def coerce_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return b""
        stripped = (
            text.replace("\n", "")
            .replace("\r", "")
            .replace("\t", "")
            .replace(" ", "")
        )
        try:
            return base64.b64decode(stripped, validate=True)
        except Exception:
            pass
        if all(ch in "0123456789abcdefABCDEF" for ch in stripped) and len(stripped) % 2 == 0:
            try:
                return bytes.fromhex(stripped)
            except ValueError:
                pass
        return text.encode("utf-8", errors="ignore")
    if isinstance(value, Mapping) and "array" in value:
        return coerce_bytes(value.get("array"))
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


def _looks_like_instruction_table(value: Any) -> bool:
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


def _lua_to_python(value: Any) -> Any:
    if isinstance(value, LuaTable):
        mapping = value.to_python()
        array_keys = [key for key in mapping if isinstance(key, int) and key > 0]
        array_keys.sort()
        if array_keys and array_keys == list(range(1, len(array_keys) + 1)):
            return [_lua_to_python(mapping[index]) for index in array_keys]
        return {_lua_to_python(key): _lua_to_python(val) for key, val in mapping.items()}
    if isinstance(value, list):
        return [_lua_to_python(item) for item in value]
    if isinstance(value, dict):
        return {_lua_to_python(key): _lua_to_python(val) for key, val in value.items()}
    return value


def _ensure_instruction_dicts(items: Iterable[Any]) -> List[Dict[str, Any]]:
    instructions: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, Mapping):
            instructions.append(dict(item))
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            instructions.append({"raw": list(item)})
        else:
            instructions.append({"value": item})
    return instructions


def _coerce_sequence(value: Any) -> Optional[List[Any]]:
    if isinstance(value, LuaTable):
        value = value.to_python()
    if isinstance(value, Mapping):
        array_data = value.get("array")
        if isinstance(array_data, Sequence) and not isinstance(array_data, (str, bytes, bytearray)):
            return list(array_data)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return None


def _normalise_rehydrated_payload(payload: Any) -> Optional[Dict[str, Any]]:
    if isinstance(payload, LuaTable):
        payload = _lua_to_python(payload)
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
                if _looks_like_instruction_table(maybe_instr):
                    instructions = maybe_instr
                    constants = maybe_consts
                    prototypes = maybe_protos
        if instructions is None:
            instructions = payload.get("4") or payload.get(4)
            if instructions is not None:
                constants = payload.get("5") or payload.get(5) or constants
                prototypes = payload.get("6") or payload.get(6) or prototypes
        if instructions is not None:
            proto_constants = list(constants) if isinstance(constants, Sequence) else []
            proto_prototypes = list(prototypes) if isinstance(prototypes, Sequence) else []
            upvalues = payload.get("upvalues") if isinstance(payload, Mapping) else []
            upvalue_entries = _coerce_sequence(upvalues) or []
            return {
                "instructions": _ensure_instruction_dicts(instructions),
                "constants": [_lua_to_python(item) for item in proto_constants],
                "prototypes": [_lua_to_python(item) for item in proto_prototypes],
                "upvalues": [_lua_to_python(item) for item in upvalue_entries],
            }
    if isinstance(payload, list):
        return {
            "instructions": _ensure_instruction_dicts(payload),
            "constants": [],
            "prototypes": [],
            "upvalues": [],
        }
    return None


def _proto_digest_counts(
    payload: Any,
    normalised: Optional[Mapping[str, Any]],
) -> Tuple[int, int, int]:
    code_len = 0
    const_len = 0
    upvalue_len = 0

    if isinstance(normalised, Mapping):
        instructions = normalised.get("instructions")
        if isinstance(instructions, Sequence):
            code_len = len(instructions)
        constants = normalised.get("constants")
        if isinstance(constants, Sequence):
            const_len = len(constants)
        upvalues = normalised.get("upvalues")
        if isinstance(upvalues, Sequence):
            upvalue_len = len(upvalues)

    if code_len == 0 and payload is not None:
        if isinstance(payload, Mapping):
            for key in ("instructions", "code", "bytecode", "opcodes"):
                seq = _coerce_sequence(payload.get(key))
                if seq is not None:
                    code_len = len(seq)
                    break
        elif isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
            code_len = len(payload)

    if const_len == 0 and isinstance(payload, Mapping):
        for key in ("constants", "consts", "k", "values"):
            seq = _coerce_sequence(payload.get(key))
            if seq is not None:
                const_len = len(seq)
                break

    if upvalue_len == 0 and isinstance(payload, Mapping):
        for key in ("upvalues", "upvals", "upvalue_map"):
            seq = _coerce_sequence(payload.get(key))
            if seq is not None:
                upvalue_len = len(seq)
                break
        if upvalue_len == 0:
            for key in ("nups", "num_upvalues", "upvalue_count"):
                raw = payload.get(key)
                if isinstance(raw, (int, float)):
                    upvalue_len = int(raw)
                    break

    return code_len, const_len, upvalue_len


def _compute_rehydration_digest(
    payload: Any,
    normalised: Optional[Mapping[str, Any]],
) -> Optional[str]:
    code_len, const_len, upvalue_len = _proto_digest_counts(payload, normalised)
    try:
        digest_input = f"{code_len}|{const_len}|{upvalue_len}".encode("ascii")
    except UnicodeEncodeError:  # pragma: no cover - defensive
        return None
    return hashlib.sha1(digest_input).hexdigest()


def _interpret_rehydrated_payload(data: bytes) -> Tuple[Optional[Any], Optional[str], Dict[str, Any]]:
    attempts: List[Tuple[str, bytes]] = [("raw", data)]
    metadata: Dict[str, Any] = {}

    for label, func in (("zlib", zlib.decompress), ("bz2", bz2.decompress), ("lzma", lzma.decompress)):
        try:
            attempts.append((label, func(data)))
        except Exception:
            continue

    metadata["attempts"] = [label for label, _ in attempts]

    for label, payload in attempts:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text:
            stripped = text.strip()
            if not stripped:
                continue
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
                return None, stripped, metadata

    metadata["decoded_with"] = None
    return None, None, metadata


def _invoke_callable(func: Callable[..., bytes], data: bytes, key: bytes) -> bytes:
    try:
        return func(data, key)
    except TypeError:
        return func(data)


def _normalise_spec_entry(entry: Any) -> List[Any]:
    if entry is None:
        return []
    if callable(entry):
        return [entry]
    if isinstance(entry, (bytes, bytearray)):
        return []
    if isinstance(entry, str):
        return [entry]
    if isinstance(entry, Mapping):
        values: List[Any] = []
        for key in ("callable", "func", "function", "handler"):
            candidate = entry.get(key)
            if callable(candidate):
                values.append(candidate)
        for key in ("method", "name", "cipher", "type"):
            candidate = entry.get(key)
            if isinstance(candidate, str):
                values.append(candidate)
        for key in ("methods", "candidates", "options", "aliases"):
            candidate = entry.get(key)
            if isinstance(candidate, Sequence) and not isinstance(candidate, (bytes, bytearray, str)):
                for item in candidate:
                    values.extend(_normalise_spec_entry(item))
        return values
    if isinstance(entry, Sequence):
        values: List[Any] = []
        for item in entry:
            if isinstance(item, (bytes, bytearray)):
                continue
            values.extend(_normalise_spec_entry(item))
        return values
    return []


def extract_encfunc_blob(candidate: Any) -> Optional[Dict[str, Any]]:
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
                return extract_encfunc_blob(nested)
        if tag_value and blob_data is not None:
            header = candidate.get("header")
            header_map = header if isinstance(header, Mapping) else {}
            return {
                "tag": tag_value,
                "data": blob_data,
                "method": candidate.get("method")
                or header_map.get("method")
                or header_map.get("cipher"),
                "key": candidate.get("key")
                or candidate.get("script_key")
                or header_map.get("key"),
                "header": header_map,
                "raw": candidate,
            }
    if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes, bytearray)):
        if candidate and isinstance(candidate[0], str) and "encfunc" in candidate[0].lower():
            if len(candidate) >= 2 and isinstance(candidate[1], Mapping):
                blob = dict(candidate[1])
                blob.setdefault("tag", candidate[0])
                return extract_encfunc_blob(blob)
    if isinstance(candidate, str) and "encfunc" in candidate.lower():
        return {"tag": "LPH_ENCFUNC", "data": candidate, "header": {}, "raw": candidate}
    return None


def rehydrate_encfunc(
    blob_bytes: bytes,
    key_bytes: Optional[bytes],
    decryptor_spec: Any = None,
) -> EncFuncResult:
    key = key_bytes or b""
    preferred_entries = _normalise_spec_entry(decryptor_spec)
    preferred_labels: List[str] = []
    candidate_attempts: List[Tuple[str, Callable[[], bytes]]] = []

    for entry in preferred_entries:
        if callable(entry):
            label = getattr(entry, "__name__", "bootstrap_callable")
            preferred_labels.append(label.lower())

            def _make_callable(func: Callable[..., bytes]) -> Callable[[], bytes]:
                return lambda func=func: _invoke_callable(func, blob_bytes, key)

            candidate_attempts.append((label, _make_callable(entry)))
        elif isinstance(entry, str):
            label = entry
            preferred_labels.append(label.lower())
            method = _method_from_label(label, blob_bytes, key)
            if method:
                candidate_attempts.append((label, method))

    fallback_order = ["rolling_xor", "xor", "rc4", "raw"]
    seen_labels = {label.lower() for label, _ in candidate_attempts}
    for label in fallback_order:
        if label in seen_labels:
            continue
        method = _method_from_label(label, blob_bytes, key)
        if method:
            candidate_attempts.append((label, method))
            seen_labels.add(label)

    errors: List[str] = []
    attempted: List[str] = []
    last_payload: bytes = blob_bytes
    last_meta: Dict[str, Any] = {"attempts": []}
    normalised: Optional[Dict[str, Any]] = None
    lua_source: Optional[str] = None
    method_used = "raw"
    last_digest: Optional[str] = None

    for label, decrypt_callable in candidate_attempts:
        try:
            payload = decrypt_callable()
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"{label}: {exc}")
            continue
        attempted.append(label)
        payload_obj, source_text, meta = _interpret_rehydrated_payload(payload)
        last_payload = payload
        last_meta = meta
        method_used = label
        candidate_normalised: Optional[Dict[str, Any]] = None
        if payload_obj is not None:
            candidate_normalised = _normalise_rehydrated_payload(payload_obj)
            digest_value = _compute_rehydration_digest(payload_obj, candidate_normalised)
            if digest_value:
                meta["rehydration_digest"] = digest_value
                last_digest = digest_value
        if payload_obj is None and source_text is None:
            continue
        normalised = candidate_normalised
        lua_source = source_text
        break

    if not attempted:
        attempted.append("raw")

    confidence = _confidence_from_method(method_used, preferred_labels, normalised, lua_source)
    metadata = {
        "attempted_methods": attempted,
        "errors": errors,
    }
    metadata.update(last_meta)

    if normalised is None and lua_source is None and last_digest:
        errors.append(f"{method_used}: failed to lift proto (digest={last_digest})")

    result = EncFuncResult(
        proto=normalised,
        lua_source=lua_source,
        raw_bytes=None if normalised or lua_source else last_payload,
        recovery_method=method_used,
        confidence=confidence,
        metadata=metadata,
    )
    return result


def _method_from_label(label: str, blob_bytes: bytes, key: bytes) -> Optional[Callable[[], bytes]]:
    lowered = label.lower()
    if lowered in {"none", "plain", "identity", "raw"}:
        return lambda data=blob_bytes: bytes(data)
    if lowered in {"xor", "simple_xor", "keyxor"}:
        return lambda data=blob_bytes: _xor_bytes(data, key)
    if lowered in {"rolling_xor", "rolling-xor", "rolling", "rxor"}:
        return lambda data=blob_bytes: _rolling_xor_bytes(data, key)
    if lowered in {"rc4", "rc-4", "arc4"}:
        return lambda data=blob_bytes: _rc4_crypt(data, key)
    return None


def _confidence_from_method(
    method: str,
    preferred: Sequence[str],
    proto: Optional[Dict[str, Any]],
    lua_source: Optional[str],
) -> str:
    lowered = method.lower()
    if proto is not None or lua_source is not None:
        if lowered in preferred:
            return "high"
        if lowered in {"rolling_xor", "xor", "rc4"}:
            return "medium"
        if lowered == "raw":
            return "medium"
    return "low"


__all__ = [
    "EncFuncResult",
    "coerce_bytes",
    "coerce_key_bytes",
    "extract_encfunc_blob",
    "rehydrate_encfunc",
]

