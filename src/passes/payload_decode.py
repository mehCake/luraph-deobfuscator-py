"""Payload decoding helpers for version-specific handling."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, TYPE_CHECKING

from .. import utils
from ..deobfuscator import VMIR
from ..versions import PayloadInfo, VersionHandler, get_handler
from ..versions.luraph_v14_4_1 import looks_like_vm_bytecode
from ..versions.luraph_v14_4_initv4 import (
    DEFAULT_ALPHABET as INITV4_DEFAULT_ALPHABET,
    decode_blob as initv4_decode_blob,
)
from ..utils.luraph_vm import canonicalise_opcode_name
from ..utils_pkg.strings import lua_placeholder_function, normalise_lua_newlines
from lph_handler import extract_vm_ir
from opcode_lifter import OpcodeLifter

from string_decryptor import StringDecryptor
import string_decryptor as string_decryptor_mod

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..pipeline import Context


ConstPool = List[Any]


_LOADSTRING_CALL_RE = re.compile(
    r"(?P<prefix>\breturn\s+)?(?:loadstring|load)\s*\(\s*(?P<payload>.+?)\s*\)\s*\(\s*\)",
    re.DOTALL,
)

_SCRIPT_KEY_LITERAL_RE = re.compile(
    r"script_key\s*=\s*script_key\s*or\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_TOP_LEVEL_LITERAL_RE = re.compile(
    r"^\s*(?:return\s+)?(?P<quote>['\"])(?P<body>.*)(?P=quote)\s*;?\s*$",
    re.DOTALL,
)
_STUB_HINT_RE = re.compile(r"init_fn\s*\(")
_INITV4_PAYLOAD_RE = re.compile(
    r"local\s+payload\s*=\s*(?P<quote>['\"])(?P<blob>[A-Za-z0-9!#$%&()*+,\-./:;<=>?@\[\]^_`{|}~]{32,})(?P=quote)",
    re.IGNORECASE,
)


def _detect_jump_table(constants: Iterable[Any]) -> Optional[Dict[str, Any]]:
    """Identify jump-table like structures in *constants*."""

    best_index: Optional[int] = None
    best_entries: List[int] = []
    best_kind = ""

    for index, value in enumerate(constants):
        entries: List[int] | None = None
        kind = ""

        if isinstance(value, (list, tuple)) and len(value) >= 3:
            ints = [int(item) for item in value if isinstance(item, (int, float))]
            if len(ints) >= 3:
                entries = ints
                kind = "sequence"
        elif isinstance(value, dict) and value:
            numeric_items = [
                (int(key), int(val))
                for key, val in value.items()
                if isinstance(key, (int, float)) and isinstance(val, (int, float))
            ]
            if len(numeric_items) >= 3:
                numeric_items.sort(key=lambda item: item[0])
                entries = [val for _, val in numeric_items]
                kind = "mapping"

        if entries and len(entries) > len(best_entries):
            best_index = index
            best_entries = entries
            best_kind = kind or "sequence"

    if best_index is None or not best_entries:
        return None

    preview = best_entries[:64]
    result: Dict[str, Any] = {
        "index": best_index,
        "size": len(best_entries),
        "entries": preview,
        "type": best_kind,
    }
    if len(best_entries) > len(preview):
        result["truncated"] = True
    return result


def _payload_iteration_limit(ctx: "Context") -> int:
    """Return the maximum number of iterative payload decodes to attempt."""

    default_limit = 5
    options = getattr(ctx, "options", None)
    if isinstance(options, dict):
        raw_limit = options.get("payload_decode_max_iterations")
        if not isinstance(raw_limit, int):
            raw_limit = options.get("max_iterations")
        if isinstance(raw_limit, int) and raw_limit > 0:
            return max(1, raw_limit)
    return default_limit


def _unescape_literal(body: str) -> str:
    try:
        return bytes(body, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return body


def _extract_literal(text: str) -> Tuple[Optional[str], bool]:
    match = _TOP_LEVEL_LITERAL_RE.match(text.strip())
    if not match:
        return None, False
    literal = _unescape_literal(match.group("body"))
    return literal, True


def _decode_literal_value(
    value: str,
    *,
    script_key: Optional[str] = None,
) -> Tuple[str, Optional[str]]:
    stripped = value.strip()
    compact = "".join(ch for ch in stripped if not ch.isspace())

    if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
        try:
            decoded = bytes.fromhex(compact)
        except ValueError:
            decoded = b""
        if decoded:
            text = decoded.decode("utf-8", errors="replace")
            if utils._is_printable(text):
                return text, "hex"

    if len(compact) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        padded = compact + "=" * (-len(compact) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False)
        except (ValueError, binascii.Error):
            decoded = b""
        except Exception:
            decoded = b""
        if decoded:
            text = decoded.decode("utf-8", errors="replace")
            if utils._is_printable(text):
                return text, "base64"

    if (
        script_key
        and len(compact) >= 12
        and all(32 <= ord(ch) <= 126 for ch in compact)
        and not compact.startswith("{")
    ):
        try:
            from ..versions.luraph_v14_4_1 import (
                decode_blob_with_metadata as _decode_blob_with_metadata,
            )
        except Exception:  # pragma: no cover - optional import
            pass
        else:
            try:
                data, _ = _decode_blob_with_metadata(compact, script_key)
            except Exception:
                data = b""
            if data:
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = ""
                if text and utils._is_printable(text):
                    return text, "base91"

    return value, None


def _strip_json_quotes_and_escapes(blob: str) -> str:
    """Return ``blob`` without wrapping quotes and with escapes resolved."""

    stripped = blob.strip()
    if not stripped:
        return stripped
    if stripped.startswith("\"") and stripped.endswith("\""):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            stripped = stripped[1:-1]
    return stripped


def _persist_bootstrap_blob(
    ctx: "Context", decoded: bytes, *, chunk_index: int
) -> Optional[Dict[str, str]]:
    """Write ``decoded`` bytes to disk and return artefact paths."""

    if not decoded:
        return None

    bootstrap_path = getattr(ctx, "bootstrapper_path", None)
    candidate: Optional[str]
    if bootstrap_path:
        candidate = str(bootstrap_path)
    else:
        input_path = getattr(ctx, "input_path", None)
        candidate = str(input_path) if input_path else None

    base_name = "bootstrap"
    if candidate:
        base_path = Path(candidate)
        if base_path.is_dir():
            for name in ("initv4.lua", "init.lua", "bootstrap.lua", "init.lua.txt"):
                guess = base_path / name
                if guess.exists():
                    base_path = guess
                    break
        stem = base_path.stem or base_path.name
        if stem:
            base_name = stem

    sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", base_name)[:60] or "bootstrap"
    logs_dir = Path("out") / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None

    suffix = "" if chunk_index == 0 else f"_{chunk_index:02d}"
    decoded_path = logs_dir / f"bootstrap_decoded_{sanitized}{suffix}.bin"
    try:
        decoded_path.write_bytes(decoded)
    except OSError:
        return None

    out_dir = Path("out")
    try:
        utils.ensure_directory(out_dir)
    except Exception:
        base64_path = None
    else:
        base_suffix = "" if chunk_index == 0 else f".part{chunk_index + 1:02d}"
        candidate_path = out_dir / f"bootstrap_blob{base_suffix}.b64.txt"
        encoded = base64.b64encode(decoded).decode("ascii") if decoded else ""
        if utils.safe_write_file(str(candidate_path), encoded):
            base64_path = candidate_path
        else:
            base64_path = None

    result: Dict[str, str] = {"binary": str(decoded_path)}
    if base64_path is not None:
        result["base64"] = str(base64_path)
    return result


def _json_compatible(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_compatible(item) for item in value]
    return str(value)


def _persist_decoded_outputs(
    ctx: "Context",
    decoded_text: Optional[str],
    payload_mapping: Optional[Mapping[str, Any]],
    *,
    chunk_index: int,
) -> Optional[Dict[str, str]]:
    raw_text = decoded_text or ""
    byte_length = len(raw_text.encode("utf-8", errors="ignore"))
    sanitized = utils.strip_non_printable(raw_text)
    if sanitized:
        sanitized = normalise_lua_newlines(sanitized)
    if not sanitized.strip():
        sanitized = lua_placeholder_function(
            f"chunk_{chunk_index + 1}",
            [
                f"undecoded content (size: {byte_length} bytes)",
                "no decoded Lua emitted by initv4 fallback",
                f"chunk index: {chunk_index}",
            ],
        )
    elif "function" not in sanitized:
        placeholder = lua_placeholder_function(
            f"chunk_{chunk_index + 1}",
            [f"undecoded content (size: {byte_length} bytes)"],
        )
        sanitized_body = sanitized.rstrip("\r\n")
        joiner = "\r\n\r\n" if sanitized_body else ""
        sanitized = f"{sanitized_body}{joiner}{placeholder}"
    sanitized = normalise_lua_newlines(sanitized)

    out_dir = Path("out")
    try:
        utils.ensure_directory(out_dir)
    except Exception:
        return None

    suffix = "" if chunk_index == 0 else f".part{chunk_index + 1:02d}"
    lua_path = out_dir / f"decoded_output{suffix}.lua"
    json_path = out_dir / f"unpacked_dump{suffix}.json"

    lua_written = utils.safe_write_file(str(lua_path), sanitized, encoding="utf-8")

    payload_obj: Mapping[str, Any]
    if isinstance(payload_mapping, Mapping) and payload_mapping:
        payload_obj = {k: _json_compatible(v) for k, v in payload_mapping.items()}
    else:
        payload_obj = {"script": sanitized}
    try:
        json_text = json.dumps(payload_obj, ensure_ascii=False, indent=2)
    except TypeError:
        payload_obj = {key: _json_compatible(value) for key, value in payload_obj.items()}
        json_text = json.dumps(payload_obj, ensure_ascii=False, indent=2)
    json_written = utils.safe_write_file(str(json_path), json_text, encoding="utf-8")

    if lua_written:
        try:
            if lua_path.stat().st_size <= 0:
                lua_written = False
        except OSError:
            lua_written = False
    if json_written:
        try:
            if json_path.stat().st_size <= 0:
                json_written = False
        except OSError:
            json_written = False

    if chunk_index == 0:
        summary_path = out_dir / "unpacked.json"
        if not summary_path.exists():
            utils.safe_write_file(str(summary_path), json_text, encoding="utf-8")

    if not lua_written or not json_written:
        if lua_written:
            try:
                lua_path.unlink()
            except OSError:
                pass
        if json_written:
            try:
                json_path.unlink()
            except OSError:
                pass
        return None

    ctx.result.setdefault("artifacts", {})
    artifacts = ctx.result["artifacts"]
    if isinstance(artifacts, dict):
        decoded_bucket = artifacts.setdefault("decoded_output", [])
        if isinstance(decoded_bucket, list):
            decoded_bucket.append(str(lua_path))
        else:
            artifacts["decoded_output"] = [str(lua_path)]
        unpacked_bucket = artifacts.setdefault("unpacked_dump", [])
        if isinstance(unpacked_bucket, list):
            unpacked_bucket.append(str(json_path))
        else:
            artifacts["unpacked_dump"] = [str(json_path)]

    return {"lua": str(lua_path), "json": str(json_path)}


def _ensure_bootstrap_blob_placeholder(source: Optional[str | Path]) -> Optional[str]:
    if not source:
        return None
    try:
        source_path = Path(source)
    except TypeError:
        return None
    if not source_path.exists() or not source_path.is_file():
        return None

    out_dir = Path("out")
    try:
        utils.ensure_directory(out_dir)
    except Exception:
        return None

    target = out_dir / "bootstrap_blob.b64.txt"
    if target.exists():
        return str(target)

    try:
        raw = source_path.read_bytes()
    except OSError:
        return None

    encoded = base64.b64encode(raw).decode("ascii") if raw else ""
    if not utils.safe_write_file(str(target), encoded):
        return None
    return str(target)


def _ensure_summary_artifacts(
    metadata: Mapping[str, Any],
) -> Dict[str, str]:
    artifacts: Dict[str, str] = {}
    out_dir = Path("out")
    try:
        utils.ensure_directory(out_dir)
    except Exception:
        return artifacts

    payload_meta = metadata.get("handler_payload_meta")
    if isinstance(payload_meta, Mapping):
        payload_data = _json_compatible(payload_meta)
    else:
        payload_data = {}

    bootstrap_meta = metadata.get("bootstrapper_metadata")
    if isinstance(bootstrap_meta, Mapping):
        bootstrap_data = _json_compatible(bootstrap_meta)
    else:
        bootstrap_data = {}

    summary = {
        "handler_payload_meta": payload_data,
        "bootstrapper_metadata": bootstrap_data,
    }

    target = out_dir / "unpacked.json"
    if not target.exists():
        try:
            json_text = json.dumps(summary, ensure_ascii=False, indent=2)
        except TypeError:
            json_text = json.dumps(_json_compatible(summary), ensure_ascii=False, indent=2)
        if utils.safe_write_file(str(target), json_text, encoding="utf-8"):
            artifacts["unpacked_json"] = str(target)

    return artifacts


def _persist_decoder_metadata(
    decoder: Any,
    *,
    chunk_index: int,
) -> Dict[str, str]:
    artifacts: Dict[str, str] = {}
    out_dir = Path("out")
    try:
        utils.ensure_directory(out_dir)
    except Exception:
        return artifacts

    suffix = "" if chunk_index == 0 else f".part{chunk_index + 1:02d}"

    alphabet = getattr(decoder, "alphabet", None)
    if isinstance(alphabet, str) and alphabet:
        target = out_dir / f"alphabet{suffix}.txt"
        if not target.exists() and utils.safe_write_file(str(target), alphabet, encoding="utf-8"):
            artifacts["alphabet"] = str(target)

    opcode_map: Optional[Mapping[Any, Any]] = None
    if hasattr(decoder, "opcode_table"):
        try:
            table_candidate = decoder.opcode_table()
        except Exception:
            table_candidate = None
        if isinstance(table_candidate, Mapping) and table_candidate:
            opcode_map = table_candidate
    if opcode_map is None:
        candidate = getattr(decoder, "opcode_map", None)
        if isinstance(candidate, Mapping) and candidate:
            opcode_map = candidate

    if isinstance(opcode_map, Mapping) and opcode_map:
        lines: List[str] = []
        try:
            iterator = sorted(opcode_map.items())
        except Exception:
            iterator = opcode_map.items()
        for key, value in iterator:
            try:
                opcode_int = int(key)
            except Exception:
                continue
            mnemonic = str(value)
            lines.append(f"0x{opcode_int:02X} {mnemonic}")
        if lines:
            target = out_dir / f"opcode_map{suffix}.txt"
            text = "\n".join(lines)
            if not target.exists() and utils.safe_write_file(str(target), text, encoding="utf-8"):
                artifacts["opcode_map"] = str(target)

    return artifacts


def _canonical_opcode_map(mapping: Mapping[Any, Any]) -> Dict[int, str]:
    result: Dict[int, str] = {}
    for key, name in mapping.items():
        opcode: Optional[int] = None
        if isinstance(key, int):
            opcode = key
        elif isinstance(key, str):
            try:
                opcode = int(key, 0)
            except (TypeError, ValueError):
                opcode = None
        if opcode is None:
            continue
        canonical = canonicalise_opcode_name(name)
        if not canonical:
            continue
        opcode &= 0x3F
        result.setdefault(opcode, canonical)
    return result


def _persist_chunk_outputs(ctx: "Context", text: str) -> List[str]:
    prefix = getattr(ctx, "output_prefix", None)
    if not prefix:
        return []

    raw_text = text or ""
    sanitized = utils.strip_non_printable(raw_text)
    if sanitized:
        sanitized = normalise_lua_newlines(sanitized)
    byte_length = len(raw_text.encode("utf-8", errors="ignore"))
    if not sanitized.strip():
        sanitized = lua_placeholder_function(
            prefix,
            [
                f"undecoded content (size: {byte_length} bytes)",
                "empty pipeline output",
            ],
        )
    elif "function" not in sanitized:
        placeholder = lua_placeholder_function(
            prefix,
            [f"undecoded content (size: {byte_length} bytes)"],
        )
        sanitized_body = sanitized.rstrip("\r\n")
        joiner = "\r\n\r\n" if sanitized_body else ""
        sanitized = f"{sanitized_body}{joiner}{placeholder}"
    sanitized = normalise_lua_newlines(sanitized)

    chunk_lines_value: Optional[int] = None
    options = getattr(ctx, "options", None)
    if isinstance(options, dict):
        raw_chunk_lines = options.get("chunk_lines")
        if isinstance(raw_chunk_lines, int) and raw_chunk_lines > 0:
            chunk_lines_value = raw_chunk_lines

    out_dir = Path("out")
    try:
        utils.ensure_directory(out_dir)
    except Exception:
        return []

    if chunk_lines_value:
        lines = sanitized.splitlines()
        chunks: List[str] = []
        for index in range(0, len(lines), chunk_lines_value):
            chunk = "\n".join(lines[index : index + chunk_lines_value])
            chunk = normalise_lua_newlines(chunk)
            chunks.append(chunk)
        if not chunks:
            chunks = [sanitized]
    else:
        chunks = [sanitized]

    paths: List[str] = []
    for index, chunk_text in enumerate(chunks):
        suffix = "" if len(chunks) == 1 or index == 0 else f".part{index + 1:02d}"
        target = out_dir / f"{prefix}{suffix}.lua"
        if utils.safe_write_file(str(target), chunk_text, encoding="utf-8"):
            paths.append(str(target))
    return paths


def _attempt_simple_fallback_bytes(candidate: str) -> bytes:
    """Decode ``candidate`` using lightweight heuristics.

    The helper mirrors the best-effort logic in the reference pseudocode: first
    try hexadecimal, then base64.  When both strategies fail an empty byte
    string is returned so callers can distinguish fallback failures from valid
    payloads.
    """

    text = candidate.strip()
    if not text:
        return b""

    if len(text) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", text):
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass

    if len(text) >= 12 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", text):
        padded = text + "=" * (-len(text) % 4)
        try:
            return base64.b64decode(padded, validate=False)
        except (binascii.Error, ValueError):
            pass

    return b""


def _decode_simple_bootstrap(text: str, script_key: Optional[str]) -> Optional[str]:
    match = _INITV4_PAYLOAD_RE.search(text)
    if not match:
        return None
    key = script_key
    if not key:
        key_match = re.search(
            r"script_key\s*=\s*script_key\s*or\s*['\"]([^'\"]+)['\"]",
            text,
        )
        if key_match:
            key = key_match.group(1).strip()
    if not key:
        return None
    try:
        decoded = initv4_decode_blob(match.group("blob"), key_bytes=key.encode("utf-8"))
    except Exception:
        return None
    try:
        decoded_text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    cleaned = utils.strip_non_printable(decoded_text)
    if not cleaned:
        return None
    try:
        payload = json.loads(cleaned)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("script"), str):
        return utils.strip_non_printable(payload["script"])
    return cleaned


def _mask_script_key(script_key: Optional[str]) -> Optional[str]:
    if not script_key:
        return None
    cleaned = script_key.strip()
    if not cleaned:
        return None
    prefix = cleaned[:6]
    masked_len = max(len(cleaned) - len(prefix), 0)
    return prefix + ("*" * masked_len)


def _bootstrap_decoder_needs_emulation(
    metadata: Optional[Mapping[str, Any]]
) -> Tuple[bool, List[str]]:
    if not isinstance(metadata, Mapping):
        return False, []

    needs_emulation = bool(metadata.get("needs_emulation"))
    paths: List[str] = []
    seen: Set[str] = set()

    def _collect(container: Mapping[str, Any]) -> None:
        blobs = container.get("blobs")
        if not isinstance(blobs, list):
            return
        for entry in blobs:
            if not isinstance(entry, Mapping):
                continue
            path = (
                entry.get("decoded_path")
                or entry.get("bin_path")
                or entry.get("artifact")
                or entry.get("path")
            )
            if isinstance(path, str) and path and path not in seen:
                seen.add(path)
                paths.append(path)

    _collect(metadata)

    decoder_info = metadata.get("decoder")
    if isinstance(decoder_info, Mapping):
        needs_emulation = needs_emulation or bool(decoder_info.get("needs_emulation"))
        _collect(decoder_info)

    return needs_emulation, paths


def _iterative_initv4_decode(
    ctx: "Context",
    source: str,
    *,
    script_key: Optional[str],
    max_iterations: int,
    force: bool,
) -> Tuple[List[Dict[str, Any]], str, Dict[str, Any]]:
    """Decode every initv4 payload chunk discovered in ``source``.

    The implementation mirrors the user-provided pseudocode: it enumerates every
    payload blob, decodes it with the supplied script key, records per-chunk
    metadata, and replaces the literal with a placeholder so subsequent
    iterations do not reprocess the same content.  The helper returns a list of
    chunk dictionaries, the transformed source text, and aggregate metadata that
    can feed the reporting layer.
    """

    if not script_key:
        return [], source, {}

    try:
        from ..versions.luraph_v14_4_initv4 import InitV4Decoder
    except Exception:  # pragma: no cover - optional helper may fail to load
        return [], source, {}

    existing_meta = getattr(ctx, "bootstrapper_metadata", None)
    base_meta: Dict[str, Any] = dict(existing_meta) if isinstance(existing_meta, dict) else {}

    ctx_proxy = SimpleNamespace(
        script_key=script_key,
        bootstrapper_path=getattr(ctx, "bootstrapper_path", None),
        debug_bootstrap=bool(getattr(ctx, "debug_bootstrap", False)),
        bootstrap_debug_log=getattr(ctx, "deobfuscator", None)
        and getattr(ctx.deobfuscator, "_bootstrap_debug_log", None),
        bootstrapper_metadata=base_meta,
        manual_alphabet=getattr(ctx, "manual_alphabet", None),
        manual_opcode_map=getattr(ctx, "manual_opcode_map", None),
        allow_lua_run=getattr(ctx, "allow_lua_run", False),
    )

    context_manual_alphabet = bool(getattr(ctx, "manual_alphabet", None))
    context_manual_opcode_map = bool(getattr(ctx, "manual_opcode_map", None))

    try:
        decoder = InitV4Decoder(ctx_proxy)
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("initv4 decoder bootstrap failed: %s", exc)
        return [], source, {"warnings": [str(exc)]}

    proxy_meta = getattr(ctx_proxy, "bootstrapper_metadata", None)
    if isinstance(proxy_meta, dict) and proxy_meta:
        try:
            ctx.bootstrapper_metadata = dict(proxy_meta)
        except Exception:  # pragma: no cover - defensive
            pass

    decoder_opcode_map = getattr(decoder, "opcode_map", None)
    if isinstance(decoder_opcode_map, Mapping) and decoder_opcode_map:
        existing_vm_map = ctx.vm_metadata.get("opcode_map")
        combined_vm_map: Dict[int, str] = {}
        if isinstance(existing_vm_map, Mapping):
            combined_vm_map.update(_canonical_opcode_map(existing_vm_map))
        combined_vm_map.update(_canonical_opcode_map(decoder_opcode_map))
        if combined_vm_map:
            ctx.vm_metadata["opcode_map"] = combined_vm_map

    masked_key = _mask_script_key(script_key)
    aggregate_meta: Dict[str, Any] = {
        "chunk_count": 0,
        "chunk_decoded_bytes": [],
        "chunk_encoded_lengths": [],
        "chunk_details": [],
        "chunk_success_count": 0,
    }
    warnings: List[str] = []
    decoded_chunks: List[Dict[str, Any]] = []
    current_text = source
    key_bytes = script_key.encode("utf-8")

    opcode_lifter: Optional[OpcodeLifter] = None

    iteration_count = 0
    iteration_versions: List[str] = []
    iteration_changes: List[bool] = []
    detected_version = getattr(getattr(ctx, "detected_version", None), "name", None)
    if not isinstance(detected_version, str) or not detected_version:
        detected_version = "luraph_v14_4_initv4"

    initial_artifacts = _persist_decoder_metadata(decoder, chunk_index=0)
    if initial_artifacts.get("alphabet"):
        aggregate_meta.setdefault("alphabet_paths", []).append(
            initial_artifacts["alphabet"]
        )
    if initial_artifacts.get("opcode_map"):
        aggregate_meta.setdefault("opcode_map_paths", []).append(
            initial_artifacts["opcode_map"]
        )

    for _iteration in range(max(1, max_iterations)):
        try:
            payloads = decoder.locate_payload(current_text)
        except Exception as exc:  # pragma: no cover - defensive
            LOG.debug("initv4 payload scan failed: %s", exc)
            warnings.append(str(exc))
            break

        if not payloads:
            break

        progress = False
        processed_chunks = 0
        for blob in payloads:
            if not isinstance(blob, str):
                continue

            stripped = _strip_json_quotes_and_escapes(blob)
            encoded_length = len(stripped)
            decoded_bytes = b""
            manual_alphabet_override = bool(
                getattr(decoder, "_manual_override_alphabet", False)
            )
            manual_opcode_override = bool(
                getattr(decoder, "_manual_override_opcode_map", False)
            )
            if context_manual_alphabet and not manual_alphabet_override:
                manual_alphabet_override = True
            if context_manual_opcode_map and not manual_opcode_override:
                manual_opcode_override = True

            try:
                alphabet = getattr(decoder, "alphabet", None) or INITV4_DEFAULT_ALPHABET
                decoded_bytes = initv4_decode_blob(
                    stripped,
                    alphabet=alphabet,
                    key_bytes=key_bytes,
                )
            except Exception as exc:
                if not force:
                    warnings.append(str(exc))
                    continue
                warnings.append(f"{exc} (ignored due to --force)")

            if not decoded_bytes:
                fallback = _attempt_simple_fallback_bytes(stripped)
                if fallback:
                    decoded_bytes = fallback
                elif not force:
                    warnings.append(
                        "Failed to decode initv4 chunk; rerun with --force for best-effort."
                    )
                    continue

            opcode_map: Mapping[int, str] = getattr(decoder, "opcode_map", {})
            suspicious = not looks_like_vm_bytecode(
                decoded_bytes,
                opcode_map=opcode_map,
            )
            blob_paths: List[str] = []
            chunk_record: Dict[str, Any]
            if suspicious:
                needs_emulation, blob_paths = _bootstrap_decoder_needs_emulation(
                    getattr(ctx, "bootstrapper_metadata", None)
                )
                warning = "Decoded initv4 chunk does not resemble VM bytecode."
                if needs_emulation and blob_paths:
                    aggregate_meta.setdefault("bootstrapper_decoded_blobs", [])
                    for path in blob_paths:
                        if isinstance(path, str) and path:
                            aggregate_meta["bootstrapper_decoded_blobs"].append(path)
                    warning += (
                        " Bootstrapper decoder requires emulation; inspect: "
                        + ", ".join(blob_paths)
                        + ". Use --force to proceed with fallback decoding."
                    )
                chunk_record = {
                    "vm_lift_skipped": True,
                }
                if not force:
                    warnings.append(warning)
                    continue
                warnings.append(f"{warning} (ignored due to --force)")
                chunk_record["vm_lift_forced"] = True
            else:
                chunk_record = {}

            chunk_index = len(decoded_chunks)
            decoder_artifacts = _persist_decoder_metadata(
                decoder,
                chunk_index=chunk_index,
            )
            if decoder_artifacts.get("alphabet"):
                aggregate_meta.setdefault("alphabet_paths", []).append(
                    decoder_artifacts["alphabet"]
                )
                chunk_record["alphabet_path"] = decoder_artifacts["alphabet"]
            if decoder_artifacts.get("opcode_map"):
                aggregate_meta.setdefault("opcode_map_paths", []).append(
                    decoder_artifacts["opcode_map"]
                )
                chunk_record["opcode_map_path"] = decoder_artifacts["opcode_map"]

            artifact_info = _persist_bootstrap_blob(
                ctx,
                decoded_bytes,
                chunk_index=chunk_index,
            )
            if artifact_info:
                decoded_blob_path = artifact_info.get("binary")
                if decoded_blob_path:
                    aggregate_meta.setdefault(
                        "bootstrapper_decoded_blobs", []
                    ).append(decoded_blob_path)
                    blob_paths = list(blob_paths)
                    blob_paths.append(decoded_blob_path)
                    chunk_record["bootstrap_blob_binary"] = decoded_blob_path
                base64_path = artifact_info.get("base64")
                if base64_path:
                    aggregate_meta.setdefault(
                        "bootstrapper_decoded_blobs_b64", []
                    ).append(base64_path)
                    chunk_record["bootstrap_blob_b64"] = base64_path

            aggregate_meta["chunk_count"] += 1
            aggregate_meta["chunk_decoded_bytes"].append(len(decoded_bytes))
            aggregate_meta["chunk_encoded_lengths"].append(encoded_length)
            chunk_success = bool(decoded_bytes)

            chunk_record.update(
                {
                    "index": chunk_index,
                    "encoded_size": encoded_length,
                    "decoded_byte_count": len(decoded_bytes),
                    "used_key_masked": masked_key,
                }
            )
            alphabet_source = "bootstrap" if decoder.alphabet else "heuristic"
            if manual_alphabet_override and decoder.alphabet:
                alphabet_source = "manual_override"
            chunk_record["alphabet_source"] = alphabet_source
            aggregate_meta.setdefault("chunk_alphabet_sources", []).append(alphabet_source)
            chunk_record["suspicious"] = suspicious
            aggregate_meta.setdefault("chunk_suspicious_flags", []).append(suspicious)
            if blob_paths:
                chunk_record["bootstrapper_decoded_blobs"] = list(blob_paths)

            decoded_text: Optional[str]
            try:
                decoded_text = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                decoded_text = None

            payload_mapping: Optional[Dict[str, Any]] = None

            if not suspicious:
                chunk_record["vm_lift_skipped"] = False
                vm_summary: Dict[str, Any] = {}

                if decoded_text:
                    payload_mapping = extract_vm_ir(decoded_text)

                if payload_mapping and isinstance(opcode_map, Mapping) and opcode_map:
                    constants = payload_mapping.get("constants")
                    bytecode_listing = payload_mapping.get("bytecode") or payload_mapping.get("code")
                    prototypes = payload_mapping.get("prototypes")
                    if isinstance(constants, list):
                        vm_summary["constants"] = len(constants)
                    if isinstance(bytecode_listing, list):
                        vm_summary["bytecode"] = len(bytecode_listing)
                    if isinstance(prototypes, list):
                        vm_summary["prototypes"] = len(prototypes)

                    try:
                        if opcode_lifter is None:
                            opcode_lifter = OpcodeLifter()
                        module = opcode_lifter.lift_program(
                            payload_mapping,
                            version="luraph_v14_4_initv4",
                            opcode_map=dict(opcode_map),
                        )
                    except Exception as exc:
                        warning = f"Opcode lifting failed: {exc}"
                        warnings.append(warning)
                        chunk_record["vm_lift_error"] = str(exc)
                    else:
                        vm_summary["instructions"] = len(getattr(module, "instructions", []))
                        table_meta = getattr(module, "metadata", {}).get("opcode_table")
                        if isinstance(table_meta, Mapping):
                            opcode_source = table_meta.get("source")
                            if opcode_source:
                                vm_summary["opcode_table_source"] = opcode_source
                        if manual_opcode_override and opcode_map:
                            vm_summary.setdefault("opcode_table_source", "manual_override")
                        aggregate_meta.setdefault("vm_lift_summaries", []).append(dict(vm_summary))
                else:
                    chunk_record["vm_lift_skipped"] = True

                if vm_summary:
                    chunk_record["vm_lift_summary"] = vm_summary
            elif "vm_lift_skipped" not in chunk_record:
                chunk_record["vm_lift_skipped"] = True

            persisted = _persist_decoded_outputs(
                ctx,
                decoded_text,
                payload_mapping,
                chunk_index=chunk_index,
            )
            if persisted:
                chunk_record["decoded_output_path"] = persisted["lua"]
                chunk_record["unpacked_dump_path"] = persisted["json"]
                aggregate_meta.setdefault("decoded_output_paths", []).append(
                    persisted["lua"]
                )
                aggregate_meta.setdefault("unpacked_dump_paths", []).append(
                    persisted["json"]
                )
                if not chunk_success:
                    chunk_success = True

            chunk_record["chunk_success"] = chunk_success

            decoded_chunks.append(chunk_record)
            aggregate_meta["chunk_details"].append(dict(chunk_record))

            if chunk_success:
                aggregate_meta["chunk_success_count"] += 1

            placeholder = f"<decoded_chunk_{chunk_index + 1}>"
            replacement = (
                f'"{placeholder}"' if blob.strip().startswith('"') else placeholder
            )
            current_text = current_text.replace(blob, replacement, 1)
            progress = True
            processed_chunks += 1

        if progress:
            increment = processed_chunks or 1
            iteration_count += increment
            iteration_versions.extend([detected_version] * increment)
            iteration_changes.extend([True] * increment)
        else:
            break

    if warnings:
        aggregate_meta["warnings"] = warnings

    if iteration_count:
        aggregate_meta["payload_iterations"] = iteration_count
        aggregate_meta["payload_iteration_versions"] = list(iteration_versions)
        if iteration_changes:
            aggregate_meta["payload_iteration_changes"] = list(iteration_changes)
        else:
            aggregate_meta["payload_iteration_changes"] = [True] * iteration_count

    return decoded_chunks, current_text, aggregate_meta


def _evaluate_payload_expression(
    expr: str,
    *,
    script_key: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    literal, matched = _extract_literal(expr)
    if matched and literal is not None:
        decoded, method = _decode_literal_value(literal, script_key=script_key)
        return decoded, method

    try:
        evaluated = string_decryptor_mod._evaluate_expression(expr)
    except Exception:  # pragma: no cover - defensive
        evaluated = None
    if isinstance(evaluated, str):
        decoded, method = _decode_literal_value(evaluated, script_key=script_key)
        return decoded, method
    return None, None


def _expand_loadstring_calls(
    text: str,
    *,
    script_key: Optional[str] = None,
) -> Tuple[str, Dict[str, Any]]:
    decryptor = StringDecryptor()
    replacements = 0
    failures = 0
    methods: Set[str] = set()
    return_wrapped = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal replacements, failures, return_wrapped
        snippet = match.group(0)
        payload_expr = match.group("payload")
        prefix = match.group("prefix")

        decrypted = decryptor.decrypt(snippet)
        literal, matched_literal = _extract_literal(decrypted)
        candidate: Optional[str] = None
        method: Optional[str] = None

        if matched_literal and literal is not None:
            decoded_literal, method = _decode_literal_value(literal, script_key=script_key)
            candidate = decoded_literal

        if candidate is None:
            evaluated, eval_method = _evaluate_payload_expression(
                payload_expr,
                script_key=script_key,
            )
            if evaluated is not None:
                candidate = evaluated
                method = eval_method

        if candidate is None:
            failures += 1
            return snippet

        replacements += 1
        if method:
            methods.add(method)
        if prefix:
            return_wrapped += 1
        return utils.strip_non_printable(candidate)

    updated = _LOADSTRING_CALL_RE.sub(repl, text)
    metadata: Dict[str, Any] = {}
    if replacements:
        metadata["decoded"] = replacements
    if methods:
        metadata["methods"] = sorted(methods)
    if failures:
        metadata["failed"] = failures
    if return_wrapped:
        metadata["return_wrapped"] = return_wrapped
    return updated, metadata


def _unwrap_literal_block(
    text: str,
    *,
    script_key: Optional[str] = None,
) -> Tuple[str, Dict[str, Any], bool]:
    literal, matched = _extract_literal(text)
    if not matched or literal is None:
        return text, {}, False

    decoded, method = _decode_literal_value(literal, script_key=script_key)
    metadata: Dict[str, Any] = {"unwrapped": True}
    if method:
        metadata["method"] = method
    cleaned = utils.strip_non_printable(decoded)
    return cleaned, metadata, cleaned != text


def _force_init_stub_decode(
    ctx: "Context",
    source: str,
    *,
    script_key: Optional[str],
    handler: Optional[VersionHandler],
    version: Any,
) -> Tuple[Optional[str], Dict[str, Any]]:
    if not script_key or handler is None:
        return None, {}
    if not _STUB_HINT_RE.search(source):
        return None, {}

    deob = ctx.deobfuscator
    if deob is None:
        return None, {}

    force_mode = bool(getattr(ctx, "force", False))
    if isinstance(ctx.options, dict):
        force_mode = bool(ctx.options.get("force")) or force_mode

    try:
        decoded_parts, meta, analysis = deob._decode_initv4_chunks(
            source,
            script_key=script_key,
            handler=handler,
            version=version,
            force=force_mode,
        )
    except Exception:  # pragma: no cover - defensive
        return None, {}

    if analysis.get("final_source"):
        return analysis["final_source"], meta

    if decoded_parts:
        combined = b"".join(decoded_parts)
        mapping, _, _ = deob._decode_payload_mapping(combined)
        if isinstance(mapping, dict):
            script_text = mapping.get("script")
            if isinstance(script_text, str) and script_text.strip():
                return utils.strip_non_printable(script_text), meta

    return None, meta


def _merge_chunk_meta(metadata: Dict[str, Any], chunk_meta: Dict[str, Any]) -> None:
    if not isinstance(chunk_meta, dict):
        return

    payload_meta = metadata.setdefault("handler_payload_meta", {})
    if not isinstance(payload_meta, dict):
        payload_meta = {}
        metadata["handler_payload_meta"] = payload_meta

    if "chunk_count" in chunk_meta and "handler_payload_chunks" not in metadata:
        count = chunk_meta.get("chunk_count")
        if isinstance(count, int):
            metadata["handler_payload_chunks"] = count

    for key in ("chunk_decoded_bytes", "chunk_encoded_lengths", "chunk_success_count"):
        value = chunk_meta.get(key)
        if value is not None and key not in payload_meta:
            payload_meta[key] = value

    if "chunk_decoded_bytes" in chunk_meta and "handler_chunk_decoded_bytes" not in metadata:
        decoded = chunk_meta.get("chunk_decoded_bytes")
        if isinstance(decoded, list):
            metadata["handler_chunk_decoded_bytes"] = list(decoded)

    if "chunk_encoded_lengths" in chunk_meta and "handler_chunk_encoded_lengths" not in metadata:
        encoded = chunk_meta.get("chunk_encoded_lengths")
        if isinstance(encoded, list):
            metadata["handler_chunk_encoded_lengths"] = list(encoded)

    if "chunk_success_count" in chunk_meta and "handler_chunk_success_count" not in metadata:
        success = chunk_meta.get("chunk_success_count")
        if isinstance(success, int):
            metadata["handler_chunk_success_count"] = success

    if (
        "chunk_suspicious_flags" in chunk_meta
        and "handler_chunk_suspicious" not in metadata
    ):
        flags = chunk_meta.get("chunk_suspicious_flags")
        if isinstance(flags, list):
            metadata["handler_chunk_suspicious"] = [bool(flag) for flag in flags]

    blobs = chunk_meta.get("bootstrapper_decoded_blobs")
    if isinstance(blobs, list):
        existing = metadata.setdefault("bootstrapper_decoded_blobs", [])
        if isinstance(existing, list):
            for path in blobs:
                if isinstance(path, str) and path:
                    existing.append(path)

    if chunk_meta.get("vm_lift_skipped"):
        metadata["handler_vm_lift_skipped"] = True
    if chunk_meta.get("vm_lift_forced"):
        metadata["handler_vm_lift_forced"] = True


def _apply_inline_fallback(
    ctx: "Context",
    text: str,
    metadata: Dict[str, Any],
    *,
    script_key: Optional[str],
    handler: Optional[VersionHandler],
    version: Any,
) -> Tuple[str, Dict[str, Any], bool]:
    fallback_meta: Dict[str, Any] = {}
    updated = text
    changed = False

    expanded, load_meta = _expand_loadstring_calls(updated, script_key=script_key)
    if load_meta.get("decoded"):
        fallback_meta["loadstrings"] = load_meta
        updated = expanded
        changed = True

    unwrapped, literal_meta, literal_changed = _unwrap_literal_block(
        updated,
        script_key=script_key,
    )
    if literal_changed:
        fallback_meta["literal"] = literal_meta
        updated = unwrapped
        changed = True

    simplified = utils.decode_simple_obfuscations(updated)
    if simplified != updated:
        fallback_meta.setdefault("simple_decoders", True)
        updated = utils.strip_non_printable(simplified)
        changed = True

    forced, chunk_meta = _force_init_stub_decode(
        ctx,
        updated,
        script_key=script_key,
        handler=handler,
        version=version,
    )
    if forced:
        fallback_meta["forced_initv4"] = True
        if chunk_meta:
            fallback_meta["chunk_meta"] = dict(chunk_meta)
            _merge_chunk_meta(metadata, chunk_meta)
        updated = forced
        changed = True

    if changed:
        updated = utils.strip_non_printable(updated)

    return updated, fallback_meta, changed


def _should_apply_inline_fallback(text: str, metadata: Dict[str, Any]) -> bool:
    if not text or not text.strip():
        return False
    if "loadstring" in text or "string.char" in text:
        return True
    if _STUB_HINT_RE.search(text):
        chunk_count = metadata.get("handler_payload_chunks")
        if not isinstance(chunk_count, int) or chunk_count == 0:
            return True
    return False


def _extend_list(
    target: Dict[str, Any],
    key: str,
    values: Optional[Iterable[Any]],
    *,
    allow_false: bool = False,
    predicate: Optional[Any] = None,
    transform: Optional[Any] = None,
) -> None:
    if not values:
        return
    bucket = target.setdefault(key, [])
    for value in values:
        if not allow_false and not value:
            continue
        if predicate is not None and not predicate(value):
            continue
        if transform is not None:
            value = transform(value)
        bucket.append(value)


def _merge_payload_meta(target: Dict[str, Any], meta: Any) -> None:
    if not isinstance(meta, dict):
        return

    for key, value in meta.items():
        if key == "payload_iterations" and isinstance(value, int):
            existing = target.get("payload_iterations")
            if isinstance(existing, int):
                target["payload_iterations"] = max(existing, value)
            else:
                target["payload_iterations"] = value
            continue
        if key == "payload_iteration_versions" and isinstance(value, list):
            existing_versions = target.setdefault("payload_iteration_versions", [])
            for item in value:
                if item:
                    existing_versions.append(str(item))
            continue
        if key == "payload_iteration_changes" and isinstance(value, list):
            existing_changes = target.setdefault("payload_iteration_changes", [])
            for item in value:
                if isinstance(item, bool):
                    existing_changes.append(item)
                elif isinstance(item, int):
                    existing_changes.append(bool(item))
            continue
        if key in {"chunk_count", "chunk_success_count"} and isinstance(value, int):
            target[key] = target.get(key, 0) + max(value, 0)
            continue
        if key in {"chunk_decoded_bytes", "chunk_encoded_lengths", "chunk_lengths"} and isinstance(value, list):
            existing = target.setdefault(key, [])
            for item in value:
                if isinstance(item, int):
                    existing.append(item)
            continue
        if key in {"chunk_meta", "decode_attempts", "decode_errors"} and isinstance(value, list):
            existing = target.setdefault(key, [])
            for item in value:
                if isinstance(item, dict):
                    existing.append(dict(item))
            continue
        if key in {"chunk_methods", "chunk_alphabet_sources"} and isinstance(value, list):
            existing = target.setdefault(key, [])
            existing.extend(value)
            continue
        if key == "chunk_suspicious_flags" and isinstance(value, list):
            existing = target.setdefault(key, [])
            for item in value:
                if isinstance(item, bool):
                    existing.append(item)
                elif isinstance(item, int):
                    existing.append(bool(item))
            continue
        if key == "bootstrapper_decoded_blobs" and isinstance(value, list):
            existing = target.setdefault(key, [])
            for item in value:
                if isinstance(item, str) and item:
                    existing.append(item)
            continue
        if key == "warnings" and isinstance(value, list):
            existing = target.setdefault(key, [])
            for item in value:
                if item:
                    existing.append(str(item))
            continue
        if key in {"vm_lift_skipped", "vm_lift_forced"} and isinstance(value, bool):
            target[key] = target.get(key, False) or value
            continue
        if key not in target:
            target[key] = value


def _merge_iteration_metadata(
    aggregate: Dict[str, Any],
    meta: Dict[str, Any],
    *,
    version_name: str,
    changed: bool,
) -> None:
    aggregate.setdefault("payload_iterations", 0)
    aggregate["payload_iterations"] += 1

    versions = aggregate.setdefault("payload_iteration_versions", [])
    versions.append(version_name)

    changes = aggregate.setdefault("payload_iteration_changes", [])
    changes.append(bool(changed))

    aggregate.setdefault("initial_version", version_name)
    aggregate["final_version"] = version_name

    for key in ("handler_payload_offset", "script_key_override", "bootstrapper_path", "bootstrapper"):
        if key in meta and key not in aggregate:
            aggregate[key] = meta[key]

    for key in ("handler_payload_chunks", "handler_chunk_success_count", "handler_bytecode_bytes", "handler_payload_bytes", "decoded_bytes"):
        value = meta.get(key)
        if isinstance(value, int):
            aggregate[key] = aggregate.get(key, 0) + max(value, 0)

    if meta.get("script_payload"):
        aggregate["script_payload"] = True
    if meta.get("decoded_json"):
        aggregate["decoded_json"] = True

    _extend_list(
        aggregate,
        "handler_chunk_decoded_bytes",
        meta.get("handler_chunk_decoded_bytes"),
        allow_false=True,
        predicate=lambda value: isinstance(value, int),
    )
    _extend_list(
        aggregate,
        "handler_chunk_encoded_lengths",
        meta.get("handler_chunk_encoded_lengths"),
        allow_false=True,
        predicate=lambda value: isinstance(value, int),
    )
    _extend_list(
        aggregate,
        "handler_chunk_cleaned",
        meta.get("handler_chunk_cleaned"),
        allow_false=True,
        predicate=lambda value: isinstance(value, bool),
    )
    _extend_list(
        aggregate,
        "handler_chunk_rename_counts",
        meta.get("handler_chunk_rename_counts"),
        allow_false=True,
        predicate=lambda value: isinstance(value, int),
    )
    _extend_list(
        aggregate,
        "handler_chunk_sources",
        meta.get("handler_chunk_sources"),
        predicate=lambda value: isinstance(value, str) and value != "",
    )
    _extend_list(
        aggregate,
        "handler_chunk_errors",
        meta.get("handler_chunk_errors"),
        predicate=lambda value: isinstance(value, dict),
    )
    _extend_list(
        aggregate,
        "decode_attempts",
        meta.get("decode_attempts"),
        predicate=lambda value: isinstance(value, dict),
    )
    _extend_list(
        aggregate,
        "warnings",
        meta.get("warnings"),
        predicate=lambda value: bool(value),
    )

    combined = meta.get("handler_chunk_combined_source")
    if isinstance(combined, str) and combined.strip():
        aggregate["handler_chunk_combined_source"] = combined

    payload_meta = aggregate.setdefault("handler_payload_meta", {})
    _merge_payload_meta(payload_meta, meta.get("handler_payload_meta"))

    summary = {
        "version": version_name,
        "chunks": meta.get("handler_payload_chunks", 0),
        "decoded_bytes": meta.get("handler_bytecode_bytes") or meta.get("handler_payload_bytes") or meta.get("decoded_bytes") or 0,
        "script_payload": bool(meta.get("script_payload")),
        "changed": bool(changed),
    }
    aggregate.setdefault("payload_iteration_summary", []).append(summary)

    skip_keys = {
        "handler_chunk_decoded_bytes",
        "handler_chunk_encoded_lengths",
        "handler_chunk_cleaned",
        "handler_chunk_sources",
        "handler_chunk_rename_counts",
        "handler_chunk_errors",
        "handler_payload_meta",
        "handler_vm_bytecode",
        "decode_attempts",
        "warnings",
    }
    for key, value in meta.items():
        if key in skip_keys:
            continue
        if key not in aggregate:
            aggregate[key] = value


def _detect_literal_script_key(*candidates: Optional[str]) -> Optional[str]:
    for text in candidates:
        if not isinstance(text, str) or not text:
            continue
        match = _SCRIPT_KEY_LITERAL_RE.search(text)
        if match:
            value = match.group(1).strip()
            if value:
                return value
    return None


def _ensure_payload_meta_dict(payload_meta: Any) -> Dict[str, Any]:
    if isinstance(payload_meta, dict):
        return payload_meta
    return {}


def _populate_payload_summary(
    ctx: "Context",
    metadata: Dict[str, Any],
    *,
    script_key_value: Optional[str],
    script_key_override: bool,
    script_key_missing_forced: bool = False,
) -> None:
    payload_meta = _ensure_payload_meta_dict(metadata.get("handler_payload_meta"))

    if payload_meta is not metadata.get("handler_payload_meta"):
        metadata["handler_payload_meta"] = payload_meta

    # Script key bookkeeping -------------------------------------------------
    options = getattr(ctx, "options", {}) if ctx else {}

    def _normalise_provider_label(label: Optional[str]) -> Optional[str]:
        if not label:
            return None
        lowered = label.strip().lower()
        mapping = {
            "bootstrapper": "bootstrap",
            "bootstrap": "bootstrap",
            "override": "override",
            "manual": "override",
            "literal": "literal",
            "missing_forced": "missing_forced",
            "forced_missing": "missing_forced",
            "heuristic": "heuristic",
        }
        return mapping.get(lowered, lowered)

    provider = _normalise_provider_label(payload_meta.get("script_key_provider"))
    provider_hint: Optional[str] = None
    if isinstance(options, Mapping):
        hint = options.get("script_key_source")
        if isinstance(hint, str) and hint:
            provider_hint = hint
            if hint == "literal":
                script_key_override = False
                metadata["script_key_override"] = False
    literal_key = _detect_literal_script_key(
        getattr(ctx, "original_text", None),
        getattr(ctx, "raw_input", None),
        getattr(ctx, "stage_output", None),
    )

    if script_key_value is None and literal_key:
        script_key_value = literal_key

    hint_label = _normalise_provider_label(provider_hint)
    forced_flag = bool(script_key_missing_forced)
    if not forced_flag:
        forced_flag = bool(metadata.get("script_key_missing_forced"))
    existing_flag = payload_meta.get("script_key_missing_forced")
    if isinstance(existing_flag, bool):
        forced_flag = forced_flag or existing_flag
    if forced_flag:
        payload_meta["script_key_missing_forced"] = True
        metadata["script_key_missing_forced"] = True
    else:
        payload_meta.pop("script_key_missing_forced", None)

    provider_candidate = provider
    if forced_flag:
        provider_candidate = "missing_forced"
    elif script_key_override:
        provider_candidate = "override"
    elif hint_label:
        provider_candidate = hint_label
    elif provider_candidate:
        provider_candidate = provider_candidate
    elif literal_key:
        provider_candidate = "literal"
    elif getattr(ctx, "bootstrapper_path", None) and script_key_value:
        provider_candidate = "bootstrap"
    elif script_key_value and provider_candidate is None:
        provider_candidate = "heuristic"

    if provider_candidate:
        payload_meta["script_key_provider"] = provider_candidate

    if script_key_value:
        payload_meta.setdefault("script_key", script_key_value)
        payload_meta.setdefault("script_key_length", len(script_key_value))

    # Alphabet/opcode provenance --------------------------------------------
    def _normalise_source_label(value: Optional[str]) -> Optional[str]:
        if not value:
            return None
        lowered = value.strip().lower()
        mapping = {
            "bootstrapper": "bootstrap",
            "bootstrap": "bootstrap",
            "manual_override": "manual_override",
            "override": "manual_override",
            "manual": "manual_override",
            "default": "heuristic",
            "auto": "heuristic",
            "heuristic": "heuristic",
        }
        return mapping.get(lowered, lowered)

    alphabet_source = _normalise_source_label(payload_meta.get("alphabet_source"))
    if alphabet_source is None:
        sources = metadata.get("chunk_alphabet_sources")
        if isinstance(sources, list):
            for candidate in reversed(sources):
                if isinstance(candidate, str) and candidate.strip():
                    alphabet_source = _normalise_source_label(candidate)
                    if alphabet_source:
                        break
        manual_alphabet = getattr(ctx, "manual_alphabet", None)
        if alphabet_source is None:
            if isinstance(manual_alphabet, str) and manual_alphabet.strip():
                alphabet_source = "manual_override"
            elif getattr(ctx, "bootstrapper_path", None):
                alphabet_source = "bootstrap"
            else:
                alphabet_source = "heuristic"
        payload_meta["alphabet_source"] = alphabet_source
    else:
        payload_meta["alphabet_source"] = alphabet_source

    opcode_source = _normalise_source_label(payload_meta.get("opcode_source"))
    if opcode_source is None:
        manual_opcode = getattr(ctx, "manual_opcode_map", None)
        if isinstance(manual_opcode, Mapping) and manual_opcode:
            opcode_source = "manual_override"
        elif getattr(ctx, "bootstrapper_path", None):
            opcode_source = "bootstrap"
        else:
            opcode_source = "heuristic"
        payload_meta["opcode_source"] = opcode_source
    else:
        payload_meta["opcode_source"] = opcode_source

    # Chunk statistics -------------------------------------------------------
    chunk_count = metadata.get("chunk_count")
    if not isinstance(chunk_count, int) or chunk_count <= 0:
        chunk_count = metadata.get("handler_payload_chunks")
    if isinstance(chunk_count, int) and chunk_count >= 0:
        payload_meta.setdefault("chunk_count", chunk_count)

    encoded_lengths = metadata.get("chunk_encoded_lengths")
    if not isinstance(encoded_lengths, list):
        encoded_lengths = metadata.get("handler_chunk_encoded_lengths")
    if isinstance(encoded_lengths, list):
        payload_meta.setdefault(
            "chunk_encoded_lengths",
            [int(value) for value in encoded_lengths if isinstance(value, int)],
        )
        payload_meta.setdefault("chunk_lengths", payload_meta.get("chunk_encoded_lengths", []))

    decoded_lengths = metadata.get("chunk_decoded_bytes")
    if not isinstance(decoded_lengths, list):
        decoded_lengths = metadata.get("handler_chunk_decoded_bytes")
    if isinstance(decoded_lengths, list):
        payload_meta.setdefault(
            "chunk_decoded_bytes",
            [int(value) for value in decoded_lengths if isinstance(value, int)],
        )

    chunk_success = metadata.get("chunk_success_count")
    if not isinstance(chunk_success, int):
        chunk_success = metadata.get("handler_chunk_success_count")
    if isinstance(chunk_success, int) and chunk_success >= 0:
        payload_meta.setdefault("chunk_success_count", chunk_success)

    # Decode metadata --------------------------------------------------------
    decode_method = payload_meta.get("decode_method") or metadata.get("decode_method")
    if decode_method:
        payload_meta["decode_method"] = decode_method
    elif metadata.get("chunk_count") or payload_meta.get("chunk_count"):
        payload_meta.setdefault("decode_method", "base91")

    if "index_xor" not in payload_meta:
        payload_meta["index_xor"] = bool(script_key_value or metadata.get("chunk_count"))

    # Bootstrapper provenance -------------------------------------------------
    bootstrap_info = {}
    if isinstance(payload_meta.get("bootstrapper"), dict):
        bootstrap_info.update(payload_meta["bootstrapper"])

    bootstrap_meta = metadata.get("bootstrapper")
    if isinstance(bootstrap_meta, dict):
        bootstrap_info.update({str(k): v for k, v in bootstrap_meta.items()})

    path_value = bootstrap_info.get("path") or bootstrap_info.get("source")
    if not path_value and getattr(ctx, "bootstrapper_path", None):
        path_value = str(ctx.bootstrapper_path)
    if path_value:
        path_obj = Path(path_value)
        if path_obj.is_dir():
            for candidate_name in ("initv4.lua", "init.lua", "bootstrap.lua"):
                candidate = path_obj / candidate_name
                if candidate.exists():
                    path_value = str(candidate)
                    break
        bootstrap_info["path"] = path_value

    ctx_bootstrap_meta = getattr(ctx, "bootstrapper_metadata", None)
    alphabet_length: Optional[int] = None
    alphabet_preview: Optional[str] = None
    opcode_entries: Optional[int] = None
    opcode_sample: List[Dict[str, str]] = []
    opcode_map_data: Optional[Dict[str, str]] = None

    def _process_opcode_mapping(mapping: Mapping[Any, Any]) -> None:
        nonlocal opcode_sample, opcode_map_data
        converted: Dict[str, str] = {}
        entries: List[Tuple[int, str]] = []
        for raw_key, raw_value in mapping.items():
            opcode_int: Optional[int] = None
            name: Optional[str] = None

            if isinstance(raw_key, (int, str)):
                try:
                    opcode_int = int(raw_key, 0) if isinstance(raw_key, str) else int(raw_key)
                except (TypeError, ValueError):
                    opcode_int = None
                else:
                    name = str(raw_value)

            if opcode_int is None and isinstance(raw_value, (int, str)):
                try:
                    opcode_int = int(raw_value, 0) if isinstance(raw_value, str) else int(raw_value)
                except (TypeError, ValueError):
                    opcode_int = None
                else:
                    name = str(raw_key)

            if opcode_int is None or name is None:
                continue

            entries.append((opcode_int, name))
            key_hex = f"0x{opcode_int:02X}"
            converted.setdefault(key_hex, name)
        if not entries:
            return
        entries.sort(key=lambda item: item[0])
        if not opcode_sample:
            formatted: List[Dict[str, str]] = []
            for opcode_int, name in entries[:10]:
                formatted.append({f"0x{opcode_int:02X}": name})
            opcode_sample = formatted
        if opcode_map_data is None and converted:
            opcode_map_data = converted

    if isinstance(ctx_bootstrap_meta, Mapping):
        for key in ("alphabet_length", "alphabet_len"):
            raw = ctx_bootstrap_meta.get(key)
            if isinstance(raw, int) and raw > 0:
                alphabet_length = raw
                break
        preview_value = ctx_bootstrap_meta.get("alphabet_preview")
        if isinstance(preview_value, str) and preview_value:
            alphabet_preview = preview_value
        map_block = ctx_bootstrap_meta.get("opcode_map")
        if isinstance(map_block, Mapping) and map_block:
            _process_opcode_mapping(map_block)
            if opcode_entries is None:
                opcode_entries = len(map_block)
        sample_block = ctx_bootstrap_meta.get("opcode_map_sample")
        if not opcode_sample and isinstance(sample_block, list):
            formatted: List[Dict[str, str]] = []
            for entry in sample_block:
                if isinstance(entry, Mapping):
                    formatted.append({str(k): str(v) for k, v in entry.items()})
            if formatted:
                opcode_sample = formatted
        if alphabet_length is None:
            alphabet_block = ctx_bootstrap_meta.get("alphabet")
            if isinstance(alphabet_block, Mapping):
                length_value = alphabet_block.get("length")
                if isinstance(length_value, int) and length_value > 0:
                    alphabet_length = length_value
                else:
                    value = alphabet_block.get("value")
                    if isinstance(value, str) and value:
                        alphabet_length = len(value)
                        alphabet_preview = value[:32] + ("..." if len(value) > 32 else "")

        dispatch = ctx_bootstrap_meta.get("opcode_dispatch")
        if isinstance(dispatch, Mapping):
            count = dispatch.get("count")
            if isinstance(count, int) and count >= 0:
                opcode_entries = count
            mapping = dispatch.get("mapping")
            if opcode_entries is None and isinstance(mapping, Mapping):
                opcode_entries = len(mapping)
            if isinstance(mapping, Mapping):
                _process_opcode_mapping(mapping)

    if (alphabet_length is None or opcode_entries is None) and path_value:
        try:
            from ..versions.initv4 import InitV4Bootstrap, _BASE_OPCODE_SPECS  # type: ignore
        except Exception:  # pragma: no cover - optional dependency
            pass
        else:
            try:
                bootstrap = InitV4Bootstrap.load(path_value)
            except Exception:  # pragma: no cover - best effort
                bootstrap = None
            if bootstrap is not None:
                try:
                    alphabet_candidate = bootstrap.alphabet()
                except Exception:  # pragma: no cover - best effort
                    alphabet_candidate = None
                if alphabet_length is None:
                    meta_length = bootstrap.metadata.get("alphabet_length")
                    if isinstance(meta_length, int) and meta_length > 0:
                        alphabet_length = meta_length
                        alphabet_value = bootstrap.metadata.get("alphabet")
                        if isinstance(alphabet_value, Mapping):
                            value_text = alphabet_value.get("value")
                            if isinstance(value_text, str) and value_text:
                                alphabet_preview = value_text[:32] + ("..." if len(value_text) > 32 else "")
                        if alphabet_preview is None and isinstance(alphabet_candidate, str) and alphabet_candidate:
                            alphabet_preview = alphabet_candidate[:32] + ("..." if len(alphabet_candidate) > 32 else "")
                    elif isinstance(alphabet_candidate, str) and alphabet_candidate:
                        alphabet_length = len(alphabet_candidate)
                        alphabet_preview = alphabet_candidate[:32] + ("..." if len(alphabet_candidate) > 32 else "")
                if opcode_entries is None:
                    try:
                        mapping = bootstrap.opcode_mapping(_BASE_OPCODE_SPECS)
                    except Exception:  # pragma: no cover - best effort
                        mapping = None
                    if isinstance(mapping, Mapping) and mapping:
                        opcode_entries = len(mapping)
                        _process_opcode_mapping(mapping)
                    else:
                        meta_count = bootstrap.metadata.get("opcode_map_entries")
                        if isinstance(meta_count, int) and meta_count > 0:
                            opcode_entries = meta_count
                            mapping_meta = bootstrap.metadata.get("opcode_dispatch")
                            if isinstance(mapping_meta, Mapping):
                                mapping_value = mapping_meta.get("mapping")
                                if isinstance(mapping_value, Mapping):
                                    _process_opcode_mapping(mapping_value)

    if alphabet_length:
        bootstrap_info.setdefault("alphabet_length", alphabet_length)
        if alphabet_preview:
            bootstrap_info.setdefault("alphabet_preview", alphabet_preview)
    if opcode_entries:
        bootstrap_info.setdefault("opcode_map_entries", opcode_entries)
    if opcode_sample and "opcode_map_sample" not in bootstrap_info:
        bootstrap_info["opcode_map_sample"] = opcode_sample
    if opcode_map_data and "opcode_map" not in bootstrap_info:
        bootstrap_info["opcode_map"] = opcode_map_data

    if bootstrap_info:
        payload_meta["bootstrapper"] = bootstrap_info

    if alphabet_length or opcode_entries:
        existing_bootstrap_meta = metadata.get("bootstrapper_metadata")
        if isinstance(existing_bootstrap_meta, Mapping):
            bootstrap_meta = dict(existing_bootstrap_meta)
        else:
            bootstrap_meta = {}
        if alphabet_length and "alphabet_len" not in bootstrap_meta:
            bootstrap_meta["alphabet_len"] = alphabet_length
        if alphabet_length and "alphabet_length" not in bootstrap_meta:
            bootstrap_meta["alphabet_length"] = alphabet_length
        if alphabet_preview and "alphabet_preview" not in bootstrap_meta:
            bootstrap_meta["alphabet_preview"] = alphabet_preview
        if opcode_entries and "opcode_map_count" not in bootstrap_meta:
            bootstrap_meta["opcode_map_count"] = opcode_entries
        if opcode_sample and "opcode_map_sample" not in bootstrap_meta:
            bootstrap_meta["opcode_map_sample"] = opcode_sample
        if opcode_map_data and "opcode_map" not in bootstrap_meta:
            bootstrap_meta["opcode_map"] = opcode_map_data
        if bootstrap_meta:
            metadata["bootstrapper_metadata"] = bootstrap_meta
            try:
                current_ctx_meta = getattr(ctx, "bootstrapper_metadata")
            except AttributeError:
                current_ctx_meta = None
            if isinstance(current_ctx_meta, Mapping):
                merged_ctx_meta = dict(current_ctx_meta)
                merged_ctx_meta.update(bootstrap_meta)
                setattr(ctx, "bootstrapper_metadata", merged_ctx_meta)
            else:
                setattr(ctx, "bootstrapper_metadata", dict(bootstrap_meta))


def _unique_ordered(values: Iterable[Any]) -> List[Any]:
    seen: Set[Any] = set()
    ordered: List[Any] = []
    for value in values:
        marker = value
        if isinstance(value, dict):
            marker = tuple(sorted(value.items()))
        if marker in seen:
            continue
        seen.add(marker)
        ordered.append(value)
    return ordered


def _finalise_metadata(
    aggregate: Dict[str, Any],
    last_meta: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    if not aggregate:
        final = dict(last_meta or {})
        if "handler_payload_meta" in final:
            payload_meta = final.get("handler_payload_meta")
            if not isinstance(payload_meta, dict):
                final["handler_payload_meta"] = {}
        return final

    final = dict(aggregate)

    if "handler_payload_meta" in final or (
        isinstance(last_meta, dict) and "handler_payload_meta" in last_meta
    ):
        payload_meta: Dict[str, Any] = {}
        current_meta = final.get("handler_payload_meta")
        if isinstance(current_meta, dict):
            payload_meta.update(current_meta)
        if isinstance(last_meta, dict):
            previous_meta = last_meta.get("handler_payload_meta")
            if isinstance(previous_meta, dict):
                for key, value in previous_meta.items():
                    payload_meta.setdefault(key, value)
        final["handler_payload_meta"] = payload_meta

    if last_meta:
        if last_meta.get("script_payload"):
            final["script_payload"] = True
        for key in (
            "handler_chunk_combined_source",
            "handler_chunk_sources",
            "handler_chunk_cleaned",
            "handler_chunk_rename_counts",
            "handler_chunk_errors",
            "decode_attempts",
            "warnings",
            "vm_ir",
        ):
            if key not in final and key in last_meta:
                final[key] = last_meta[key]

        for key in ("handler_payload_offset", "bootstrapper_path", "bootstrapper", "script_key_override"):
            if key not in final and key in last_meta:
                final[key] = last_meta[key]

    warnings = final.get("warnings")
    if isinstance(warnings, list):
        final["warnings"] = _unique_ordered(str(item) for item in warnings if item)

    iterations = final.get("payload_iterations")
    if not isinstance(iterations, int) or iterations <= 0:
        final["payload_iterations"] = 1

    versions = final.get("payload_iteration_versions")
    if isinstance(versions, list):
        final["payload_iteration_versions"] = [str(entry) for entry in versions if entry]
    elif last_meta is not None:
        final["payload_iteration_versions"] = [final.get("final_version")] if final.get("final_version") else []

    changes = final.get("payload_iteration_changes")
    if isinstance(changes, list):
        final["payload_iteration_changes"] = [bool(entry) for entry in changes]

    final.pop("handler_vm_bytecode", None)

    return final


def _has_remaining_payload(text: str, version: Any) -> bool:
    if not isinstance(text, str) or not text.strip():
        return False
    if version is None:
        return False
    is_unknown = getattr(version, "is_unknown", False)
    if is_unknown:
        return False
    version_name = getattr(version, "name", "")
    if not version_name:
        return False
    try:
        handler = get_handler(version_name)
    except KeyError:
        return False
    if not isinstance(handler, VersionHandler):
        return False
    try:
        payload = handler.locate_payload(text)
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("failed to probe payload for %s: %s", version_name, exc)
        return False
    if payload is None:
        if (
            isinstance(version_name, str)
            and "initv4" in version_name.lower()
            and _INITV4_PAYLOAD_RE.search(text)
        ):
            return True
        return False
    if isinstance(payload.data, (dict, list)):
        return True
    meta = payload.metadata or {}
    if meta.get("_chunks") or meta.get("chunk_count"):
        return True
    payload_text = payload.text
    if isinstance(payload_text, str):
        cleaned = payload_text.strip()
        return len(cleaned) >= 16
    return False


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

    force_mode = bool(getattr(ctx, "force", False))
    if isinstance(ctx.options, dict):
        force_mode = bool(ctx.options.get("force")) or force_mode

    iteration_limit = _payload_iteration_limit(ctx)
    aggregated: Dict[str, Any] = {}
    final_output = text
    current_version = version
    current_features = features
    seen_outputs: Set[str] = {text}
    last_metadata: Optional[Dict[str, Any]] = None

    if isinstance(version.name, str) and version.name.startswith("luraph_v14_4"):
        decoded_chunks, _, chunk_meta = _iterative_initv4_decode(
            ctx,
            text,
            script_key=script_key if isinstance(script_key, str) else None,
            max_iterations=iteration_limit,
            force=force_mode,
        )
        if decoded_chunks:
            aggregated.setdefault("decoded_chunks", []).extend(decoded_chunks)
        if chunk_meta:
            _merge_payload_meta(aggregated, chunk_meta)
            warnings = chunk_meta.get("warnings")
            if warnings:
                aggregated.setdefault("warnings", []).extend(str(msg) for msg in warnings)

    for iteration in range(iteration_limit):
        current_source = final_output
        override_key = script_key if iteration == 0 and isinstance(script_key, str) else None
        result = deob.decode_payload(
            current_source,
            version=current_version,
            features=current_features,
            script_key=override_key,
            bootstrapper=ctx.bootstrapper_path,
            force=force_mode,
        )

        handler_instance = getattr(deob, "last_handler", None)
        if isinstance(handler_instance, VersionHandler):
            ctx.version_handler = handler_instance
        else:
            ctx.version_handler = None

        output_text = result.text or ""
        changed = bool(output_text) and output_text != current_source
        if output_text:
            if not ctx.decoded_payloads or ctx.decoded_payloads[-1] != output_text:
                ctx.decoded_payloads.append(output_text)
        if changed:
            final_output = output_text
        ctx.stage_output = final_output

        if (
            isinstance(current_version.name, str)
            and current_version.name.startswith("luraph_v14_4")
        ):
            post_chunks, post_text, post_meta = _iterative_initv4_decode(
                ctx,
                final_output,
                script_key=script_key if isinstance(script_key, str) else None,
                max_iterations=1,
                force=force_mode,
            )
            if post_chunks:
                aggregated.setdefault("decoded_chunks", []).extend(post_chunks)
            if post_meta:
                _merge_payload_meta(aggregated, post_meta)
                warnings = post_meta.get("warnings")
                if warnings:
                    aggregated.setdefault("warnings", []).extend(
                        str(message) for message in warnings
                    )
            if post_text != final_output and post_text:
                final_output = post_text
                ctx.stage_output = final_output
                if not ctx.decoded_payloads or ctx.decoded_payloads[-1] != final_output:
                    ctx.decoded_payloads.append(final_output)
                changed = True

        iteration_metadata: Dict[str, Any] = dict(result.metadata)
        vm_ir = iteration_metadata.pop("vm_ir", None)
        if isinstance(vm_ir, VMIR):
            ctx.vm_ir = vm_ir
            if vm_ir.constants and not ctx.vm.const_pool:
                ctx.vm.const_pool = list(vm_ir.constants)
            iteration_metadata["vm_ir"] = {
                "constants": len(vm_ir.constants),
                "bytecode": len(vm_ir.bytecode),
                "prototypes": len(vm_ir.prototypes or []),
            }

        if current_version.name == "luraph_v14_2_json":
            handler_meta = _populate_v142_json_payload(ctx, current_source)
            if handler_meta:
                iteration_metadata.update(handler_meta)

        _merge_iteration_metadata(
            aggregated,
            iteration_metadata,
            version_name=current_version.name,
            changed=changed,
        )

        requires_key = current_version.name in {"luraph_v14_4_initv4", "v14.4.1"}
        error_text = iteration_metadata.get("handler_bytecode_error")
        if requires_key and isinstance(error_text, str):
            if "script key" in error_text.lower():
                base_message = error_text.strip()
                advisory = (
                    "Provide --script-key <key> or re-run with --force for best-effort partial decoding."
                )
                message = f"{base_message} {advisory}".strip()
                if force_mode:
                    LOG.warning("script key missing for %s; continuing due to --force", current_version.name)
                    warnings_bucket = aggregated.setdefault("warnings", [])
                    if message not in warnings_bucket:
                        warnings_bucket.append(message)
                    if ctx.report is not None and message not in ctx.report.warnings:
                        ctx.report.warnings.append(message)
                else:
                    LOG.error("%s", message)
                    if ctx.report is not None and message not in ctx.report.errors:
                        ctx.report.errors.append(message)
                    raise RuntimeError(message)

        _apply_vm_bytecode(ctx, dict(iteration_metadata), current_version.name)
        last_metadata = iteration_metadata

        if not changed:
            break

        if final_output in seen_outputs:
            break
        seen_outputs.add(final_output)

        next_version = deob.detect_version(final_output, from_json=ctx.from_json)
        current_version = next_version
        current_features = next_version.features if next_version.features else None

        if not _has_remaining_payload(final_output, current_version):
            break

    ctx.stage_output = final_output
    ctx.detected_version = current_version

    metadata = _finalise_metadata(aggregated, last_metadata)

    payload_meta = metadata.get("handler_payload_meta")
    if isinstance(payload_meta, dict):
        extraction_meta = payload_meta.get("bootstrapper_metadata")
        if isinstance(extraction_meta, dict) and extraction_meta:
            ctx.result.setdefault("bootstrapper_metadata", dict(extraction_meta))
    ctx_bootstrap_meta = getattr(ctx, "bootstrapper_metadata", None)
    if isinstance(ctx_bootstrap_meta, dict) and ctx_bootstrap_meta:
        ctx.result.setdefault("bootstrapper_metadata", {})
        try:
            merged = dict(ctx.result["bootstrapper_metadata"])
        except Exception:
            merged = {}
        merged.update(ctx_bootstrap_meta)
        raw_existing = merged.get("raw_matches")
        ctx_raw = ctx_bootstrap_meta.get("raw_matches")
        if isinstance(ctx_raw, dict):
            base_raw: Dict[str, Any] = {}
            if isinstance(raw_existing, dict):
                base_raw.update(raw_existing)
            base_raw.update(ctx_raw)
            merged["raw_matches"] = base_raw
        ctx.result["bootstrapper_metadata"] = merged

    placeholder_source = metadata.get("handler_placeholder_source")
    if (
        isinstance(placeholder_source, str)
        and placeholder_source.strip()
        and not metadata.get("script_payload")
    ):
        final_output = placeholder_source
        ctx.stage_output = final_output
        ctx.working_text = final_output
        metadata["placeholder_output"] = True
        if not ctx.decoded_payloads or ctx.decoded_payloads[-1] != final_output:
            ctx.decoded_payloads.append(final_output)

    script_key_value: Optional[str] = None
    if isinstance(script_key, str) and script_key.strip():
        script_key_value = script_key.strip()
    elif isinstance(ctx.script_key, str) and ctx.script_key.strip():
        script_key_value = ctx.script_key.strip()
    else:
        payload_meta = metadata.get("handler_payload_meta")
        if isinstance(payload_meta, dict):
            candidate = payload_meta.get("script_key")
            if isinstance(candidate, str) and candidate.strip():
                script_key_value = candidate.strip()

    if _should_apply_inline_fallback(final_output, metadata):
        handler_for_fallback: Optional[VersionHandler]
        if isinstance(ctx.version_handler, VersionHandler):
            handler_for_fallback = ctx.version_handler
        else:
            handler_for_fallback = None

        fallback_output, fallback_meta, fallback_changed = _apply_inline_fallback(
            ctx,
            final_output,
            metadata,
            script_key=script_key_value,
            handler=handler_for_fallback,
            version=current_version,
        )
        if fallback_meta:
            metadata.setdefault("fallback_inline", {}).update(fallback_meta)
        if fallback_changed:
            final_output = fallback_output
            ctx.stage_output = final_output
            ctx.working_text = final_output
            if not ctx.decoded_payloads or ctx.decoded_payloads[-1] != final_output:
                ctx.decoded_payloads.append(final_output)

    decoded_simple = _decode_simple_bootstrap(final_output, script_key_value)
    if decoded_simple and decoded_simple != final_output:
        final_output = decoded_simple
        ctx.stage_output = final_output
        ctx.working_text = final_output
        metadata["script_payload"] = True
        metadata.setdefault("decode_method", "base91")
        if not ctx.decoded_payloads or ctx.decoded_payloads[-1] != final_output:
            ctx.decoded_payloads.append(final_output)
        if ctx.report is not None:
            ctx.report.blob_count = max(ctx.report.blob_count, len(ctx.decoded_payloads))
            if final_output:
                ctx.report.decoded_bytes = max(
                    ctx.report.decoded_bytes,
                    sum(len(entry.encode("utf-8")) for entry in ctx.decoded_payloads),
                )

    chunk_outputs = _persist_chunk_outputs(ctx, final_output)
    if chunk_outputs:
        metadata.setdefault("chunk_output_paths", list(chunk_outputs))
        ctx.result.setdefault("artifacts", {})
        artifacts = ctx.result["artifacts"]
        if isinstance(artifacts, dict):
            chunk_bucket = artifacts.setdefault("chunk_outputs", [])
            if isinstance(chunk_bucket, list):
                for path in chunk_outputs:
                    if path not in chunk_bucket:
                        chunk_bucket.append(path)
            else:
                artifacts["chunk_outputs"] = list(chunk_outputs)

    decoded_output_paths = metadata.get("decoded_output_paths")
    if not (
        isinstance(decoded_output_paths, list) and any(decoded_output_paths)
    ):
        persisted_final = _persist_decoded_outputs(
            ctx,
            final_output,
            None,
            chunk_index=0,
        )
        if persisted_final:
            lua_path = persisted_final.get("lua")
            json_path = persisted_final.get("json")
            if lua_path:
                metadata.setdefault("decoded_output_paths", []).append(lua_path)
            if json_path:
                metadata.setdefault("unpacked_dump_paths", []).append(json_path)

    _populate_payload_summary(
        ctx,
        metadata,
        script_key_value=script_key_value,
        script_key_override=bool(metadata.get("script_key_override")),
        script_key_missing_forced=bool(getattr(ctx, "script_key_missing_forced", False)),
    )

    placeholder_blob = _ensure_bootstrap_blob_placeholder(
        getattr(ctx, "bootstrapper_path", None)
    )
    if placeholder_blob:
        metadata.setdefault("bootstrapper_blob_b64", placeholder_blob)
        ctx.result.setdefault("artifacts", {})
        artifacts = ctx.result["artifacts"]
        if isinstance(artifacts, dict):
            blob_bucket = artifacts.setdefault("bootstrap_blob_b64", [])
            if isinstance(blob_bucket, list):
                if placeholder_blob not in blob_bucket:
                    blob_bucket.append(placeholder_blob)
            else:
                artifacts["bootstrap_blob_b64"] = [placeholder_blob]

    summary_artifacts = _ensure_summary_artifacts(metadata)
    if summary_artifacts.get("unpacked_json"):
        metadata.setdefault("unpacked_json_path", summary_artifacts["unpacked_json"])
        ctx.result.setdefault("artifacts", {})
        artifacts = ctx.result["artifacts"]
        if isinstance(artifacts, dict):
            unpacked_bucket = artifacts.setdefault("unpacked_json", [])
            if isinstance(unpacked_bucket, list):
                if summary_artifacts["unpacked_json"] not in unpacked_bucket:
                    unpacked_bucket.append(summary_artifacts["unpacked_json"])
            else:
                artifacts["unpacked_json"] = [summary_artifacts["unpacked_json"]]

    const_pool = ctx.vm.const_pool or []
    if const_pool:
        jump_meta = _detect_jump_table(const_pool)
        if jump_meta:
            metadata.setdefault("vm_jump_table", dict(jump_meta))
            ctx.vm_metadata.setdefault("jump_table", dict(jump_meta))

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

        chunk_decoded_raw = metadata.get("handler_chunk_decoded_bytes")
        chunk_decoded: List[int] = []
        if isinstance(chunk_decoded_raw, list):
            chunk_decoded = [
                value for value in chunk_decoded_raw if isinstance(value, int) and value >= 0
            ]

        chunk_encoded_raw = metadata.get("handler_chunk_encoded_lengths")
        chunk_encoded: List[int] = []
        if isinstance(chunk_encoded_raw, list):
            chunk_encoded = [
                value for value in chunk_encoded_raw if isinstance(value, int) and value >= 0
            ]

        chunk_success: Optional[int] = metadata.get("handler_chunk_success_count")
        if not isinstance(chunk_success, int) or chunk_success < 0:
            chunk_success = None
            payload_meta_snapshot = metadata.get("handler_payload_meta")
            if isinstance(payload_meta_snapshot, Mapping):
                success_candidate = payload_meta_snapshot.get("chunk_success_count")
                if isinstance(success_candidate, int) and success_candidate >= 0:
                    chunk_success = success_candidate

        chunk_count = metadata.get("handler_payload_chunks")
        if isinstance(chunk_count, int) and chunk_count > 0:
            report.blob_count = chunk_success if chunk_success is not None else chunk_count
            if chunk_decoded:
                report.decoded_bytes = sum(chunk_decoded)
                decoded_warning = "Decoded chunk sizes (bytes): " + ", ".join(
                    str(value) for value in chunk_decoded
                )
                if decoded_warning not in report.warnings:
                    report.warnings.append(decoded_warning)
            elif lengths:
                report.decoded_bytes = sum(lengths)
            elif chunk_encoded:
                report.decoded_bytes = sum(chunk_encoded)
        else:
            if chunk_decoded:
                report.blob_count = chunk_success if chunk_success is not None else len(
                    chunk_decoded
                )
                report.decoded_bytes = sum(chunk_decoded)
                decoded_warning = "Decoded chunk sizes (bytes): " + ", ".join(
                    str(value) for value in chunk_decoded
                )
                if decoded_warning not in report.warnings:
                    report.warnings.append(decoded_warning)
            elif lengths:
                report.blob_count = chunk_success if chunk_success is not None else len(
                    lengths
                )
                report.decoded_bytes = sum(lengths)
            elif chunk_success is not None:
                report.blob_count = chunk_success

        warnings = metadata.get("warnings")
        if isinstance(warnings, list):
            report.warnings.extend(str(item) for item in warnings if item)

    chunk_count_value = metadata.get("handler_payload_chunks")
    if not isinstance(chunk_count_value, int) or chunk_count_value <= 0:
        payload_meta_snapshot = metadata.get("handler_payload_meta")
        if isinstance(payload_meta_snapshot, Mapping):
            raw_count = payload_meta_snapshot.get("chunk_count")
            if isinstance(raw_count, int) and raw_count > 0:
                chunk_count_value = raw_count

    chunk_success_value: Optional[int] = metadata.get("handler_chunk_success_count")
    if not isinstance(chunk_success_value, int) or chunk_success_value < 0:
        chunk_success_value = None
        payload_meta_snapshot = metadata.get("handler_payload_meta")
        if isinstance(payload_meta_snapshot, Mapping):
            raw_success = payload_meta_snapshot.get("chunk_success_count")
            if isinstance(raw_success, int) and raw_success >= 0:
                chunk_success_value = raw_success

    if isinstance(chunk_count_value, int) and chunk_count_value > 0:
        metadata["payload_iterations"] = max(
            metadata.get("payload_iterations", 1), chunk_count_value
        )
        if ctx.report is not None:
            effective_blob_count = (
                chunk_success_value
                if isinstance(chunk_success_value, int) and chunk_success_value >= 0
                else chunk_count_value
            )
            ctx.report.blob_count = max(ctx.report.blob_count, effective_blob_count)

    if ctx.decoded_payloads:
        metadata["payload_iterations"] = max(
            metadata.get("payload_iterations", 1), len(ctx.decoded_payloads)
        )
        if ctx.report is not None:
            ctx.report.blob_count = max(ctx.report.blob_count, len(ctx.decoded_payloads))

    if "handler_payload_meta" in metadata:
        payload_meta_final = metadata.get("handler_payload_meta")
        if isinstance(payload_meta_final, dict):
            metadata["handler_payload_meta"] = dict(payload_meta_final)
        else:
            metadata["handler_payload_meta"] = {}

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
