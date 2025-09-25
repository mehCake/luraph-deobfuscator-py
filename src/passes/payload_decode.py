"""Payload decoding helpers for version-specific handling."""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, TYPE_CHECKING

from .. import utils
from ..deobfuscator import VMIR
from ..versions import PayloadInfo, VersionHandler, get_handler

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
_TOP_LEVEL_LITERAL_RE = re.compile(
    r"^\s*(?:return\s+)?(?P<quote>['\"])(?P<body>.*)(?P=quote)\s*;?\s*$",
    re.DOTALL,
)
_STUB_HINT_RE = re.compile(r"init_fn\s*\(")


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

    default_limit = 3
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
        return dict(last_meta or {})

    final = dict(aggregate)

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

        chunk_count = metadata.get("handler_payload_chunks")
        if isinstance(chunk_count, int) and chunk_count > 0:
            report.blob_count = chunk_count
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
                report.blob_count = len(chunk_decoded)
                report.decoded_bytes = sum(chunk_decoded)
                decoded_warning = "Decoded chunk sizes (bytes): " + ", ".join(
                    str(value) for value in chunk_decoded
                )
                if decoded_warning not in report.warnings:
                    report.warnings.append(decoded_warning)
            elif lengths:
                report.blob_count = len(lengths)
                report.decoded_bytes = sum(lengths)

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
