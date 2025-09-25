"""High-level bootstrapper decoding pipeline.

This module exposes :class:`BootstrapDecoder`, a helper that inspects
Luraph-style bootstrapper scripts and attempts to recover the binary
payloads embedded inside them.  The pipeline mirrors the specification
provided by the integration tests and design documents:

* Locate encoded blob literals (``superflow_bytecode_ext*`` strings and
  other suspicious payloads).
* Try to reconstruct the decode routine in Python by composing simple
  transforms such as alphabet remapping and XOR mixing.
* If the Python implementation cannot confidently decode the blob,
  optionally fall back to a sandboxed Lua execution in a heavily
  restricted runtime (when :mod:`lupa` is installed and the caller opts
  in).
* Extract metadata (alphabet strings, opcode mappings, constants) from
  the decoded payload and persist both the decoded bytes and metadata to
  ``out/logs``.

The module favours safety over permissiveness.  Unknown code is never
executed directly; the sandboxed Lua fallback only loads the specific
decode routine, disables dangerous APIs, and enforces soft timeouts.  If
no reliable decode path is found the pipeline marks the blob as
``needs_emulation`` so that a downstream human can decide how to
continue.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:  # Optional dependency used for Lua sandbox fallback
    from lupa import LuaError, LuaRuntime
except ImportError:  # pragma: no cover - optional dependency may be absent
    LuaRuntime = None  # type: ignore[assignment]
    LuaError = RuntimeError  # type: ignore[assignment]


LOG = logging.getLogger(__name__)


@dataclass
class BlobInfo:
    """Represents a detected bootstrapper blob literal."""

    name: Optional[str]
    literal: str
    start: int
    end: int
    parts: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        preview = self.literal[:80]
        if len(self.literal) > 80:
            preview += "…"
        return {
            "name": self.name,
            "literal_preview": preview,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class DecoderCandidate:
    """Metadata for a candidate Lua decoder function."""

    name: Optional[str]
    params: List[str]
    body: str
    source: str
    start: int
    end: int
    hints: List[str] = field(default_factory=list)

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "params": self.params,
            "start": self.start,
            "end": self.end,
            "hints": list(self.hints),
        }


@dataclass
class DecodingResult:
    """Describes the outcome of attempting to decode a blob."""

    success: bool
    decoded: Optional[bytes]
    steps: List[str] = field(default_factory=list)
    needs_emulation: bool = False
    error: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class BootstrapperExtractionResult:
    """High-level output of :meth:`BootstrapDecoder.run_full_extraction`."""

    success: bool
    needs_emulation: bool
    bootstrapper_metadata: Dict[str, Any]
    decoded_blobs: Dict[str, bytes]
    decoded_blob_paths: Dict[str, str]
    raw_matches: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    trace_log_path: Optional[str] = None
    metadata_dict: Dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        # Provide compatibility with earlier call-sites that expected a
        # ``metadata_dict`` attribute.
        self.metadata_dict = self.bootstrapper_metadata


class BootstrapDecoder:
    """Implements the bootstrapper decoding pipeline."""

    max_iterations: int

    def __init__(self, ctx: Any, bootstrap_path: str, script_key: str):
        self.ctx = ctx
        self.bootstrap_path = bootstrap_path
        self.script_key = script_key
        self.script_key_bytes = script_key.encode("utf-8") if script_key else b""
        self.debug = bool(getattr(ctx, "debug_bootstrap", False))
        self.max_iterations = 5
        logs_dir = getattr(ctx, "logs_dir", None)
        if logs_dir:
            self.logs_dir = os.path.abspath(str(logs_dir))
        else:
            self.logs_dir = os.path.abspath(os.path.join("out", "logs"))
        os.makedirs(self.logs_dir, exist_ok=True)
        self._bootstrap_src: str = ""
        self._candidate_alphabets: List[str] = []
        self._decoder_candidates: List[DecoderCandidate] = []
        path_obj = Path(bootstrap_path)
        stem = path_obj.stem or path_obj.name
        input_name: Optional[str] = None
        ctx_input = getattr(ctx, "input_path", None)
        if ctx_input:
            try:
                input_name = Path(ctx_input).stem
            except TypeError:
                input_name = Path(str(ctx_input)).stem
        self._input_name = self._sanitise_name(input_name or stem)
        self._trace_lines: List[str] = []
        self._trace_lock = threading.Lock()
        self._primary_blob_written = False
        self._primary_blob_path: Optional[str] = None
        self._warned_about_lua = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run_full_extraction(self) -> BootstrapperExtractionResult:
        """Run the bootstrapper pipeline end-to-end."""

        decoded_blobs: Dict[str, bytes] = {}
        decoded_paths: Dict[str, str] = {}
        raw_matches: Dict[str, Any] = {"blobs": []}
        metadata: Dict[str, Any] = {
            "alphabet": None,
            "alphabet_len": 0,
            "alphabet_preview": "",
            "opcode_map": {},
            "opcode_map_count": 0,
            "constants": {},
            "nested_blobs": [],
            "raw_matches_count": 0,
            "needs_emulation": False,
            "extraction_notes": [],
            "extraction_method": None,
            "extraction_log": None,
            "fallback_attempted": False,
            "fallback_executed": False,
        }
        errors: List[str] = []

        try:
            self._bootstrap_src = Path(self.bootstrap_path).read_text(
                encoding="utf-8", errors="ignore"
            )
        except OSError as exc:
            error = f"Failed to read bootstrapper: {exc}"
            errors.append(error)
            LOG.error("%s", error)
            return self._finalise_result(
                success=False,
                needs_emulation=True,
                metadata=metadata,
                decoded_blobs=decoded_blobs,
                decoded_paths=decoded_paths,
                raw_matches=raw_matches,
                errors=errors,
            )

        self._trace(f"Loaded bootstrapper from {self.bootstrap_path}")

        blobs = self.find_blobs(self._bootstrap_src)
        if not blobs:
            note = "No bootstrap blobs located"
            metadata["extraction_notes"].append(note)
            errors.append(note)
            LOG.warning("[BOOTSTRAP] %s", note)
            return self._finalise_result(
                success=False,
                needs_emulation=True,
                metadata=metadata,
                decoded_blobs=decoded_blobs,
                decoded_paths=decoded_paths,
                raw_matches=raw_matches,
                errors=errors,
            )

        raw_matches["blobs"] = [blob.as_dict() for blob in blobs]
        self._candidate_alphabets = self._discover_candidate_alphabets(self._bootstrap_src)
        self._decoder_candidates = self.locate_decoder_functions(self._bootstrap_src)

        decoded_any = False
        needs_emulation = False

        for index, blob in enumerate(blobs):
            blob_bytes = self.unescape_lua_string(blob.literal)
            label = blob.name or f"blob_{index}"
            self._trace(f"Decoded literal {label!r} to {len(blob_bytes)} bytes")
            if self._printable_ratio(blob_bytes) > 0.9 and (
                label.lower().startswith("alphabet")
                or self._looks_like_lua(blob_bytes)
            ):
                decode_result = DecodingResult(
                    success=True,
                    decoded=blob_bytes,
                    steps=["raw"],
                    notes=["blob already printable"],
                )
            else:
                decode_result = self.python_reimpl_decode(blob_bytes)
            method_used: Optional[str] = None
            if decode_result.success:
                verification = self.sandboxed_lua_decode(blob_bytes)
                if verification.success:
                    decode_result = verification
                    method_used = "lua_fallback"
                    metadata["fallback_attempted"] = True
                    metadata["fallback_executed"] = True
                    metadata["extraction_notes"].extend(verification.notes or [])
                else:
                    method_used = "python_reimpl"
            else:
                metadata["fallback_attempted"] = True
                self._trace("Python reimplementation failed; attempting Lua fallback")
                fallback_result = self.sandboxed_lua_decode(blob_bytes)
                fallback_notes = fallback_result.notes or []
                disabled_markers = {
                    "lua-fallback-disabled",
                    "lua-fallback-unavailable",
                    "lua-fallback-no-candidate",
                }
                executed = fallback_result.success or any(
                    note.startswith("lua-fallback-") and note not in disabled_markers
                    for note in fallback_notes
                )
                if executed:
                    metadata["fallback_executed"] = True
                if fallback_result.success:
                    decode_result = fallback_result
                    method_used = "lua_fallback"
                    if fallback_result.notes:
                        metadata["extraction_notes"].extend(fallback_result.notes)
                else:
                    needs_emulation = needs_emulation or fallback_result.needs_emulation
                    errors.extend(filter(None, [fallback_result.error]))
                    metadata["extraction_notes"].extend(fallback_result.notes)

            decoded_bytes = decode_result.decoded or blob_bytes
            if not decode_result.success:
                needs_emulation = True
                metadata["extraction_notes"].append(
                    f"Failed to decode {label}; preserving raw bytes"
                )
            else:
                decoded_any = True

            if method_used == "lua_fallback":
                metadata["extraction_method"] = "lua_fallback"
            elif method_used == "python_reimpl" and not metadata.get("extraction_method"):
                metadata["extraction_method"] = "python_reimpl"

            decoded_blobs[label] = decoded_bytes
            decoded_paths[label] = self._write_blob_artifact(label, decoded_bytes)

            extracted = self.extract_metadata_from_decoded(decoded_bytes)
            raw_matches.setdefault("alphabets", []).extend(extracted["raw_alphabets"])
            raw_matches.setdefault("opcodes", []).extend(extracted["raw_opcodes"])
            raw_matches.setdefault("constants", []).extend(extracted["raw_constants"])

            if extracted["alphabet"] and not metadata["alphabet"]:
                metadata["alphabet"] = extracted["alphabet"]
                metadata["alphabet_len"] = len(extracted["alphabet"])
                metadata["alphabet_preview"] = self._preview(extracted["alphabet"])
            if extracted["opcode_map"]:
                metadata["opcode_map"].update(extracted["opcode_map"])
                metadata["opcode_map_count"] = len(metadata["opcode_map"])
            if extracted["constants"]:
                metadata["constants"].update(extracted["constants"])
            if extracted["nested_blobs"]:
                metadata["nested_blobs"].extend(extracted["nested_blobs"])

            if decoded_any and len(decoded_blobs) >= self.max_iterations:
                metadata["extraction_notes"].append("decode iteration limit reached")
                break

        metadata["raw_matches_count"] = sum(
            len(v) for v in raw_matches.values() if isinstance(v, Iterable)
        )
        metadata["needs_emulation"] = needs_emulation
        if metadata["alphabet"] and not metadata.get("alphabet_preview"):
            metadata["alphabet_preview"] = self._preview(metadata["alphabet"])
        metadata["fallback_attempted"] = bool(metadata.get("fallback_attempted"))
        metadata["fallback_executed"] = bool(metadata.get("fallback_executed"))

        success = decoded_any and bool(metadata["alphabet"]) and bool(metadata["opcode_map"])
        if success:
            LOG.info(
                "[BOOTSTRAP] Extracted alphabet (len=%d): %s",
                metadata["alphabet_len"],
                self._preview(metadata["alphabet"]),
            )
            preview_items = list(metadata["opcode_map"].items())[:10]
            if preview_items:
                LOG.info("[BOOTSTRAP] Extracted %d opcode mappings. First 10:", metadata["opcode_map_count"])
                for opcode, name in preview_items:
                    LOG.info("  0x%02X -> %s", int(opcode), name)
        else:
            LOG.warning("[BOOTSTRAP] Bootstrap extraction incomplete; needs emulation=%s", needs_emulation)

        if metadata["constants"]:
            sample_consts = list(metadata["constants"].items())[:5]
            sample_desc = ", ".join(f"{k}={v}" for k, v in sample_consts)
            LOG.info("[BOOTSTRAP] Extracted %d constants: %s", len(metadata["constants"]), sample_desc)

        if success and not metadata.get("extraction_method"):
            metadata["extraction_method"] = "python_reimpl"

        return self._finalise_result(
            success=success,
            needs_emulation=needs_emulation,
            metadata=metadata,
            decoded_blobs=decoded_blobs,
            decoded_paths=decoded_paths,
            raw_matches=raw_matches,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # Blob detection
    # ------------------------------------------------------------------
    def find_blobs(self, bootstrap_src: str) -> List[BlobInfo]:
        """Identify candidate blob literals inside ``bootstrap_src``."""

        blobs: List[BlobInfo] = []

        patterns: List[Tuple[re.Pattern[str], str]] = [
            (
                re.compile(
                    r"([A-Za-z0-9_]*superflow_bytecode_ext[A-Za-z0-9_]*?)\s*=\s*\"((?:\\\\\d{1,3}|\\\\x[0-9A-Fa-f]{2}|[^\"])+)\"",
                    re.DOTALL,
                ),
                "superflow",
            ),
            (
                re.compile(
                    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"(?:[^\"\\]|\\\\.){80,}\")",
                    re.DOTALL,
                ),
                "assigned",
            ),
            (
                re.compile(r"(\"[! -~]{200,}\")", re.DOTALL),
                "long_literal",
            ),
        ]

        for pattern, kind in patterns:
            for match in pattern.finditer(bootstrap_src):
                name = match.group(1) if match.lastindex and match.lastindex >= 1 else None
                literal = match.group(match.lastindex or 0)
                start, end = match.span()
                blobs.append(BlobInfo(name=name, literal=literal, start=start, end=end))

        long_bracket_pattern = re.compile(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\[\[(.*?)\]\]",
            re.DOTALL,
        )
        for match in long_bracket_pattern.finditer(bootstrap_src):
            name = match.group(1)
            literal = "[[" + match.group(2) + "]]"
            start, end = match.span()
            blobs.append(BlobInfo(name=name, literal=literal, start=start, end=end))

        # Concatenated literals: "..." .. "..." .. "..."
        concat_pattern = re.compile(
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\"(?:[^\"\\]|\\\\.)*\"\s*\.\.\s*)+\"(?:[^\"\\]|\\\\.)*\")",
            re.DOTALL,
        )
        for match in concat_pattern.finditer(bootstrap_src):
            name = match.group(1)
            full_literal = match.group(2)
            parts = re.findall(r"\"(?:[^\"\\]|\\\\.)*\"", full_literal)
            if not parts:
                continue
            literal = "".join(part[1:-1] for part in parts)
            start, end = match.span()
            blobs.append(BlobInfo(name=name, literal=literal, start=start, end=end, parts=parts))

        # Deduplicate by start offset
        unique: Dict[int, BlobInfo] = {}
        for blob in sorted(blobs, key=lambda b: b.start):
            unique.setdefault(blob.start, blob)
        return list(unique.values())

    # ------------------------------------------------------------------
    def unescape_lua_string(self, literal: str) -> bytes:
        """Convert a Lua string literal into raw bytes."""

        if literal.startswith("[[") and literal.endswith("]]"):
            return literal[2:-2].encode("utf-8")
        if literal.startswith(("\"", "'")) and literal.endswith(("\"", "'")):
            literal = literal[1:-1]
        out = bytearray()
        it = iter(range(len(literal)))
        i = 0
        while i < len(literal):
            ch = literal[i]
            if ch != "\\":
                out.append(ord(ch))
                i += 1
                continue
            i += 1
            if i >= len(literal):
                out.append(ord("\\"))
                break
            esc = literal[i]
            if esc in "\\\"'":
                out.append(ord(esc))
                i += 1
            elif esc in "ntra\"":
                mapping = {"n": 0x0A, "t": 0x09, "r": 0x0D, "a": 0x07, "\"": 0x22}
                out.append(mapping.get(esc, ord(esc)))
                i += 1
            elif esc == "x" and i + 2 < len(literal):
                hex_digits = literal[i + 1 : i + 3]
                try:
                    out.append(int(hex_digits, 16))
                    i += 3
                except ValueError:
                    out.append(ord("x"))
                    i += 1
            elif esc.isdigit():
                digits = esc
                j = 1
                while i + j < len(literal) and j < 3 and literal[i + j].isdigit():
                    digits += literal[i + j]
                    j += 1
                out.append(int(digits, 10) & 0xFF)
                i += j
            else:
                out.append(ord(esc))
                i += 1
        return bytes(out)

    # ------------------------------------------------------------------
    def locate_decoder_functions(self, bootstrap_src: str) -> List[DecoderCandidate]:
        """Return candidate decoder functions from the bootstrapper."""

        candidates: List[DecoderCandidate] = []
        func_pattern = re.compile(
            r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)",
        )
        token_pattern = re.compile(
            r"\b(function|if|for|while|do|repeat|end|until)\b"
        )
        for match in func_pattern.finditer(bootstrap_src):
            name = match.group("name")
            params = [p.strip() for p in match.group("params").split(",") if p.strip()]
            start = match.start()
            search_pos = match.end()
            depth = 1
            body_end = len(bootstrap_src)
            while depth and search_pos < len(bootstrap_src):
                token_match = token_pattern.search(bootstrap_src, search_pos)
                if not token_match:
                    break
                token = token_match.group(0)
                search_pos = token_match.end()
                if token in {"function", "if", "for", "while", "do", "repeat"}:
                    depth += 1
                elif token == "end":
                    depth -= 1
                    if depth == 0:
                        body_end = token_match.start()
                        break
                elif token == "until" and depth > 0:
                    depth -= 1
            body = bootstrap_src[match.end():body_end]
            source = bootstrap_src[start:search_pos]
            hints = []
            if "string.byte" in body or "string.char" in body:
                hints.append("string-byte-char")
            if re.search(r"band|bor|bxor|\^", body):
                hints.append("bitwise")
            if "alphabet" in body:
                hints.append("alphabet")
            if "script_key" in body or "key" in body:
                hints.append("key")
            candidate = DecoderCandidate(
                name=name,
                params=params,
                body=body,
                source=source,
                start=start,
                end=search_pos,
                hints=hints,
            )
            candidates.append(candidate)
        return candidates

    # ------------------------------------------------------------------
    def python_reimpl_decode(self, blob_bytes: bytes) -> DecodingResult:
        """Attempt to decode ``blob_bytes`` using a Python reimplementation."""

        alphabets = list(self._candidate_alphabets) or [None]
        if self.script_key_bytes and None not in alphabets:
            alphabets.append(None)  # allow raw handling with only key xor

        pipelines: List[List[str]] = [
            ["index_map", "key_xor", "index_mix"],
            ["index_map", "index_mix", "key_xor"],
            ["key_xor", "index_mix", "index_map"],
            ["key_xor", "index_map"],
            ["index_map"],
        ]

        best_candidate: Optional[DecodingResult] = None

        for alphabet in alphabets:
            for steps in pipelines:
                decoded = self._apply_pipeline(blob_bytes, steps, alphabet)
                note = f"pipeline={'>' .join(steps)} alphabet={'len=' + str(len(alphabet)) if alphabet else 'raw'}"
                if decoded is None:
                    self._trace(f"Pipeline failed ({note})")
                    continue
                if self._looks_like_lua(decoded):
                    result = DecodingResult(success=True, decoded=decoded, steps=steps)
                    result.notes.append(note)
                    self._trace(f"Pipeline succeeded ({note})")
                    return result
                # Keep the most printable candidate for diagnostics
                score = self._printable_ratio(decoded)
                if not best_candidate or score > self._printable_ratio(best_candidate.decoded or b""):
                    best_candidate = DecodingResult(
                        success=False,
                        decoded=decoded,
                        steps=steps,
                        notes=[note],
                    )
        if best_candidate:
            best_candidate.notes.append("no pipeline yielded Lua-like output")
            return best_candidate
        return DecodingResult(success=False, decoded=None, notes=["python reimpl failed"])

    # ------------------------------------------------------------------
    def sandboxed_lua_decode(self, blob_bytes: bytes) -> DecodingResult:
        """Fallback to a sandboxed Lua execution using :mod:`lupa`."""

        if LuaRuntime is None:
            return DecodingResult(
                success=False,
                decoded=None,
                needs_emulation=True,
                error="lupa not installed",
                notes=["lua-fallback-unavailable"],
            )

        allow_flag = bool(getattr(self.ctx, "allow_lua_run", False))
        legacy_flag = bool(getattr(self.ctx, "allow_lua_fallback", False))
        force_flag = bool(getattr(self.ctx, "force", False))
        debug_flag = bool(getattr(self.ctx, "debug_bootstrap", False))
        allow_lua = allow_flag or legacy_flag or (force_flag and debug_flag)
        if not allow_lua:
            return DecodingResult(
                success=False,
                decoded=None,
                needs_emulation=True,
                error="Lua fallback disabled (use --allow-lua-run or --force with --debug-bootstrap)",
                notes=[
                    "lua-fallback-disabled",
                    "set --allow-lua-run or (--force and --debug-bootstrap) to permit sandbox",
                ],
            )

        if not self._decoder_candidates:
            return DecodingResult(
                success=False,
                decoded=None,
                needs_emulation=True,
                error="No decoder functions located",
                notes=["lua-fallback-no-candidate"],
            )

        if not self._warned_about_lua:
            LOG.warning(
                "[BOOTSTRAP] SECURITY WARNING: running bootstrapper decode logic inside a sandboxed Lua runtime."
            )
            LOG.warning(
                "[BOOTSTRAP] Only proceed if you trust the bootstrapper. Provide --allow-lua-run or --force with --debug-bootstrap to acknowledge."
            )
            self._warned_about_lua = True

        runtime = LuaRuntime(unpack_returned_tuples=True, register_eval=True)
        base_env = self._build_sandbox_env(runtime)
        runtime.execute(
            "function __bootstrap_loader(src, env)\n"
            "  local chunk, err = load(src, 'bootstrap', 't', env)\n"
            "  if not chunk then return nil, err end\n"
            "  local ok, res = pcall(chunk)\n"
            "  if not ok then return nil, res end\n"
            "  return env\n"
            "end"
        )
        loader = runtime.globals()["__bootstrap_loader"]

        notes: List[str] = []
        for candidate in self._decoder_candidates:
            try:
                env = runtime.table_from(base_env)
                env["_G"] = env
                loader_result = loader(candidate.source, env)
                if isinstance(loader_result, tuple):
                    compiled_env, err = loader_result
                else:
                    compiled_env, err = loader_result, None
                if not compiled_env:
                    reason = f"lua-fallback-load-error {candidate.name}: {err}"
                    notes.append(reason)
                    continue
                if candidate.name:
                    try:
                        decode_func = compiled_env[candidate.name]
                    except (KeyError, TypeError):
                        decode_func = None
                else:
                    decode_func = None
                if decode_func is None:
                    notes.append(f"lua-fallback-missing-func {candidate.name}")
                    continue
                self._trace(f"Executing Lua decoder candidate {candidate.name!r}")
                start_time = time.time()
                result_holder: Dict[str, Any] = {}

                def _invoke():
                    try:
                        key_arg = self.script_key or ""
                        result_holder["value"] = decode_func(
                            blob_bytes.decode("latin-1"), key_arg
                        )
                    except LuaError as exc:  # pragma: no cover - depends on runtime behaviour
                        result_holder["error"] = exc

                thread = threading.Thread(target=_invoke, daemon=True)
                thread.start()
                thread.join(timeout=5.0)
                if thread.is_alive():
                    notes.append("lua-fallback-timeout")
                    return DecodingResult(
                        success=False,
                        decoded=None,
                        needs_emulation=True,
                        error="Lua fallback timed out",
                        notes=notes,
                    )
                if "error" in result_holder:
                    raise result_holder["error"]
                value = result_holder.get("value")
                if value is None:
                    continue
                if isinstance(value, (bytes, bytearray)):
                    decoded = bytes(value)
                else:
                    decoded = str(value).encode("latin-1")
                elapsed = time.time() - start_time
                notes.append(f"lua-fallback-success {candidate.name} {elapsed:.2f}s")
                return DecodingResult(success=True, decoded=decoded, steps=["lua-fallback"], notes=notes)
            except LuaError as exc:  # pragma: no cover - depends on runtime behaviour
                notes.append(f"lua-fallback-error {candidate.name}: {exc}")
                continue
        return DecodingResult(
            success=False,
            decoded=None,
            needs_emulation=True,
            error="Lua fallback could not decode blob",
            notes=notes or ["lua-fallback-no-success"],
        )

    def _build_sandbox_env(self, runtime: "LuaRuntime") -> Dict[str, Any]:
        """Return a minimal environment table for sandboxed Lua execution."""

        safe_env: Dict[str, Any] = {}

        def _eval(expr: str) -> Any:
            try:
                return runtime.eval(expr)
            except LuaError:
                return None

        string_mod = _eval(
            "{byte=string.byte, char=string.char, find=string.find, format=string.format,"
            " gsub=string.gsub, len=string.len, lower=string.lower, upper=string.upper,"
            " sub=string.sub, rep=string.rep}"
        )
        if string_mod is not None:
            safe_env["string"] = string_mod

        table_mod = _eval(
            "{insert=table.insert, remove=table.remove, unpack=table.unpack, pack=table.pack, concat=table.concat}"
        )
        if table_mod is not None:
            safe_env["table"] = table_mod

        math_mod = _eval(
            "{abs=math.abs, ceil=math.ceil, floor=math.floor, max=math.max, min=math.min,"
            " sqrt=math.sqrt, modf=math.modf}"
        )
        if math_mod is not None:
            safe_env["math"] = math_mod

        bit32_mod = _eval(
            "bit32 and {band=bit32.band, bor=bit32.bor, bxor=bit32.bxor,"
            " bnot=bit32.bnot, lshift=bit32.lshift, rshift=bit32.rshift, arshift=bit32.arshift}"
        )
        if bit32_mod is not None:
            safe_env["bit32"] = bit32_mod

        bit_mod = _eval(
            "bit and {band=bit.band, bor=bit.bor, bxor=bit.bxor, bnot=bit.bnot,"
            " lshift=bit.lshift, rshift=bit.rshift}"
        )
        if bit_mod is not None:
            safe_env["bit"] = bit_mod

        for name in (
            "assert",
            "error",
            "next",
            "pairs",
            "ipairs",
            "pcall",
            "xpcall",
            "select",
            "tonumber",
            "tostring",
            "type",
        ):
            value = _eval(f"return {name}")
            if value is not None:
                safe_env[name] = value

        safe_env["print"] = lambda *_args, **_kwargs: None

        return safe_env

    # ------------------------------------------------------------------
    def extract_metadata_from_decoded(self, decoded_bytes: bytes) -> Dict[str, Any]:
        """Mine metadata from ``decoded_bytes``."""

        text = self._safe_text(decoded_bytes)
        alphabet = None
        opcode_map: Dict[int, str] = {}
        constants: Dict[str, int] = {}
        nested: List[Dict[str, Any]] = []
        raw_alphabets: List[str] = []
        raw_opcodes: List[str] = []
        raw_constants: List[str] = []

        literal_match = re.search(r"alphabet\s*=\s*\"([^\"]{80,120})\"", text)
        if literal_match:
            candidate = literal_match.group(1)
            raw_alphabets.append(candidate)
        alphabet_pattern = re.compile(r"[!\x23-~]{80,120}")
        for match in alphabet_pattern.finditer(text):
            candidate = match.group(0)
            if self._looks_like_alphabet(candidate):
                raw_alphabets.append(candidate)
        if raw_alphabets:
            alphabet = max(raw_alphabets, key=len)

        opcode_patterns = [
            re.compile(r"\[\s*(0x[0-9A-Fa-f]+)\s*\]\s*=\s*function\s*\([^)]*\)\s*--\s*([A-Za-z0-9_]+)"),
            re.compile(r"case\s+(0x[0-9A-Fa-f]+)\s*:\s*--\s*([A-Za-z0-9_]+)"),
            re.compile(r"opcodes\[\"([A-Za-z0-9_]+)\"\]\s*=\s*(0x[0-9A-Fa-f]+|\d+)")
        ]
        string_opcode_pattern = re.compile(
            r"\[\s*(0x[0-9A-Fa-f]+)\s*\]\s*=\s*\"([A-Za-z0-9_]+)\""
        )
        for pattern in opcode_patterns:
            for match in pattern.finditer(text):
                raw_opcodes.append(match.group(0))
                if pattern is opcode_patterns[2]:
                    name = match.group(1)
                    value = int(match.group(2), 0)
                else:
                    value = int(match.group(1), 0)
                    name = match.group(2)
                opcode_map[value] = name.upper()
        for match in string_opcode_pattern.finditer(text):
            raw_opcodes.append(match.group(0))
            value = int(match.group(1), 0)
            opcode_map[value] = match.group(2).upper()

        const_pattern = re.compile(r"([A-Z][A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)")
        for match in const_pattern.finditer(text):
            raw_constants.append(match.group(0))
            try:
                constants[match.group(1)] = int(match.group(2), 0)
            except ValueError:
                continue

        if text:
            nested_blobs = self.find_blobs(text)
            for blob in nested_blobs[: self.max_iterations]:
                nested.append(blob.as_dict())

        return {
            "alphabet": alphabet,
            "opcode_map": opcode_map,
            "constants": constants,
            "nested_blobs": nested,
            "raw_alphabets": raw_alphabets,
            "raw_opcodes": raw_opcodes,
            "raw_constants": raw_constants,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _apply_pipeline(
        self, blob_bytes: bytes, steps: Sequence[str], alphabet: Optional[str]
    ) -> Optional[bytes]:
        data = blob_bytes
        for step in steps:
            if step == "index_map":
                data = self._alphabet_map(data, alphabet)
            elif step == "key_xor":
                data = self._xor_with_key(data)
            elif step == "index_mix":
                data = self._xor_with_index(data)
            elif step == "rle":
                data = self._simple_rle_decode(data)
            else:
                return None
            if data is None:
                return None
        return data

    def _alphabet_map(self, blob_bytes: bytes, alphabet: Optional[str]) -> Optional[bytes]:
        if not alphabet:
            return bytes(blob_bytes)
        decode_map = {ch: idx for idx, ch in enumerate(alphabet)}
        out = bytearray()
        for i, value in enumerate(blob_bytes):
            ch = chr(value)
            if ch in decode_map:
                out.append(decode_map[ch] & 0xFF)
            else:
                out.append(value)
        return bytes(out)

    def _xor_with_key(self, data: bytes) -> bytes:
        if not self.script_key_bytes:
            return bytes(data)
        key = self.script_key_bytes
        out = bytearray()
        key_len = len(key)
        for i, value in enumerate(data):
            out.append(value ^ key[i % key_len])
        return bytes(out)

    @staticmethod
    def _xor_with_index(data: bytes) -> bytes:
        out = bytearray()
        for i, value in enumerate(data):
            out.append(value ^ (i & 0xFF))
        return bytes(out)

    @staticmethod
    def _simple_rle_decode(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        length = len(data)
        while i < length:
            count = data[i]
            i += 1
            if i >= length:
                break
            if count & 0x80:
                repeat = (count & 0x7F) + 3
                value = data[i]
                i += 1
                out.extend([value] * repeat)
            else:
                literal_len = (count & 0x7F) + 1
                out.extend(data[i : i + literal_len])
                i += literal_len
        return bytes(out)

    def _discover_candidate_alphabets(self, bootstrap_src: str) -> List[str]:
        alphabets: List[str] = []
        pattern = re.compile(r"[! -~]{80,120}")
        for match in pattern.finditer(bootstrap_src):
            candidate = match.group(0)
            if self._looks_like_alphabet(candidate):
                alphabets.append(candidate)
        return alphabets

    def _looks_like_alphabet(self, candidate: str) -> bool:
        unique = len(set(candidate))
        return len(candidate) >= 80 and unique / len(candidate) > 0.5

    def _looks_like_lua(self, data: bytes) -> bool:
        text = self._safe_text(data)
        if not text:
            return False
        printable_ratio = self._printable_ratio(data)
        if printable_ratio < 0.6:
            return False
        keywords = ["function", "local", "alphabet", "opcode", "return", "end"]
        return any(keyword in text for keyword in keywords)

    @staticmethod
    def _printable_ratio(data: Optional[bytes]) -> float:
        if not data:
            return 0.0
        printable = sum(1 for b in data if 32 <= b <= 126)
        return printable / max(1, len(data))

    @staticmethod
    def _safe_text(data: bytes) -> str:
        if not data:
            return ""
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="ignore")

    def _write_blob_artifact(self, label: str, data: bytes) -> str:
        if not self._primary_blob_written:
            base_filename = f"bootstrap_decoded_{self._input_name}.bin"
            base_path = os.path.join(self.logs_dir, base_filename)
            with open(base_path, "wb") as fh:
                fh.write(data)
            self._primary_blob_written = True
            self._primary_blob_path = base_path
        safe_label = re.sub(r"[^A-Za-z0-9._-]", "_", label) if label else "blob"
        if len(safe_label) > 48:
            safe_label = safe_label[:48]
        filename = f"bootstrap_decoded_{self._input_name}_{safe_label}.bin"
        path = os.path.join(self.logs_dir, filename)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def _write_metadata_artifact(
        self,
        metadata: Dict[str, Any],
        raw_matches: Dict[str, Any],
        *,
        path: Optional[str] = None,
    ) -> str:
        payload = dict(metadata)
        payload["raw_matches"] = raw_matches if self.debug else None
        if path is None:
            path = os.path.join(
                self.logs_dir, f"bootstrapper_metadata_{self._input_name}.json"
            )
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        return path

    def _write_trace(self) -> str:
        path = os.path.join(
            self.logs_dir, f"bootstrap_decode_trace_{self._input_name}.log"
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(self._trace_lines))
        return path

    def _trace(self, message: str) -> None:
        with self._trace_lock:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            line = f"[{timestamp}] {message}"
            self._trace_lines.append(line)
            if self.debug:
                LOG.debug("[BOOTSTRAP] %s", message)

    def _finalise_result(
        self,
        *,
        success: bool,
        needs_emulation: bool,
        metadata: Dict[str, Any],
        decoded_blobs: Dict[str, bytes],
        decoded_paths: Dict[str, str],
        raw_matches: Dict[str, Any],
        errors: List[str],
    ) -> BootstrapperExtractionResult:
        if self._primary_blob_path:
            decoded_paths.setdefault("primary", self._primary_blob_path)
        metadata["decoded_blob_paths"] = decoded_paths

        if self.debug:
            metadata["raw_matches"] = raw_matches

        artifact_paths: Dict[str, str] = dict(metadata.get("artifact_paths") or {})
        if self._primary_blob_path:
            artifact_paths.setdefault("decoded_blob_path", self._primary_blob_path)

        trace_path = self._write_trace()
        artifact_paths.setdefault("trace_log_path", trace_path)
        metadata["extraction_log"] = trace_path
        debug_path: Optional[str] = None
        if self.debug:
            debug_logs_dir = os.path.abspath("logs")
            os.makedirs(debug_logs_dir, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            debug_path = os.path.join(
                debug_logs_dir, f"bootstrap_extract_debug_{timestamp}.log"
            )
            metadata_preview = {
                "alphabet_len": metadata.get("alphabet_len", 0),
                "opcode_map_count": metadata.get("opcode_map_count", 0),
                "constants_count": len(metadata.get("constants", {})),
            }
            debug_payload = {
                "trace": list(self._trace_lines),
                "raw_matches": raw_matches,
                "metadata_preview": metadata_preview,
            }
            with open(debug_path, "w", encoding="utf-8") as fh:
                json.dump(debug_payload, fh, indent=2, ensure_ascii=False)
            metadata.setdefault("extraction_notes", []).append(
                f"debug_log={debug_path}"
            )
            artifact_paths["debug_log_path"] = debug_path

        metadata_path = os.path.join(
            self.logs_dir, f"bootstrapper_metadata_{self._input_name}.json"
        )
        artifact_paths["metadata_path"] = metadata_path
        metadata["artifact_paths"] = artifact_paths

        self._write_metadata_artifact(metadata, raw_matches, path=metadata_path)

        result = BootstrapperExtractionResult(
            success=success,
            needs_emulation=needs_emulation,
            bootstrapper_metadata=metadata,
            decoded_blobs=decoded_blobs,
            decoded_blob_paths=decoded_paths,
            raw_matches=raw_matches if self.debug else {},
            errors=errors,
            trace_log_path=trace_path,
        )
        try:
            if self.ctx is not None:
                setattr(self.ctx, "bootstrapper_metadata", metadata)
        except Exception:  # pragma: no cover - defensive only
            LOG.debug("Failed to set ctx.bootstrapper_metadata", exc_info=True)
        return result

    @staticmethod
    def _sanitise_name(name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        return safe or "bootstrap"

    @staticmethod
    def _preview(text: Optional[str]) -> str:
        if not text:
            return ""
        preview_len = 32
        preview = text[:preview_len]
        if len(text) > preview_len:
            preview += "..."
        return preview

