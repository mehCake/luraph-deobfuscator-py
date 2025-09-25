"""Utilities for recovering binary payloads and metadata from Luraph
bootstrappers.

The :class:`BootstrapDecoder` class exposes helpers to locate encoded blobs
inside bootstrapper scripts, re-implement the Lua decoding routine using a
Python analogue, decode the extracted payloads, and mine the decoded bytes for
useful metadata such as alphabets, opcode dispatch tables, and VM constants.

The implementation intentionally favours defensive heuristics over aggressive
execution of unknown code.  Whenever a decoder routine cannot be confidently
translated into Python the logic records the failure and marks the blob as
requiring emulation rather than executing arbitrary Lua.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


LOG = logging.getLogger(__name__)


@dataclass
class BlobInfo:
    """Represents an encoded blob literal detected inside a bootstrapper."""

    literal: str
    start: int
    end: int
    kind: str
    name: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "literal": self.literal[:80] + ("…" if len(self.literal) > 80 else ""),
            "start": self.start,
            "end": self.end,
            "kind": self.kind,
            "name": self.name,
        }


@dataclass
class DecoderFunctionInfo:
    """Information about a candidate Lua function that decodes payloads."""

    name: Optional[str]
    params: List[str]
    body: str
    start: int
    end: int
    hints: List[str] = field(default_factory=list)

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "params": self.params,
            "start": self.start,
            "end": self.end,
            "hints": self.hints,
        }


@dataclass
class DecoderImplementation:
    """Result produced by :meth:`BootstrapDecoder.reimplement_decoder`."""

    func: Optional[Callable[[bytes, bytes], bytes]]
    needs_emulation: bool
    notes: List[str] = field(default_factory=list)


@dataclass
class BootstrapperExtractionResult:
    """High-level output returned by :meth:`BootstrapDecoder.run_extraction`."""

    decoded_blobs: Dict[str, bytes]
    bootstrapper_metadata: Dict[str, Any]
    raw_matches: Dict[str, Any]
    success: bool
    errors: List[str] = field(default_factory=list)
    needs_emulation: bool = False


class BootstrapDecoder:
    """Searches bootstrapper scripts for encoded payloads and decodes them."""

    MAX_DECODE_ITERATIONS = 4

    def __init__(self, ctx: Optional[Any] = None):
        self.ctx = ctx

    # ------------------------------------------------------------------
    # Blob discovery helpers
    # ------------------------------------------------------------------
    def find_blobs(self, bootstrap_src: str) -> List[BlobInfo]:
        """Return a list of :class:`BlobInfo` records describing encoded blobs.

        The detection logic combines several heuristics to locate large string
        literals, base85 payloads, and byte-array representations that commonly
        show up in Luraph bootstrappers.  Each match records the literal form
        along with positional metadata so downstream passes can reference the
        original script context.
        """


        patterns: List[Tuple[re.Pattern[str], str]] = [
            (
                re.compile(
                    r"""(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>[\"'])"""
                    r"""(?P<payload>s8W-[^\"']{50,}|[! -~]{200,})(?P=quote)""",
                    re.DOTALL,
                ),
                "quoted",
            ),
            (
                re.compile(
                    r"""(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>[\"'])"""
                    r"""(?P<payload>[! -~]{80,})(?P=quote)""",
                    re.DOTALL,
                ),
                "quoted",
            ),
            (
                re.compile(
                    r"""(?P<quote>[\"'])(?P<payload>[! -~]{240,})(?P=quote)""",
                    re.DOTALL,
                ),
                "quoted",
            ),
            (
                re.compile(
                    r"""(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{(?P<payload>[0-9,\s]+)\}""",
                    re.DOTALL,
                ),
                "table",
            ),
            (
                re.compile(
                    r"""superflow_bytecode_ext\w*\s*=\s*(?P<quote>[\"'])(?P<payload>.+?)(?P=quote)""",
                    re.DOTALL,
                ),
                "quoted",
            ),
        ]

        blobs: List[BlobInfo] = []
        seen_ranges: List[Tuple[int, int]] = []

        for regex, kind in patterns:
            for match in regex.finditer(bootstrap_src):
                payload = match.group("payload")
                start, end = match.span()
                name = match.groupdict().get("name")
                if self._range_overlaps(seen_ranges, start, end):
                    continue
                if len(payload) < 50:
                    # Too small to be interesting.
                    continue
                seen_ranges.append((start, end))
                blob = BlobInfo(literal=match.group(0), start=start, end=end, kind=kind, name=name)
                blobs.append(blob)
                LOG.debug("[BOOTSTRAP] Found blob %s @%d:%d", name or "<anon>", start, end)

        blobs.sort(key=lambda b: b.start)
        LOG.info("[BOOTSTRAP] Detected %d potential encoded blob(s).", len(blobs))
        return blobs

    # ------------------------------------------------------------------
    def unescape_lua_string(self, lit: str) -> bytes:
        """Convert a Lua string literal to raw bytes.

        Supports hexadecimal escapes (``\xAB``), decimal escapes (``\123``),
        and the common escaped characters (``\\``, ``\"``, ``\'``).  Unknown
        escapes are preserved verbatim and logged for transparency.
        """

        if not lit:
            return b""

        quote = None
        if lit[0] in {'"', "'"} and lit[-1] == lit[0]:
            quote = lit[0]
            lit = lit[1:-1]

        buf = bytearray()
        i = 0
        while i < len(lit):
            ch = lit[i]
            if ch != "\\":
                buf.append(ord(ch))
                i += 1
                continue

            i += 1
            if i >= len(lit):
                buf.append(ord("\\"))
                break

            esc = lit[i]
            i += 1
            if esc in {"\\", '"', "'"}:
                buf.append(ord(esc))
            elif esc in "abfnrtv":
                mapping = {
                    "a": 7,
                    "b": 8,
                    "f": 12,
                    "n": 10,
                    "r": 13,
                    "t": 9,
                    "v": 11,
                }
                buf.append(mapping[esc])
            elif esc == "x" and i + 1 <= len(lit):
                hex_digits = lit[i : i + 2]
                if re.fullmatch(r'[0-9A-Fa-f]{2}', hex_digits or ''):
                    buf.append(int(hex_digits, 16))
                    i += 2
                else:
                    LOG.warning('[BOOTSTRAP] Invalid hex escape \\x%s', hex_digits)
            elif esc.isdigit():
                digits = esc
                while i < len(lit) and len(digits) < 3 and lit[i].isdigit():
                    digits += lit[i]
                    i += 1
                buf.append(int(digits, 10) & 0xFF)
            else:
                LOG.debug("[BOOTSTRAP] Preserving unknown escape \%s", esc)
                buf.append(ord(esc))

        if quote:
            LOG.debug("[BOOTSTRAP] Unescaped Lua string literal using %s quotes.", quote)
        return bytes(buf)

    # ------------------------------------------------------------------
    def locate_decoder_functions(self, bootstrap_src: str) -> List[DecoderFunctionInfo]:
        """Heuristically identify Lua functions that perform blob decoding."""

        func_regex = re.compile(
            r"function\s+(?P<name>[A-Za-z0-9_.:]*)\s*\((?P<params>[^)]*)\)(?P<body>.*?)(?<=\n)end",
            re.DOTALL,
        )

        candidates: List[DecoderFunctionInfo] = []
        for match in func_regex.finditer(bootstrap_src):
            body = match.group("body")
            hints: List[str] = []
            if re.search(r"string\.char", body):
                hints.append("string.char")
            if re.search(r"for\s+[%w_,]+\s*=\s*1\s*,\s*#", body):
                hints.append("for-range")
            if re.search(r"alphabet", body, re.IGNORECASE):
                hints.append("alphabet")
            if re.search(r"bit32?\.bxor|\^", body):
                hints.append("xor")
            if re.search(r"script_key|key", body):
                hints.append("key")
            if re.search(r"unpack|table\.unpack", body):
                hints.append("unpack")

            if not hints:
                continue

            params = [p.strip() for p in match.group("params").split(",") if p.strip()]
            candidates.append(
                DecoderFunctionInfo(
                    name=match.group("name") or None,
                    params=params,
                    body=body,
                    start=match.start(),
                    end=match.end(),
                    hints=hints,
                )
            )

        LOG.info("[BOOTSTRAP] Located %d candidate decoder function(s).", len(candidates))
        return candidates

    # ------------------------------------------------------------------
    def reimplement_decoder(self, func_src: str) -> DecoderImplementation:
        """Attempt to translate a Lua decoder into a Python callable."""

        notes: List[str] = []
        alphabet_match = re.search(r'"([ !-~]{80,120})"', func_src)
        alphabet: Optional[str] = None
        if alphabet_match:
            alphabet = alphabet_match.group(1)
            notes.append("alphabet-mapping")

        xor_with_index = bool(re.search(r"i\s*&\s*0x?FF|i\s*%\s*256", func_src))
        if xor_with_index:
            notes.append("xor-index")

        key_usage = bool(re.search(r"script_key|key", func_src))
        if key_usage:
            notes.append("xor-key")

        uses_string_byte = bool(re.search(r"string\.byte", func_src))
        uses_char_concat = bool(re.search(r"table\.concat|string\.char", func_src))

        if not (alphabet or uses_string_byte or xor_with_index or key_usage):
            notes.append("insufficient-patterns")
            LOG.warning("[BOOTSTRAP] Unable to infer decoder behaviour from source.")
            return DecoderImplementation(func=None, needs_emulation=True, notes=notes)

        def _decode(blob_bytes: bytes, key_bytes: bytes) -> bytes:
            src_text = blob_bytes.decode("latin-1")
            output: List[int] = []

            if alphabet:
                alphabet_map = {ch: idx for idx, ch in enumerate(alphabet)}
                quartet: List[int] = []
                base = len(alphabet)
                for ch in src_text:
                    if ch not in alphabet_map:
                        continue
                    quartet.append(alphabet_map[ch])
                    if len(quartet) == 5:
                        value = 0
                        for idx in quartet:
                            value = value * base + idx
                        for shift in (3, 2, 1, 0):
                            output.append((value >> (shift * 8)) & 0xFF)
                        quartet.clear()
                if quartet:
                    notes.append("partial-base85")
            else:
                output.extend(blob_bytes)

            if not output:
                output = list(blob_bytes)

            for i, value in enumerate(output):
                v = value
                if xor_with_index:
                    v ^= i & 0xFF
                if key_usage and key_bytes:
                    v ^= key_bytes[i % len(key_bytes)]
                output[i] = v & 0xFF

            if uses_char_concat and not alphabet:
                # The Lua code likely rebuilt bytes via string.char.  Preserve raw bytes.
                pass

            return bytes(output)

        LOG.info("[BOOTSTRAP] Inferred decoder implementation with notes: %s", ", ".join(notes))
        return DecoderImplementation(func=_decode, needs_emulation=False, notes=notes)

    # ------------------------------------------------------------------
    def decode_blob_bytes(
        self, blob_bytes: bytes, key_bytes: bytes, decoder: DecoderImplementation
    ) -> Tuple[bytes, Optional[str]]:
        """Decode ``blob_bytes`` using the supplied decoder implementation."""

        if decoder.func is None:
            LOG.warning("[BOOTSTRAP] Decoder requires emulation; returning raw bytes.")
            return blob_bytes, "needs-emulation"

        try:
            decoded = decoder.func(blob_bytes, key_bytes)
            return decoded, None
        except Exception as exc:  # pragma: no cover - defensive
            LOG.exception("[BOOTSTRAP] Decoder invocation failed: %s", exc)
            return blob_bytes, str(exc)

    # ------------------------------------------------------------------
    def extract_metadata_from_decoded(self, decoded_bytes: bytes) -> Dict[str, Any]:
        """Mine the decoded bytes for alphabets, opcode maps, and constants."""

        metadata: Dict[str, Any] = {
            "alphabet": None,
            "opcode_map": {},
            "constants": {},
            "nested_blobs": [],
        }

        try:
            text = decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            text = decoded_bytes.decode("latin-1", errors="ignore")

        alphabet_match = re.search(r"([! -~]{80,120})", text)
        if alphabet_match:
            metadata["alphabet"] = alphabet_match.group(1)

        opcode_regex = re.compile(
            r"\[\s*(0x[0-9A-Fa-f]+|\d+)\s*\]\s*=\s*(?:function[^-]*--\s*)?([A-Za-z0-9_]+)",
            re.DOTALL,
        )
        for code, name in opcode_regex.findall(text):
            opcode = int(code, 0)
            metadata["opcode_map"][opcode] = name.upper()

        constant_regex = re.compile(
            r"([A-Z][A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)", re.MULTILINE
        )
        for key, value in constant_regex.findall(text):
            metadata["constants"][key] = int(value, 0)

        nested_candidates = []
        for match in re.finditer(r"(?P<quote>['\"])[! -~]{120,}(?P=quote)", text):
            nested_candidates.append(
                {
                    "start": match.start(),
                    "end": match.end(),
                    "preview": match.group(0)[:60],
                }
            )
        metadata["nested_blobs"] = nested_candidates

        # Optionally parse JSON or Lua-table-like metadata
        json_candidates = re.findall(r"\{\s*\"[A-Za-z0-9_]+\"\s*:\s*", text)
        if json_candidates:
            try:
                json_obj = json.loads(text)
                metadata.setdefault("parsed_structures", []).append(json_obj)
            except Exception:  # pragma: no cover - heuristic
                pass

        return metadata

    # ------------------------------------------------------------------
    def run_extraction(
        self, bootstrap_path: str, script_key_bytes: bytes
    ) -> BootstrapperExtractionResult:
        """Entry-point orchestrating blob discovery, decoding, and metadata mining."""

        LOG.info("[BOOTSTRAP] Starting extraction for %s", bootstrap_path)
        try:
            with open(bootstrap_path, "r", encoding="utf-8", errors="ignore") as fh:
                src = fh.read()
        except OSError as exc:  # pragma: no cover - defensive
            LOG.error("[BOOTSTRAP] Failed to read bootstrapper: %s", exc)
            return BootstrapperExtractionResult(
                decoded_blobs={},
                bootstrapper_metadata={},
                raw_matches={},
                success=False,
                errors=[str(exc)],
            )

        blobs = self.find_blobs(src)
        decoder_functions = self.locate_decoder_functions(src)

        raw_matches = {
            "blobs": [blob.as_dict() for blob in blobs],
            "decoder_functions": [fn.describe() for fn in decoder_functions],
        }

        decoded_blobs: Dict[str, bytes] = {}
        aggregate_metadata: Dict[str, Any] = {
            "alphabet": None,
            "opcode_map": {},
            "constants": {},
            "blobs": [],
        }
        errors: List[str] = []
        needs_emulation = False

        decoder_impl: Optional[DecoderImplementation] = None
        if decoder_functions:
            decoder_impl = self.reimplement_decoder(decoder_functions[0].body)
            needs_emulation = needs_emulation or decoder_impl.needs_emulation

        for idx, blob in enumerate(blobs):
            literal = blob.literal
            if blob.kind == "table":
                bytes_list = [int(v.strip(), 0) for v in literal.split("{")[1].split("}")[0].split(",") if v.strip()]
                blob_bytes = bytes([b & 0xFF for b in bytes_list])
            else:
                payload_match = re.search(r"(['\"]).*(?P<payload>.+)(?:\\1)", literal, re.DOTALL)
                payload = payload_match.group("payload") if payload_match else literal
                blob_bytes = self.unescape_lua_string(payload)

            LOG.info(
                "[BOOTSTRAP] Decoding blob %d (%s) of size %d bytes.",
                idx,
                blob.name or blob.kind,
                len(blob_bytes),
            )

            if not decoder_impl:
                decoder_impl = DecoderImplementation(func=None, needs_emulation=True)
                needs_emulation = True

            decoded, error = self.decode_blob_bytes(blob_bytes, script_key_bytes, decoder_impl)
            if error:
                errors.append(error)

            meta = self.extract_metadata_from_decoded(decoded)
            if meta.get("alphabet") and not aggregate_metadata.get("alphabet"):
                aggregate_metadata["alphabet"] = meta["alphabet"]
            aggregate_metadata["opcode_map"].update(meta.get("opcode_map", {}))
            aggregate_metadata["constants"].update(meta.get("constants", {}))

            self._persist_artifacts(blob, decoded, meta)

            sanitized_name = re.sub(
                r"[^A-Za-z0-9_.-]", "_", (blob.name or f"offset_{blob.start}")
            )[:60]
            blob_entry = {
                "name": blob.name,
                "kind": blob.kind,
                "size": len(blob_bytes),
                "decoded_size": len(decoded),
                "decoded_path": os.path.join(
                    "logs", f"bootstrap_decoded_{sanitized_name}.bin"
                ),
                "metadata_path": os.path.join(
                    "logs", f"bootstrapper_metadata_{sanitized_name}.json"
                ),
            }
            aggregate_metadata["blobs"].append(blob_entry)
            decoded_blobs[f"blob_{idx}"] = decoded

        success = bool(decoded_blobs)
        result = BootstrapperExtractionResult(
            decoded_blobs=decoded_blobs,
            bootstrapper_metadata=aggregate_metadata,
            raw_matches=raw_matches,
            success=success,
            errors=errors,
            needs_emulation=needs_emulation,
        )

        LOG.info(
            "[BOOTSTRAP] Extraction completed: success=%s, needs_emulation=%s, errors=%d",
            success,
            needs_emulation,
            len(errors),
        )

        return result

    # ------------------------------------------------------------------
    def _persist_artifacts(self, blob: BlobInfo, decoded: bytes, meta: Dict[str, Any]) -> None:
        """Write decoded payload bytes and metadata summaries to disk."""

        logs_dir = os.path.join("logs")
        os.makedirs(logs_dir, exist_ok=True)

        base_name = blob.name or f"offset_{blob.start}"
        sanitized = re.sub(r"[^A-Za-z0-9_.-]", "_", base_name)[:60]
        bin_path = os.path.join(logs_dir, f"bootstrap_decoded_{sanitized}.bin")
        json_path = os.path.join(logs_dir, f"bootstrapper_metadata_{sanitized}.json")

        try:
            with open(bin_path, "wb") as fh:
                fh.write(decoded)
            LOG.debug("[BOOTSTRAP] Wrote decoded blob to %s", bin_path)
        except OSError as exc:  # pragma: no cover - filesystem errors are rare in CI
            LOG.warning("[BOOTSTRAP] Failed to write decoded blob %s: %s", bin_path, exc)

        try:
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(meta, fh, indent=2, ensure_ascii=False)
            LOG.debug("[BOOTSTRAP] Wrote metadata snapshot to %s", json_path)
        except OSError as exc:  # pragma: no cover
            LOG.warning("[BOOTSTRAP] Failed to write metadata json %s: %s", json_path, exc)

    # ------------------------------------------------------------------
    @staticmethod
    def _range_overlaps(ranges: Iterable[Tuple[int, int]], start: int, end: int) -> bool:
        for r_start, r_end in ranges:
            if start < r_end and end > r_start:
                return True
        return False

