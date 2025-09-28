"""
src/bootstrap_decoder.py

BootstrapDecoder:
 - Python-first decoding of initv4 bootstrapper blobs (alphabet detection, base91, key XOR, index mixing)
 - Optional sandboxed Lua fallback using lupa if Python heuristics don't yield confident results
 - Writes artifacts to out/logs and returns a structured BootstrapperExtractionResult

Dependencies:
 - base91 (pip) for basE91 decode
 - lupa (pip) for sandboxed Lua fallback (requires LuaJIT on system)

References:
 - Lupa (LuaJIT <-> Python): https://pypi.org/project/lupa/ and https://github.com/scoder/lupa. :contentReference[oaicite:5]{index=5}
 - base91 Python implementations: https://github.com/aberaud/base91-python and base91 packages on PyPI. :contentReference[oaicite:6]{index=6}
 - Lua sandbox patterns & removing unsafe libs: lua-users wiki / sandboxing guidance. :contentReference[oaicite:7]{index=7}
"""

import re
import os
import json
import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple

from src.utils.io_utils import ensure_out, write_b64_text
from src.utils.lph_decoder import parse_escaped_lua_string, try_xor as lph_try_xor
from src.utils.luraph_vm import rebuild_vm_bytecode
from src.utils.opcode_inference import infer_opcode_map

# Optional imports (fall back if missing)
try:
    import base91
except Exception:
    base91 = None

try:
    import lupa
    from lupa import LuaRuntime
except Exception:
    lupa = None
    LuaRuntime = None

_DEFAULT_OUT_DIR = ensure_out(os.environ.get("LURAPH_OUT_DIR", "out"))
_LOGS_ENV = os.environ.get("LURAPH_LOGS_DIR")
LOGS_DIR = ensure_out(_LOGS_ENV) if _LOGS_ENV else ensure_out(_DEFAULT_OUT_DIR, "logs")
logger = logging.getLogger("bootstrap_decoder")
logger.setLevel(logging.DEBUG)


@dataclass
class BootstrapperExtractionResult:
    success: bool
    metadata_dict: Dict[str, Any] = field(default_factory=dict)
    decoded_bytes: Optional[bytes] = None
    needs_emulation: bool = False
    error: Optional[str] = None
    trace: List[str] = field(default_factory=list)


class BootstrapDecoder:
    """
    BootstrapDecoder tries:
      1) static extraction: find candidate alphabet/opcode text in bootstrap Lua source
      2) python reimplementation: base91 -> key-xor -> index-mix -> simple rle passthrough
      3) sandboxed Lua fallback using lupa to let bootstrap decode itself and capture alphabet/opcodes
    """

    # Regex patterns
    _ALPHABET_RE = re.compile(r'(?P<name>\w{0,32})\s*=\s*["\'](?P<val>[^"\']{85,200})["\']')
    _BLOB_RE = re.compile(
        r"(?P<name>superflow_bytecode_ext(?:\d+)?|payload)\s*=\s*['\"]"
        r"(?P<val>(?:\\\\\d{1,3}|\\\\x[0-9A-Fa-f]{2}|[^'\"]){100,})"
        r"['\"]",
        re.S,
    )
    _GENERIC_LONG_STRING_RE = re.compile(r'["\'](?P<val>[! -~]{160,})["\']', re.S)  # printable run
    _OPCODE_TABLE_RE = re.compile(r'\[\s*0x([0-9A-Fa-f]+)\s*\]\s*=\s*(?:["\']?([A-Za-z0-9_]+)["\']?|function)', re.S)

    def __init__(
        self,
        bootstrap_path: str,
        script_key: Optional[str] = None,
        debug: bool = False,
        *,
        out_dir: Optional[str] = None,
        emit_binary: bool = False,
        output_prefix: str = "bootstrap_blob",
    ):
        self.bootstrap_path = bootstrap_path
        self.script_key = script_key or ""
        self.script_key_bytes = (script_key.encode("utf-8") if script_key else b"")
        self.debug = debug
        self.out_dir = ensure_out(out_dir) if out_dir else _DEFAULT_OUT_DIR
        if _LOGS_ENV:
            self.logs_dir = ensure_out(_LOGS_ENV)
        else:
            self.logs_dir = ensure_out(self.out_dir, "logs")
        self.emit_binary = bool(emit_binary)
        self.output_prefix = output_prefix or "bootstrap_blob"

    # ===== file helpers =====
    def _read_bootstrap(self) -> str:
        with open(self.bootstrap_path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()

    # ===== lua string unescape helper =====
    def _unescape_lua_string(self, s: str) -> bytes:
        r"""Convert a Lua string literal into bytes using LPH decoding rules."""

        try:
            decoded = parse_escaped_lua_string(s)
            if decoded is not None:
                return decoded
        except Exception as exc:
            self._debug_log(f"parse_escaped_lua_string failed: {exc}")

        # Fallback to conservative escape handling to avoid regressions.
        out = bytearray()
        i = 0
        L = len(s)
        while i < L:
            ch = s[i]
            if ch == "\\" and i + 1 < L:
                nxt = s[i + 1]
                if nxt in ("n", "r", "t", "\\", "\"", "'"):
                    mapping = {"n": 10, "r": 13, "t": 9, "\\": 92, '"': 34, "'": 39}
                    out.append(mapping.get(nxt, ord(nxt)))
                    i += 2
                    continue
                if nxt == "x" and i + 3 < L and re.match(r'[0-9A-Fa-f]{2}', s[i + 2:i + 4]):
                    hexv = s[i + 2:i + 4]
                    out.append(int(hexv, 16))
                    i += 4
                    continue
                m = re.match(r'\\([0-7]{1,3})', s[i:])
                if m:
                    octv = m.group(1)
                    out.append(int(octv, 8))
                    i += 1 + len(octv)
                    continue
                out.append(ord(nxt))
                i += 2
            else:
                out.append(ord(ch))
                i += 1
        return bytes(out)

    def _artifact_b64_path(self) -> str:
        out_dir = getattr(self, "out_dir", _DEFAULT_OUT_DIR)
        prefix = getattr(self, "output_prefix", "bootstrap_blob")
        return os.path.join(out_dir, f"{prefix}.b64.txt")

    def _has_lua_markers(self, data: Optional[bytes]) -> bool:
        if not data:
            return False
        lowered = data.lower()
        return b"function" in lowered or b"\x1blua" in lowered

    def _emit_blob_artifacts(
        self,
        blob_name: str,
        raw_bytes: Optional[bytes],
        decoded_bytes: Optional[bytes] = None,
    ) -> None:
        if not raw_bytes and not decoded_bytes:
            return

        safe_blob = re.sub(r"[^A-Za-z0-9_.-]", "_", blob_name or "blob")
        logs_dir = getattr(self, "logs_dir", LOGS_DIR)
        emit_binary = bool(getattr(self, "emit_binary", False))
        prefix = getattr(self, "output_prefix", "bootstrap_blob")

        candidate = decoded_bytes or raw_bytes or b""
        xored = lph_try_xor(candidate, self.script_key_bytes)
        if self._has_lua_markers(xored):
            preferred = xored
        elif self._has_lua_markers(candidate):
            preferred = candidate
        elif self._has_lua_markers(raw_bytes):
            preferred = raw_bytes or candidate
        else:
            preferred = candidate

        write_b64_text(self._artifact_b64_path(), preferred)

        if not emit_binary:
            return

        if raw_bytes:
            raw_path = os.path.join(logs_dir, f"{prefix}_{safe_blob}_raw.bin")
            with open(raw_path, "wb") as handle:
                handle.write(raw_bytes)
        if decoded_bytes and decoded_bytes != raw_bytes:
            dec_path = os.path.join(logs_dir, f"{prefix}_{safe_blob}_decoded.bin")
            with open(dec_path, "wb") as handle:
                handle.write(decoded_bytes)
        if preferred not in {raw_bytes, decoded_bytes} and preferred:
            pref_path = os.path.join(logs_dir, f"{prefix}_{safe_blob}_preferred.bin")
            with open(pref_path, "wb") as handle:
                handle.write(preferred)

    # ===== blob & alphabet discovery =====
    def find_blobs_and_alphabets(self, bootstrap_src: str) -> Tuple[List[Tuple[str,str]], List[str]]:
        """
        Return two lists:
          - blobs: list of tuples (name, raw_literal) where raw_literal is the literal body (not unescaped)
          - alphabet_candidates: list of strings found that might be alphabets
        """
        blobs = []
        alphabets = []

        # direct blob pattern (superflow style)
        for m in self._BLOB_RE.finditer(bootstrap_src):
            name = m.group("name")
            val = m.group("val")
            blobs.append((name, val))
            self._debug_log(f"Found blob pattern {name} len={len(val)}")

        # explicit alphabet assignments
        for m in self._ALPHABET_RE.finditer(bootstrap_src):
            name = m.group("name")
            val = m.group("val")
            if len(set(val)) >= 60:
                alphabets.append(val)
                self._debug_log(f"Found alphabet candidate {name} len={len(val)} unique={len(set(val))}")

        # generic printable long strings
        for m in self._GENERIC_LONG_STRING_RE.finditer(bootstrap_src):
            val = m.group("val")
            if len(val) >= 160:
                blobs.append(("long_printable", val))
                self._debug_log(f"Found long printable blob len={len(val)}")
                if 85 <= len(val) <= 200 and len(set(val)) >= 60:
                    alphabets.append(val)
                    self._debug_log(
                        "Treating long printable string as alphabet candidate len=%d unique=%d",
                        len(val),
                        len(set(val)),
                    )

        # try opcode table textual matches
        opcodes = {}
        for m in self._OPCODE_TABLE_RE.finditer(bootstrap_src):
            op_hex = m.group(1)
            name = m.group(2) or f"OP_{op_hex}"
            opcodes[int(op_hex, 16)] = name
        if opcodes:
            alphabets.append("")  # placeholder so metadata captures opcodes later
            self._debug_log(f"Found opcode textual table entries: {len(opcodes)}")
        return blobs, alphabets

    # ===== heuristics-based python decode =====
    _STANDARD_BASE91_ALPHABET = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
    )

    def _fallback_base91_decode(self, encoded: bytes, alphabet: Optional[str] = None) -> Optional[bytes]:
        """Decode ``encoded`` using the provided alphabet or the standard basE91 set."""

        if alphabet and len(alphabet) >= 85 and len(set(alphabet)) == len(alphabet):
            chosen = alphabet
        else:
            chosen = self._STANDARD_BASE91_ALPHABET
        table = {ch: idx for idx, ch in enumerate(chosen)}
        value = -1
        buffer = 0
        bits = 0
        out = bytearray()

        try:
            text = encoded.decode("latin1", errors="ignore")
        except Exception:
            return None

        for ch in text:
            if ch.isspace():
                continue
            if ch not in table:
                return None
            cval = table[ch]
            if value < 0:
                value = cval
                continue
            value += cval * 91
            buffer |= value << bits
            if value & 0x1FFF > 88:
                bits += 13
            else:
                bits += 14
            while bits >= 8:
                out.append(buffer & 0xFF)
                buffer >>= 8
                bits -= 8
            value = -1

        if value >= 0:
            buffer |= value << bits
            out.append(buffer & 0xFF)

        return bytes(out)

    def _try_base91_decode(self, encoded: bytes, alphabet: Optional[str] = None) -> Optional[bytes]:
        """Attempt basE91 decoding using ``base91`` when available or the fallback."""

        s = encoded.decode("latin1", errors="ignore")
        if base91:
            try:
                return base91.decode(s)
            except Exception as e:
                self._debug_log(f"base91.decode failed: {e}")
        fallback = self._fallback_base91_decode(encoded, alphabet)
        if fallback is not None:
            return fallback
        return None

    def _validate_decoded_blob(self, decoded: bytes) -> bool:
        sample = (decoded or b"")[:1024].lower()
        if not sample:
            return False
        tokens = (b"function", b"local", b"\x1blua")
        return any(token in sample for token in tokens)

    def _python_transform_pipeline(self, blob_bytes: bytes, alphabet: Optional[str]) -> Tuple[Optional[bytes], List[str]]:
        """
        Attempt composed transforms:
         - If alphabet provided -> use base91 decode (requires base91 lib)
         - XOR with key bytes
         - optional index mixing (v ^= (i & 0xFF))
        Return (decoded_bytes or None, trace)
        """
        trace = []
        decoded = None

        # Step 1: attempt basE91 decode when an alphabet or printable data is available
        if alphabet:
            trace.append("attempt basE91 decode using provided alphabet")
            candidate = self._try_base91_decode(blob_bytes, alphabet)
            if candidate:
                decoded = candidate
                trace.append("base91 succeeded")
        elif all(32 <= b < 127 for b in blob_bytes[:200]):
            trace.append("attempt base91 (no alphabet given)")
            candidate = self._try_base91_decode(blob_bytes)
            if candidate:
                decoded = candidate
                trace.append("base91 succeeded (no alphabet)")

        # If base91 decode not done, assume blob_bytes are raw numeric escape decoded bytes
        if decoded is None:
            trace.append("treating blob as already binary")
            decoded = blob_bytes

        def xor_with_key(buf: bytes, label: str) -> bytes:
            if not self.script_key_bytes:
                raise ValueError("no script key available for XOR step")
            out = lph_try_xor(buf, self.script_key_bytes)
            trace.append(f"applied key XOR ({label})")
            return out

        def index_mix(buf: bytes) -> bytes:
            out = bytearray(len(buf))
            for i, b in enumerate(buf):
                out[i] = b ^ (i & 0xFF)
            trace.append("applied index XOR (i & 0xFF)")
            return bytes(out)

        sequences = []
        if self.script_key_bytes:
            sequences.append(("key-index-key", ("xor_pre", "index", "xor_post")))
            sequences.append(("index-key", ("index", "xor_post")))
            sequences.append(("key-index", ("xor_pre", "index")))
            sequences.append(("key-only", ("xor_pre",)))
        sequences.append(("index-only", ("index",)))
        sequences.append(("identity", ()))

        for label, steps in sequences:
            candidate = decoded
            try:
                for step in steps:
                    if step.startswith("xor"):
                        candidate = xor_with_key(candidate, step)
                    elif step == "index":
                        candidate = index_mix(candidate)
            except Exception as exc:
                trace.append(f"{label} transform failed: {exc}")
                continue

            if self._validate_decoded_blob(candidate):
                trace.append(f"validation OK after {label} transforms")
                return candidate, trace
            trace.append(f"{label} transform failed validation")

        trace.append("validation failed: no lua-like keywords found in decoded data")
        return None, trace

    def _convert_lua_table(
        self,
        value,
        depth: int = 0,
        max_depth: int = 6,
        max_items: int = 2048,
    ):
        """Best-effort conversion of a Lua table into Python primitives."""

        if depth > max_depth:
            return "<depth-limit>"

        if isinstance(value, (str, bytes, int, float, bool)) or value is None:
            return value

        if not hasattr(value, "items"):
            return str(value)

        array: List[object] = []
        mapping: Dict[object, object] = {}
        count = 0
        for key, item in value.items():
            count += 1
            if count > max_items:
                mapping["__truncated__"] = True
                break

            py_item = self._convert_lua_table(item, depth + 1, max_depth, max_items)

            if isinstance(key, (int, float)) and float(key).is_integer() and key > 0:
                idx = int(key)
                if idx > 4096:
                    mapping[f"index_{idx}"] = py_item
                    continue
                while len(array) < idx:
                    array.append(None)
                array[idx - 1] = py_item
            else:
                mapping[str(key)] = py_item

        while array and array[-1] is None:
            array.pop()

        if mapping and array:
            return {"array": array, "map": mapping}
        if mapping:
            return mapping
        return array

    # ===== Lua sandbox fallback (lupa) =====
    def _lua_sandbox_decode(self, bootstrap_src: str, blob_literal: str, timeout_s: int = 5) -> Tuple[Optional[bytes], Dict[str, Any], List[str]]:
        """
        Use lupa to run the bootstrap decode in a restricted environment and attempt to capture the alphabet and opcode map.
        Returns (decoded_bytes_or_none, metadata, trace_lines)
        """
        trace = []
        metadata = {}
        if LuaRuntime is None:
            trace.append("lupa not installed; cannot run lua fallback")
            return None, metadata, trace

        # Prepare Lua runtime with limited globals
        lua = None
        try:
            lua = LuaRuntime(unpack_returned_tuples=True)
        except Exception as e:
            trace.append(f"LuaRuntime init failed: {e}")
            return None, metadata, trace

        # Build safe env
        safe_env = lua.table()

        # Provide minimal safe string/table/math functions (copy selectively)
        safe_env["string"] = lua.eval("{ sub = string.sub, find = string.find, byte = string.byte, char = string.char, len = string.len }")
        safe_env["table"] = lua.eval("{ insert = table.insert, remove = table.remove, unpack = table.unpack }")
        safe_env["math"] = lua.eval("{ floor = math.floor, ceil = math.ceil, abs = math.abs }")

        # block dangerous builtins by not adding them (os, io, debug, package)
        # inject SCRIPT_KEY if bootstrap expects it
        safe_env["SCRIPT_KEY"] = self.script_key or ""

        # Capture hooks
        captured = {
            "alphabets": [],
            "opcode_tables": [],
            "raw_assignments": [],
            "unpacked_tables": [],
        }

        # Helpers we will inject into the Lua env to capture assignments
        # We'll define small Lua print-capture and a register function
        lua_code_capture = r'''
        function __capture_assign(name, val)
            -- If val is a string and length > 80, record it
            if type(val) == "string" and #val >= 80 then
                __capture_store_alphabet(val)
            elseif type(val) == "table" then
                -- heuristics: numeric keys with function values
                local num = 0
                for k, v in pairs(val) do
                    if type(k) == "number" and type(v) == "function" then
                        num = num + 1
                    end
                end
                if num >= 16 then
                    __capture_store_opcode_table(val)
                end
            end
        end
        '''
        # Register capture helpers from Python side
        def py_store_alphabet(val):
            try:
                if isinstance(val, (str, bytes)):
                    s = val if isinstance(val, str) else val.decode("latin1", errors="ignore")
                    captured["alphabets"].append(s)
            except Exception as e:
                logger.debug("py_store_alphabet error: %s", e)

        def py_store_opcode_table(tbl):
            try:
                # convert lua table to python mapping where numeric keys map to function names or placeholders
                m = {}
                for k, v in tbl.items():
                    try:
                        key = int(k)
                    except Exception:
                        continue
                    if callable(v):
                        # try to get a name via debug if available; else placeholder
                        # Lupa functions are callable python proxies; we set placeholder names
                        m[key] = f"OP_{key:02X}"
                    else:
                        m[key] = str(v)
                captured["opcode_tables"].append(m)
            except Exception as e:
                logger.debug("py_store_opcode_table error: %s", e)

        def py_store_unpacked(tbl):
            try:
                converted = self._convert_lua_table(tbl)
                captured["unpacked_tables"].append(converted)
            except Exception as e:
                logger.debug("py_store_unpacked error: %s", e)

        # bind python functions into lua
        lua.globals()["__capture_store_alphabet"] = py_store_alphabet
        lua.globals()["__capture_store_opcode_table"] = py_store_opcode_table
        lua.globals()["__capture_unpacked"] = py_store_unpacked

        # load the bootstrap code under the safe env
        try:
            # we will run the bootstrap in the safe env by loading it as a chunk then setting _ENV
            # Note: in LuaJIT (5.1) setfenv is used; in Lua 5.2+ use load(chunk, "name", "t", env)
            # We'll attempt to use generic load via lupa
            loader = lua.eval("function(src) return load(src) end")
            chunk = loader(bootstrap_src)
            if chunk is None:
                trace.append("lua load failed to produce a chunk")
                return None, metadata, trace
            # set environment if possible
            try:
                # prefer setting _ENV if supported
                lua.execute("_ENV = _ENV or _G")
            except Exception:
                pass

            # spawn watchdog
            result_holder = {}
            def target():
                try:
                    # run chunk; the chunk will run inside LuaRuntime default env but our capture hooks are registered globally
                    chunk()
                    result_holder["ok"] = True
                except Exception as e:
                    result_holder["err"] = str(e)

            t = threading.Thread(target=target, daemon=True)
            t.start()
            t.join(timeout_s)
            if t.is_alive():
                trace.append("lua sandbox timeout; thread still running -> abort")
                return None, metadata, trace
            if "err" in result_holder:
                trace.append(f"lua runtime error: {result_holder['err']}")
        except Exception as e:
            trace.append(f"lua execution failed: {e}")
            return None, metadata, trace

        # Attempt to hook interpreter and proactively trigger the unpacker when available
        try:
            lua.execute(
                """
                if type(LuraphInterpreter) == "function" then
                    local original = LuraphInterpreter
                    LuraphInterpreter = function(unpacked, env)
                        __capture_unpacked(unpacked)
                        return original(unpacked, env)
                    end
                end
                if type(LPH_UnpackData) == "function" then
                    local ok, unpacked = pcall(LPH_UnpackData)
                    if ok and type(unpacked) == "table" then
                        __capture_unpacked(unpacked)
                    end
                end
                """
            )
        except Exception as exc:
            trace.append(f"lua capture hook failed: {exc}")

        # After running, see what we captured
        # Prefer longest alphabet candidate
        alph = None
        if captured["alphabets"]:
            alph = max(captured["alphabets"], key=lambda s: len(s))
            metadata["alphabet"] = alph
            trace.append(f"lua-capture: alphabet len={len(alph)}")
        if captured["opcode_tables"]:
            # choose the largest
            chosen = max(captured["opcode_tables"], key=lambda t: len(t))
            metadata["opcode_map"] = chosen
            trace.append(f"lua-capture: opcode_map entries={len(chosen)}")
            try:
                write_json(os.path.join(self.out_dir, "opcode_map.json"), chosen)
            except Exception as exc:  # pragma: no cover - defensive
                trace.append(f"lua-capture: failed to write opcode_map.json ({exc})")
        if captured["unpacked_tables"]:
            vm_table = captured["unpacked_tables"][0]
            metadata["unpackedData"] = vm_table
            trace.append("lua-capture: captured unpackedData table")
            if "opcode_map" not in metadata:
                try:
                    inferred_map = infer_opcode_map(vm_table)
                except Exception as exc:  # pragma: no cover - defensive
                    trace.append(f"lua-capture: opcode inference failed ({exc})")
                else:
                    if inferred_map:
                        metadata["opcode_map"] = inferred_map
                        trace.append(
                            f"lua-capture: inferred opcode map entries={len(inferred_map)}"
                        )
                        try:
                            write_json(
                                os.path.join(self.out_dir, "opcode_map.json"), inferred_map
                            )
                        except Exception as exc:  # pragma: no cover - defensive
                            trace.append(
                                f"lua-capture: failed to write opcode_map.json ({exc})"
                            )
            try:
                rebuild = rebuild_vm_bytecode(vm_table, metadata.get("opcode_map"))
            except Exception as exc:  # pragma: no cover - defensive
                trace.append(f"lua-capture: vm rebuild failed ({exc})")
            else:
                try:
                    write_json(os.path.join(self.out_dir, "unpacked.json"), vm_table)
                except Exception as exc:  # pragma: no cover - defensive
                    trace.append(f"lua-capture: failed to write unpacked.json ({exc})")
                if rebuild.bytecode:
                    metadata["vm_bytecode"] = [b for b in rebuild.bytecode]
                    metadata["_vm_bytecode_bytes"] = rebuild.bytecode
                    metadata["vm_instruction_count"] = len(rebuild.instructions)
                    trace.append(
                        f"lua-capture: rebuilt {len(rebuild.instructions)} bytecode instructions"
                    )
                    try:
                        out_path = os.path.join(self.out_dir, "reconstructed.luac")
                        ensure_out(self.out_dir)
                        with open(out_path, "wb") as handle:
                            handle.write(rebuild.bytecode)
                        metadata.setdefault("artifact_paths", {})["reconstructed_luac"] = out_path
                    except Exception as exc:  # pragma: no cover - defensive
                        trace.append(f"lua-capture: failed to write reconstructed.luac ({exc})")
                if rebuild.constants:
                    metadata["vm_constants"] = rebuild.constants
                if rebuild.instructions:
                    metadata["vm_instructions"] = rebuild.instructions

        # If the bootstrap exposed a direct decode function, try to call it on blob literal
        # Some bootstrappers return or write the decoded payload to a global; we attempt to inspect typical names
        # Common patterns: init_fn(...), decode_blob(...), or assignment to `payload`
        possible_names = ["init_fn", "decode_blob", "decode", "run"]
        decoded_bytes = None
        for name in possible_names:
            try:
                f = lua.globals().get(name)
                if f:
                    trace.append(f"invoking lua function {name} to decode blob")
                    # call with the raw blob (unescaped) - but we can't easily produce the same escapes:
                    # instead, attempt calling with script key if function expects it
                    try:
                        res = f(self.script_key or "")
                        if isinstance(res, (bytes, str)):
                            if isinstance(res, str):
                                decoded_bytes = res.encode("latin1", errors="ignore")
                            else:
                                decoded_bytes = res
                            trace.append(f"lua decode func {name} returned bytes len={len(decoded_bytes)}")
                            break
                    except TypeError:
                        # try no-arg
                        try:
                            res = f()
                            if isinstance(res, (bytes, str)):
                                decoded_bytes = res.encode("latin1", errors="ignore") if isinstance(res, str) else res
                                trace.append(f"lua decode func {name} returned bytes len={len(decoded_bytes)}")
                                break
                        except Exception as e2:
                            trace.append(f"lua call {name} failed: {e2}")
            except Exception as e:
                trace.append(f"probe of lua function {name} failed: {e}")

        return decoded_bytes, metadata, trace

    # ===== public API =====
    def run_full_extraction(self, allow_lua_run: bool = False, timeout_s: int = 5) -> BootstrapperExtractionResult:
        """
        Orchestrate full extraction. Returns BootstrapperExtractionResult.
        Steps:
         - read bootstrap
         - find blobs & alphabet candidates
         - for each blob: unescape, try python pipeline
         - if python decode fails and allow_lua_run True: attempt lua sandbox fallback
         - write artifacts and return metadata/result
        """
        res = BootstrapperExtractionResult(success=False, metadata_dict={})
        try:
            src = self._read_bootstrap()
            blobs, alph_cands = self.find_blobs_and_alphabets(src)
            res.trace.append(f"found {len(blobs)} blobs and {len(alph_cands)} alphabet candidates")

            # pick an alphabet candidate if present (prefer explicit alphabets)
            alphabet = None
            if alph_cands:
                # choose the longest non-empty candidate
                cand = max([c for c in alph_cands if c], key=len, default=None)
                if cand:
                    alphabet = cand
                    res.trace.append(f"selected alphabet candidate len={len(cand)}")

            # if no blobs found, return early
            if not blobs:
                # last-resort: search for any long printable run
                m = self._GENERIC_LONG_STRING_RE.search(src)
                if m:
                    blobs.append(("generic", m.group("val")))
                    res.trace.append("no explicit blob; used generic long printable run")

            # iterate blobs
            for name, rawlit in blobs:
                res.trace.append(f"processing blob {name} (literal len={len(rawlit)})")
                # unescape lua string literal into bytes
                try:
                    blob_bytes = self._unescape_lua_string(rawlit)
                    res.trace.append(f"unescaped blob -> {len(blob_bytes)} bytes")
                except Exception as e:
                    res.trace.append(f"unescape failed: {e}")
                    blob_bytes = rawlit.encode("latin1", errors="ignore")

                self._emit_blob_artifacts(name, blob_bytes)

                # try python transform pipeline
                decoded, ttrace = self._python_transform_pipeline(blob_bytes, alphabet)
                res.trace.extend(ttrace)
                if decoded:
                    res.success = True
                    res.decoded_bytes = decoded
                    res.metadata_dict["alphabet"] = alphabet
                    res.metadata_dict["extraction_method"] = "python_reimpl"
                    res.metadata_dict["confidence"] = 0.8
                    res.metadata_dict["blob_name"] = name
                    self._emit_blob_artifacts(name, blob_bytes, decoded)
                    artifact_paths = res.metadata_dict.setdefault("artifact_paths", {})
                    artifact_paths["bootstrap_blob_b64"] = self._artifact_b64_path()
                    res.trace.append(
                        f"wrote decoded blob to {self._artifact_b64_path()} (base64)"
                    )
                    return res  # success, done

                # python decode failed: attempt Lua fallback (if allowed)
                if allow_lua_run:
                    res.trace.append("python decode failed; attempting lua sandbox fallback")
                    decoded2, meta2, lua_trace = self._lua_sandbox_decode(src, rawlit, timeout_s=timeout_s)
                    res.trace.extend(lua_trace)
                    if decoded2:
                        res.success = True
                        res.decoded_bytes = decoded2
                        res.metadata_dict.update(meta2 or {})
                        res.metadata_dict["extraction_method"] = "lua_sandbox"
                        res.metadata_dict["confidence"] = 0.95
                        self._emit_blob_artifacts(name, blob_bytes, decoded2)
                        artifact_paths = res.metadata_dict.setdefault("artifact_paths", {})
                        artifact_paths["bootstrap_blob_b64"] = self._artifact_b64_path()
                        res.trace.append(
                            f"wrote lua-decoded blob to {self._artifact_b64_path()} (base64)"
                        )
                        return res
                    else:
                        res.trace.append("lua sandbox fallback did not return decoded bytes")
                        res.needs_emulation = True
                        res.metadata_dict["needs_emulation"] = True

                else:
                    res.trace.append("python decode failed and lua fallback not allowed")
                    res.needs_emulation = True
                    res.metadata_dict["needs_emulation"] = True

            # after all blobs tried
            res.error = None
            if not res.success:
                res.metadata_dict.setdefault("warnings", []).append("no_decoded_blob_found")
                res.metadata_dict.setdefault("alphabet_candidates", []).extend(alph_cands)
                # write raw matches to logs for inspection
                raw_out = os.path.join(self.logs_dir, f"bootstrap_raw_{os.path.basename(self.bootstrap_path)}.txt")
                with open(raw_out, "w", encoding="utf-8") as fh:
                    fh.write(src)
                res.trace.append(f"wrote raw bootstrap source to {raw_out}")
                res.success = False
                res.needs_emulation = True
                res.metadata_dict["needs_emulation"] = True
            return res

        except Exception as e:
            res.error = str(e)
            res.trace.append(f"exception in run_full_extraction: {e}")
            return res

    # ===== utilities =====
    def _debug_log(self, msg: str):
        if self.debug:
            logger.debug(msg)
            # also append to trace log file
            try:
                p = os.path.join(self.logs_dir, "bootstrap_debug.log")
                with open(p, "a", encoding="utf-8") as fh:
                    fh.write(f"{time.asctime()}: {msg}\n")
            except Exception:
                pass
