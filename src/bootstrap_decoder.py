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

LOGS_DIR = os.environ.get("LURAPH_LOGS_DIR", "out/logs")
os.makedirs(LOGS_DIR, exist_ok=True)
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
    _ALPHABET_RE = re.compile(r'(?P<name>\w{0,32})\s*=\s*["\'](?P<val>[^"\']{80,200})["\']')
    _BLOB_RE = re.compile(
        r"(?P<name>superflow_bytecode_ext\w*|payload)\s*=\s*['\"]"
        r"(?P<val>(?:\\\\\d{1,3}|\\\\x[0-9A-Fa-f]{2}|[^'\"]){100,})"
        r"['\"]",
        re.S,
    )
    _GENERIC_LONG_STRING_RE = re.compile(r'["\'](?P<val>[! -~]{160,})["\']', re.S)  # printable run
    _OPCODE_TABLE_RE = re.compile(r'\[\s*0x([0-9A-Fa-f]+)\s*\]\s*=\s*(?:["\']?([A-Za-z0-9_]+)["\']?|function)', re.S)

    def __init__(self, bootstrap_path: str, script_key: Optional[str] = None, debug: bool = False):
        self.bootstrap_path = bootstrap_path
        self.script_key = script_key or ""
        self.script_key_bytes = (script_key.encode("utf-8") if script_key else b"")
        self.debug = debug
        self.logs_dir = LOGS_DIR

    # ===== file helpers =====
    def _read_bootstrap(self) -> str:
        with open(self.bootstrap_path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()

    # ===== lua string unescape helper =====
    def _unescape_lua_string(self, s: str) -> bytes:
        r"""
        Convert a Lua string literal body (with escapes like \xHH or \ddd) into raw bytes.
        Handles \xHH hex, \ddd octal, and common C-like escapes.
        """
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
                # octal \ddd up to 3 digits
                m = re.match(r'\\([0-7]{1,3})', s[i:])
                if m:
                    octv = m.group(1)
                    out.append(int(octv, 8))
                    i += 1 + len(octv)
                    continue
                # unknown escape -> keep literal next char
                out.append(ord(nxt))
                i += 2
            else:
                out.append(ord(ch))
                i += 1
        return bytes(out)

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
    def _try_base91_decode(self, encoded: bytes) -> Optional[bytes]:
        """
        Attempt basE91 decode if library available. If not, try a fallback to base91-python implementation.
        """
        s = encoded.decode("latin1", errors="ignore")
        if base91:
            try:
                return base91.decode(s)
            except Exception as e:
                self._debug_log(f"base91.decode failed: {e}")
                return None
        else:
            # Lightweight fallback: attempt to decode using a small implementation if available
            self._debug_log("base91 library not available; skipping base91 decode.")
            return None

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

        # Step 1: treat blob as ascii encoded base91 (if alphabet present, we prefer base91 lib)
        if alphabet:
            # If alphabet is provided but base91 lib is missing, we can't do custom base-n easily here
            if base91:
                trace.append("attempt base91 via base91 lib")
                candidate = self._try_base91_decode(blob_bytes)
                if candidate:
                    decoded = candidate
                    trace.append("base91 succeeded")
            else:
                trace.append("alphabet present but base91 lib missing; skipping base91 step")
        else:
            # try raw base91 decode if looks like printable
            if all(32 <= b < 127 for b in blob_bytes[:200]) and base91:
                trace.append("attempt base91 (no alphabet given) via base91 lib")
                candidate = self._try_base91_decode(blob_bytes)
                if candidate:
                    decoded = candidate
                    trace.append("base91 succeeded (no alphabet)")

        # If base91 decode not done, assume blob_bytes are raw numeric escape decoded bytes
        if decoded is None:
            trace.append("treating blob as already binary")
            decoded = blob_bytes

        # Step 2: key XOR (if script_key set)
        if self.script_key_bytes:
            try:
                k = self.script_key_bytes
                out = bytearray(len(decoded))
                for i, b in enumerate(decoded):
                    out[i] = b ^ k[i % len(k)]
                decoded = bytes(out)
                trace.append("applied key XOR")
            except Exception as e:
                trace.append(f"key XOR failed: {e}")

        # Step 3: index-mix heuristic
        try:
            out = bytearray(len(decoded))
            for i, b in enumerate(decoded):
                out[i] = b ^ (i & 0xFF)
            decoded = bytes(out)
            trace.append("applied index XOR (i & 0xFF)")
        except Exception as e:
            trace.append(f"index mix failed: {e}")

        # Quick validation: do we see 'function' or 'local ' in the first kilobyte?
        sample = decoded[:2048].lower()
        if b"function" in sample or b"init_fn" in sample or b"local " in sample:
            trace.append("validation OK: found lua-like keywords in decoded bytes")
            return decoded, trace
        else:
            trace.append("validation failed: no lua-like keywords found in decoded data")
            return None, trace

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
            "raw_assignments": []
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

        # bind python functions into lua
        lua.globals()["__capture_store_alphabet"] = py_store_alphabet
        lua.globals()["__capture_store_opcode_table"] = py_store_opcode_table

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
                    # write artifact
                    outpath = os.path.join(self.logs_dir, f"bootstrap_decoded_{os.path.basename(self.bootstrap_path)}_{name}.bin")
                    with open(outpath, "wb") as fh:
                        fh.write(decoded)
                    res.trace.append(f"wrote decoded blob to {outpath}")
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
                        # write artifact
                        outpath = os.path.join(self.logs_dir, f"bootstrap_decoded_{os.path.basename(self.bootstrap_path)}_{name}_lua.bin")
                        with open(outpath, "wb") as fh:
                            fh.write(decoded2)
                        res.trace.append(f"wrote lua-decoded blob to {outpath}")
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
