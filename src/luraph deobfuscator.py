"""
src/luraph_deobfuscator.py

Top-level Deobfuscator pipeline class used by main.py.

Responsibilities:
 - detect_version(input_path) -> {name, handler, confidence}
 - run() performs:
    * bootstrap extraction (via BootstrapDecoder)
    * multi-chunk decode & iteration
    * VM lifting (placeholder: integrate your lifter/devirtualizer here)
    * produce lua_source and json_report dict

Notes:
 - Requires src/bootstrap_decoder.py (BootstrapDecoder).
 - The VM lifter/devirtualizer is intentionally left as a stub to integrate with
   your existing lifter modules. The pipeline will pass alphabet/opcode_map
   to lifter via the `bootstrapper_metadata` field.
"""

import os
import re
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("Deobfuscator")
logger.setLevel(logging.DEBUG)

# attempt import of BootstrapDecoder
try:
    from src.bootstrap_decoder import BootstrapDecoder, BootstrapperExtractionResult
except Exception:
    BootstrapDecoder = None
    BootstrapperExtractionResult = None

# ---- utility helpers ----
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()

def looks_like_luraph(src: str) -> Dict[str, Any]:
    """
    Heuristic detection for Luraph v14.4.1 / initv4 bootstrap.
    Returns dict with keys: name, handler, confidence
    """
    lower = src.lower()
    r = {"name": "unknown", "handler": None, "confidence": 0.0}

    # simple version banner scan
    m = re.search(r"luraph[\s-_]*v?14(?:\.4(?:\.1)?)?", src, re.IGNORECASE)
    if m:
        r["name"] = "luraph_v14_4_initv4"
        r["handler"] = "initv4"
        r["confidence"] = 0.95
        return r

    # fallback: look for typical initv4 patterns: script_key and init function
    if "script_key" in lower and "init_fn" in lower:
        r["name"] = "luraph_v14_4_initv4"
        r["handler"] = "initv4"
        r["confidence"] = 0.6
        return r

    # detect JSON-wrapped form
    if lower.strip().startswith("{") and ("superflow_bytecode" in lower or "superflow_bytecode_ext" in lower):
        r["name"] = "luraph_v14_4_initv4_json"
        r["handler"] = "initv4"
        r["confidence"] = 0.6
        return r

    # otherwise unknown
    return r

# ---- Deobfuscator class ----
class Deobfuscator:
    def __init__(
        self,
        input_path: str,
        script_key: Optional[str] = None,
        bootstrapper_metadata: Optional[Dict[str, Any]] = None,
        max_iterations: int = 5,
        debug: bool = False,
    ):
        self.input_path = input_path
        self.script_key = script_key or ""
        self.bootstrapper_metadata = bootstrapper_metadata or {}
        self.max_iterations = max_iterations
        self.debug = debug

        # results
        self.lua_source = ""
        self.json_report: Dict[str, Any] = {
            "input": input_path,
            "script_key_used": bool(script_key),
            "bootstrapper_metadata": self.bootstrapper_metadata,
            "passes": [],
            "warnings": [],
            "errors": [],
        }

    @staticmethod
    def detect_version(input_path: str) -> Dict[str, Any]:
        try:
            src = read_text(input_path)
            return looks_like_luraph(src)
        except Exception as e:
            logger.debug("detect_version read failed: %s", e)
            return {"name": "unknown", "handler": None, "confidence": 0.0}

    def _validate_bootstrap_metadata(self, meta: Dict[str, Any]) -> bool:
        """
        Basic checks: alphabet length and opcode_map count thresholds.
        """
        if not meta:
            return False
        alphabet = meta.get("alphabet")
        opcode_map = meta.get("opcode_map") or meta.get("opcode_dispatch")
        if alphabet and len(alphabet) >= 60 and opcode_map and isinstance(opcode_map, dict) and len(opcode_map) >= 16:
            return True
        return False

    def _attempt_bootstrap_extraction(self, bootstrap_path: Optional[str]) -> Dict[str, Any]:
        """
        Run the BootstrapDecoder if available to extract alphabet/opcode and decoded bytes.
        Returns metadata dict (may include 'decoded_bytes' as base64 or raw bytes)
        """
        meta = {}
        if BootstrapDecoder is None:
            self.json_report["warnings"].append("bootstrap_decoder_module_missing")
            logger.warning("BootstrapDecoder implementation not available in src/; skipping extraction.")
            return meta

        bd = BootstrapDecoder(bootstrap_path, script_key=self.script_key, debug=self.debug)
        res: BootstrapperExtractionResult = bd.run_full_extraction(allow_lua_run=bool(self.bootstrapper_metadata.get("allow_lua_run", False)))
        # attach trace and metadata
        meta.update(res.metadata_dict or {})
        meta["needs_emulation"] = res.needs_emulation
        meta["_trace"] = res.trace
        if res.decoded_bytes:
            meta["_decoded_bytes_len"] = len(res.decoded_bytes)
            # keep decoded bytes in memory for immediate use (not saved to JSON raw)
            meta["_decoded_bytes"] = res.decoded_bytes
        return meta

    def _validate_decoded_bytes(self, b: bytes) -> bool:
        """
        Basic heuristic that decoded bytes "look like" Lua: contain 'function' or 'local ' markers
        """
        if not b:
            return False
        sample = b[:4096].lower()
        return b"function" in sample or b"local " in sample or b"init_fn" in sample

    def run(self) -> Dict[str, Any]:
        """
        Orchestrates deobfuscation:
         - Try to extract bootstrap metadata (alphabet/opcode_map) if not provided
         - Decode payload(s) (multi-chunk) using alphabet + script_key
         - For each decoded payload, validate and pass to lifter
         - Iterate nested decoding until stable or max_iterations
        """
        self.json_report["start_time"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"

        # 1) determine if we need to extract bootstrap metadata
        if not self.bootstrapper_metadata:
            # try to find a nearby initv4.lua if present next to input
            candidate_bootstrap = None
            input_dir = os.path.dirname(self.input_path) or "."
            cpath = os.path.join(input_dir, "initv4.lua")
            if os.path.exists(cpath):
                candidate_bootstrap = cpath
            # attempt extraction if candidate found
            if candidate_bootstrap:
                logger.info("Attempting bootstrap extraction using %s", candidate_bootstrap)
                meta = self._attempt_bootstrap_extraction(candidate_bootstrap)
                self.bootstrapper_metadata.update(meta)
                self.json_report["passes"].append({"bootstrap_extraction": True, "bootstrap_path": candidate_bootstrap, "metadata_summary": {"needs_emulation": meta.get("needs_emulation", False), "decoded_bytes_len": meta.get("_decoded_bytes_len")}})
            else:
                # no bootstrap found; leave metadata empty
                self.json_report["warnings"].append("no_bootstrap_found_adjacent")
                logger.info("No bootstrap file auto-located next to input.")

        # If metadata seems incomplete, add a warning
        if not self._validate_bootstrap_metadata(self.bootstrapper_metadata):
            self.json_report["warnings"].append("bootstrap_metadata_incomplete_or_missing")
            logger.warning("bootstrapper metadata seems incomplete; lifecycle may require --allow-lua-run or manual overrides.")

        # 2) Locate primary payload(s) in input (JSON wrapper or raw Lua)
        raw = read_text(self.input_path)
        payload_candidates = []

        # If JSON, try to parse and find fields that contain long strings
        try:
            j = json.loads(raw)
            # search for candidate string fields
            def walk_json(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        walk_json(v, path + "/" + k)
                elif isinstance(obj, list):
                    for i, v in enumerate(obj):
                        walk_json(v, path + f"[{i}]")
                elif isinstance(obj, str):
                    if len(obj) >= 120:
                        payload_candidates.append({"path": path, "data": obj})
                else:
                    pass
            walk_json(j)
        except Exception:
            # not JSON; treat raw as Lua code and search for long string literals
            # find long printable runs or superflow_bytecode_ext variables
            m = re.findall(r'["\']([! -~]{100,})["\']', raw, re.S)
            for i, s in enumerate(m):
                payload_candidates.append({"path": f"literal_{i}", "data": s})

        if not payload_candidates:
            self.json_report["warnings"].append("no_payload_candidates_found")
            logger.warning("No payload candidates found in input; aborting.")
            self.json_report["errors"].append("no_payload_candidates_found")
            return {"lua_source": "", "json_report": self.json_report}

        # 3) For each candidate, attempt decode pipeline and lifter
        final_sources = []
        for candidate in payload_candidates:
            data_str = candidate["data"]
            # If BootstrapDecoder already produced decoded bytes, prefer that
            decoded_bytes = None
            if "_decoded_bytes" in self.bootstrapper_metadata:
                decoded_bytes = self.bootstrapper_metadata["_decoded_bytes"]
                logger.debug("Using decoded bytes from bootstrapper metadata (len=%d)", len(decoded_bytes))
            else:
                # try python decode using BootstrapDecoder's python pipeline helper if available
                if BootstrapDecoder is not None:
                    # instantiate a helper decoder (without specifying path)
                    bd = BootstrapDecoder.__new__(BootstrapDecoder)
                    # configure minimal attributes used by its pipeline
                    bd.script_key = self.script_key or ""
                    bd.script_key_bytes = (self.script_key.encode("utf-8") if self.script_key else b"")
                    bd.debug = self.debug
                    # reuse its python pipeline method if present
                    try:
                        unescaped = bd._unescape_lua_string(data_str)
                    except Exception:
                        unescaped = data_str.encode("latin1", errors="ignore")
                    decoded, trace = bd._python_transform_pipeline(unescaped, self.bootstrapper_metadata.get("alphabet"))
                    # Attach trace to report
                    self.json_report.setdefault("bootstrap_trace", []).extend(trace)
                    if decoded:
                        decoded_bytes = decoded
                # last-resort: try direct ascii->bytes
                if decoded_bytes is None:
                    decoded_bytes = data_str.encode("latin1", errors="ignore")

            # Validate decoded_bytes
            if not self._validate_decoded_bytes(decoded_bytes):
                self.json_report["warnings"].append(f"decoded_candidate_no_lua_keywords_{candidate.get('path')}")
                # if bootstrap suggested needs_emulation and we haven't tried sandbox, do that?
                if self.bootstrapper_metadata.get("needs_emulation") and BootstrapDecoder is not None:
                    # attempt lua sandbox extraction (trusting BootstrapDecoder to have code)
                    meta = self._attempt_bootstrap_extraction(None)
                    if "_decoded_bytes" in meta:
                        decoded_bytes = meta["_decoded_bytes"]
                        logger.info("Recovered decoded bytes via sandbox fallback")
                else:
                    logger.warning("Decoded bytes failed validation; continuing best-effort.")

            # Pass decoded bytes to VM lifter and devirtualizer (user's lifter API)
            # NOTE: this is a placeholder. Replace with your lifter integration.
            try:
                # Example placeholder lifter behavior: if decoded bytes contain Lua text, use text.
                if b"function" in decoded_bytes[:4096]:
                    lua_src = decoded_bytes.decode("latin1", errors="ignore")
                else:
                    # If no textual Lua, generate placeholder and keep raw bytes in report
                    lua_src = "-- [UNPARSED VM BYTES] --\n" + f"-- decoded_bytes_len = {len(decoded_bytes)}\n"
                    self.json_report.setdefault("raw_decoded_blobs", []).append({"path": candidate.get("path"), "len": len(decoded_bytes)})
                final_sources.append(lua_src)
            except Exception as e:
                self.json_report["errors"].append(f"lifter_error_{str(e)}")
                final_sources.append(f"-- lifter error for candidate {candidate.get('path')}: {e}")

        # merge final sources
        self.lua_source = "\n\n-- CHUNK SEPARATOR --\n\n".join(final_sources)
        self.json_report["final_output_length"] = len(self.lua_source)
        self.json_report["end_time"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        return {"lua_source": self.lua_source, "json_report": self.json_report}
