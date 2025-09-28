"""
src/luraph_deobfuscator.py  -- updated to integrate vm_lift and vm_devirtualize

This version:
 - Uses the BootstrapDecoder (if present) to extract alphabet/opcode metadata
 - Calls vm_lift.lift_entry and vm_devirtualize.devirtualize_entry to convert
   decoded bytecode into a Lua source string
 - Captures detailed traces and errors into json_report
 - Falls back to safe placeholders if lifter/devirtualizer fail
"""

import os
import re
import json
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("Deobfuscator")
logger.setLevel(logging.DEBUG)

# Attempt to import the BootstrapDecoder and the VM passes we created
try:
    from src.bootstrap_decoder import BootstrapDecoder, BootstrapperExtractionResult
except Exception:
    BootstrapDecoder = None
    BootstrapperExtractionResult = None

try:
    from src.passes.vm_lift import lift_entry, LiftError
except Exception:
    lift_entry = None
    LiftError = None

try:
    from src.passes.vm_devirtualize import devirtualize_entry, DevirtualizeError
except Exception:
    devirtualize_entry = None
    DevirtualizeError = None

# small helper to read file text
def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return fh.read()

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

        self.lua_source = ""
        self.json_report: Dict[str, Any] = {
            "input": input_path,
            "script_key_used": bool(script_key),
            "bootstrapper_metadata": self.bootstrapper_metadata,
            "passes": [],
            "warnings": [],
            "errors": [],
            "trace": []
        }

    @staticmethod
    def detect_version(input_path: str) -> Dict[str, Any]:
        try:
            src = read_text(input_path)
            # Reuse the simple heuristic used previously
            if re.search(r"luraph[\s-_]*v?14(?:\.4(?:\.1)?)?", src, re.IGNORECASE):
                return {"name": "luraph_v14_4_initv4", "handler": "initv4", "confidence": 0.95}
            if "script_key" in src and "init_fn" in src:
                return {"name": "luraph_v14_4_initv4", "handler": "initv4", "confidence": 0.6}
            return {"name": "unknown", "handler": None, "confidence": 0.0}
        except Exception as e:
            logger.debug("detect_version failed: %s", e)
            return {"name": "unknown", "handler": None, "confidence": 0.0}

    def _attempt_bootstrap_extraction(self, bootstrap_path: Optional[str], allow_lua_run: bool) -> Dict[str, Any]:
        meta = {}
        if BootstrapDecoder is None:
            logger.warning("BootstrapDecoder not found; skipping bootstrap extraction")
            self.json_report["warnings"].append("bootstrap_decoder_missing")
            return meta

        # Run the bootstrap decoder (it will try python-first and optionally lua fallback)
        bd = BootstrapDecoder(bootstrap_path, script_key=self.script_key, debug=self.debug)
        res: BootstrapperExtractionResult = bd.run_full_extraction(allow_lua_run=allow_lua_run)
        meta.update(res.metadata_dict or {})
        meta["_trace"] = res.trace
        meta["_decoded_bytes"] = res.decoded_bytes if res.decoded_bytes is not None else None
        meta["needs_emulation"] = res.needs_emulation
        return meta

    def _validate_decoded_bytes(self, b: bytes) -> bool:
        if not b:
            return False
        sample = b[:4096].lower()
        return b"function" in sample or b"local " in sample or b"init_fn" in sample

    def run(self) -> Dict[str, Any]:
        self.json_report["start_time"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        self.json_report["trace"].append("deobfuscation started")

        # 1) ensure we have bootstrap metadata if possible
        if not self.bootstrapper_metadata:
            # try to find initv4.lua alongside input
            candidate = os.path.join(os.path.dirname(self.input_path) or ".", "initv4.lua")
            if os.path.exists(candidate):
                self.json_report["trace"].append(f"auto-locating bootstrapper at {candidate}")
                meta = self._attempt_bootstrap_extraction(candidate, allow_lua_run=False)
                self.bootstrapper_metadata.update(meta)
                self.json_report["passes"].append({"bootstrap_extraction": True, "bootstrap_path": candidate})
            else:
                self.json_report["warnings"].append("no_bootstrap_found_adjacent")

        # 1.1 If metadata incomplete and we are allowed, attempt a Lua sandbox extraction to improve results
        if self.bootstrapper_metadata.get("needs_emulation") and BootstrapDecoder is not None:
            self.json_report["trace"].append("bootstrap metadata marked needs_emulation; attempting sandbox extraction")
            # try extraction with allow_lua_run True
            candidate = os.path.join(os.path.dirname(self.input_path) or ".", "initv4.lua")
            meta2 = self._attempt_bootstrap_extraction(candidate if os.path.exists(candidate) else None, allow_lua_run=True)
            # merge non-empty fields
            for k, v in meta2.items():
                if v:
                    self.bootstrapper_metadata[k] = v
            self.json_report["passes"].append({"bootstrap_extraction_sandbox": True, "bootstrap_path": candidate})

        # 2) find payload candidates (JSON or raw lua)
        raw = read_text(self.input_path)
        payloads = []
        try:
            j = json.loads(raw)
            # collect string fields >= 120 chars
            def walk(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        walk(v, f"{path}/{k}")
                elif isinstance(obj, list):
                    for i, v in enumerate(obj):
                        walk(v, f"{path}[{i}]")
                elif isinstance(obj, str):
                    if len(obj) >= 120:
                        payloads.append({"path": path, "data": obj})
            walk(j)
        except Exception:
            # raw lua: find long printable runs
            matches = re.findall(r'["\']([! -~]{100,})["\']', raw, re.S)
            for i, s in enumerate(matches):
                payloads.append({"path": f"literal_{i}", "data": s})

        if not payloads:
            self.json_report["errors"].append("no_payload_candidates_found")
            self.json_report["trace"].append("no payload candidates; aborting")
            return {"lua_source": "", "json_report": self.json_report}

        # 3) decode and lift each payload
        sources = []
        for cand in payloads:
            data = cand["data"]
            decoded = None

            # prefer any decoded bytes from bootstrap metadata
            if self.bootstrapper_metadata.get("_decoded_bytes"):
                decoded = self.bootstrapper_metadata["_decoded_bytes"]
                self.json_report["trace"].append("using decoded bytes from bootstrap metadata")
            else:
                # try reusing BootstrapDecoder's python pipeline (if present)
                if BootstrapDecoder is not None:
                    bd = BootstrapDecoder.__new__(BootstrapDecoder)
                    bd.script_key = self.script_key or ""
                    bd.script_key_bytes = (self.script_key.encode("utf-8") if self.script_key else b"")
                    bd.debug = self.debug
                    try:
                        unescaped = bd._unescape_lua_string(data)
                    except Exception:
                        unescaped = data.encode("latin1", errors="ignore")
                    decoded_try, trace = bd._python_transform_pipeline(unescaped, self.bootstrapper_metadata.get("alphabet"))
                    self.json_report.setdefault("bootstrap_trace", []).extend(trace)
                    if decoded_try:
                        decoded = decoded_try

                if decoded is None:
                    # fall back to raw bytes (best-effort)
                    decoded = data.encode("latin1", errors="ignore")

            # 3.1 validate decoded
            valid = self._validate_decoded_bytes(decoded)
            if not valid:
                self.json_report["warnings"].append(f"candidate_{cand.get('path')}_no_lua_keywords")
                # if bootstrap suggested we need emulation, try sandbox extraction now (best-effort)
                if self.bootstrapper_metadata.get("needs_emulation") and BootstrapDecoder is not None:
                    meta = self._attempt_bootstrap_extraction(None, allow_lua_run=True)
                    if meta.get("_decoded_bytes"):
                        decoded = meta["_decoded_bytes"]

            # 4) pass decoded bytes to lifter & devirtualizer
            try:
                if lift_entry is None or devirtualize_entry is None:
                    # missing lifter modules; fall back to direct text if looks textual
                    if b"function" in decoded[:4096]:
                        lua_text = decoded.decode("latin1", errors="ignore")
                    else:
                        lua_text = f"-- UNPARSED BYTES (len={len(decoded)}) --\n"
                        self.json_report.setdefault("raw_decoded_blobs", []).append({"path": cand.get("path"), "len": len(decoded)})
                    sources.append(lua_text)
                    self.json_report["trace"].append("lifter or devirtualizer modules missing; used fallback textual heuristic")
                else:
                    # lift to IR then devirtualize
                    ir = lift_entry(decoded, self.bootstrapper_metadata)
                    lua_text = devirtualize_entry(ir, self.bootstrapper_metadata)
                    sources.append(lua_text)
                    self.json_report["trace"].append(f"lifted and devirtualized candidate {cand.get('path')}")
            except Exception as e:
                logger.exception("Lifting/devirtualization failed: %s", e)
                self.json_report["errors"].append(f"lifter_error_{str(e)}")
                # fallback: provide annotated raw bytes
                fallback = f"-- LIFTER FAILED: {e} --\n-- raw decoded len={len(decoded)} --\n"
                sources.append(fallback)
                continue

        # merge and finalize
        self.lua_source = "\n\n-- CHUNK SEPARATOR --\n\n".join(sources)
        self.json_report["final_output_length"] = len(self.lua_source)
        self.json_report["end_time"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        return {"lua_source": self.lua_source, "json_report": self.json_report}
