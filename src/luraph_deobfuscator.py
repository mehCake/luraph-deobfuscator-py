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
from typing import Optional, Dict, Any, List

from src.utils_pkg.strings import lua_placeholder_function, normalise_lua_newlines

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
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as fh:
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

    def _extract_payload_candidates(self, text: str, allow_literal_search: bool = False) -> List[Dict[str, Any]]:
        payloads: List[Dict[str, Any]] = []
        try:
            parsed = json.loads(text)
        except Exception:
            if not allow_literal_search:
                return payloads
            matches = re.findall(r'["\']([! -~]{100,})["\']', text, re.S)
            for idx, match in enumerate(matches):
                payloads.append({"path": f"literal_{idx}", "data": match})
            return payloads

        def walk(obj, path: str = ""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    walk(value, f"{path}/{key}")
            elif isinstance(obj, list):
                for index, value in enumerate(obj):
                    walk(value, f"{path}[{index}]")
            elif isinstance(obj, str) and len(obj) >= 120:
                payloads.append({"path": path or "root", "data": obj})

        walk(parsed)
        return payloads

    def _decode_payload_candidate(self, cand: Dict[str, Any]) -> str:
        data = cand.get("data", "") or ""
        decoded = None

        if self.bootstrapper_metadata.get("_decoded_bytes"):
            decoded = self.bootstrapper_metadata["_decoded_bytes"]
            self.json_report["trace"].append("using decoded bytes from bootstrap metadata")
        else:
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
                decoded = data.encode("latin1", errors="ignore")

        if not self._validate_decoded_bytes(decoded):
            self.json_report["warnings"].append(f"candidate_{cand.get('path')}_no_lua_keywords")
            if self.bootstrapper_metadata.get("needs_emulation") and BootstrapDecoder is not None:
                meta = self._attempt_bootstrap_extraction(None, allow_lua_run=True)
                if meta.get("_decoded_bytes"):
                    decoded = meta["_decoded_bytes"]

        try:
            if lift_entry is None or devirtualize_entry is None:
                if b"function" in decoded[:4096]:
                    return normalise_lua_newlines(
                        decoded.decode("latin1", errors="ignore")
                    )
                self.json_report.setdefault("raw_decoded_blobs", []).append({"path": cand.get("path"), "len": len(decoded)})
                placeholder = lua_placeholder_function(
                    cand.get("path"),
                    [
                        f"undecoded content (size: {len(decoded)} bytes)",
                        f"path={cand.get('path')}",
                    ],
                )
                self.json_report.setdefault("warnings", []).append("placeholder_chunk_emitted")
                return normalise_lua_newlines(
                    f"-- UNPARSED BYTES (len={len(decoded)}) --\n{placeholder}"
                )

            ir = lift_entry(decoded, self.bootstrapper_metadata)
            lua_text = devirtualize_entry(ir, self.bootstrapper_metadata)
            return normalise_lua_newlines(lua_text)
        except Exception as exc:
            logger.exception("Lifting/devirtualization failed: %s", exc)
            self.json_report["errors"].append(f"lifter_error_{str(exc)}")
            placeholder = lua_placeholder_function(
                cand.get("path"),
                [
                    f"undecoded content (size: {len(decoded)} bytes)",
                    f"lifter failed: {exc}",
                    f"raw decoded len={len(decoded)}",
                ],
            )
            self.json_report.setdefault("warnings", []).append("placeholder_chunk_emitted")
            return normalise_lua_newlines(
                f"-- LIFTER FAILED: {exc} --\n{placeholder}"
            )

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

        # 2) extract payloads from input
        raw = read_text(self.input_path)
        pending = self._extract_payload_candidates(raw, allow_literal_search=True)
        if not pending:
            self.json_report["errors"].append("no_payload_candidates_found")
            self.json_report["trace"].append("no payload candidates; aborting")
            return {"lua_source": "", "json_report": self.json_report}

        seen_hashes = set()
        final_sources: List[str] = []
        iterations_metadata: List[Dict[str, Any]] = []

        for iteration in range(1, self.max_iterations + 1):
            if not pending:
                break
            self.json_report["trace"].append(f"iteration {iteration}: processing {len(pending)} payload(s)")
            iterations_metadata.append({"iteration": iteration, "payloads": len(pending)})
            next_pending: List[Dict[str, Any]] = []
            iteration_outputs: List[str] = []

            for cand in pending:
                payload_data = cand.get("data")
                if isinstance(payload_data, str):
                    key_hash = hash(payload_data)
                    if key_hash in seen_hashes:
                        continue
                    seen_hashes.add(key_hash)

                lua_text = self._decode_payload_candidate(cand)
                iteration_outputs.append(lua_text)

                for extra in self._extract_payload_candidates(lua_text, allow_literal_search=False):
                    extra_data = extra.get("data")
                    if isinstance(extra_data, str):
                        extra_hash = hash(extra_data)
                        if extra_hash in seen_hashes:
                            continue
                        seen_hashes.add(extra_hash)
                    next_pending.append(extra)

            final_sources = iteration_outputs
            pending = next_pending
            if not pending:
                break

        self.json_report["iterations"] = iterations_metadata
        self.json_report["iterations_run"] = len(iterations_metadata)

        self.lua_source = "\n\n-- CHUNK SEPARATOR --\n\n".join(final_sources)
        self.json_report["final_output_length"] = len(self.lua_source)
        self.json_report["end_time"] = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        return {"lua_source": self.lua_source, "json_report": self.json_report}
