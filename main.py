#!/usr/bin/env python3
"""
main.py - CLI entrypoint for luraph-deobfuscator-py

This version:
 - enforces --script-key for initv4 flows (unless --force is used)
 - introduces --allow-lua-run (sandbox fallback), --debug-bootstrap,
   --alphabet and --opcode-map-json overrides
 - integrates with a BootstrapDecoder API (see src/bootstrap_decoder.py)
 - writes rich JSON reports including bootstrapper_metadata
"""

import argparse
import base64
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

# TODO: these imports refer to modules you'll add/modify:
# src/bootstrap_decoder.py (BootstrapDecoder)
# src/versions/luraph_v14_4_initv4.py (InitV4Decoder)
# src/luraph_deobfuscator.py (Deobfuscator pipeline)
try:
    from src.bootstrap_decoder import BootstrapDecoder, BootstrapperExtractionResult
except Exception:
    BootstrapDecoder = None
    BootstrapperExtractionResult = None

try:
    from src.luraph_deobfuscator import Deobfuscator
except Exception:
    Deobfuscator = None

try:
    from src.utils.io_utils import chunk_lines, ensure_out, write_b64_text, write_json, write_text
    from src.utils.lph_decoder import try_xor
except Exception:
    chunk_lines = None  # type: ignore[assignment]
    ensure_out = None  # type: ignore[assignment]
    write_b64_text = None  # type: ignore[assignment]
    write_json = None  # type: ignore[assignment]
    write_text = None  # type: ignore[assignment]
    try_xor = None  # type: ignore[assignment]

# Fallback constants
DEFAULT_OUTPUT_SUFFIX_LUA = "_deob.lua"
DEFAULT_OUTPUT_SUFFIX_JSON = "_deob.json"
OUT_DIR = "out"
LOGS_DIR = os.path.join(OUT_DIR, "logs")


def _alphabet_from_metadata(metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(metadata, dict):
        return None
    alphabet = metadata.get("alphabet")
    if isinstance(alphabet, str) and alphabet.strip():
        return alphabet
    if isinstance(alphabet, dict):
        for key in ("value", "alphabet", "preview", "string"):
            value = alphabet.get(key)
            if isinstance(value, str) and value.strip():
                return value
    preview = metadata.get("alphabet_preview")
    if isinstance(preview, str) and preview.strip():
        return preview
    return None


def _normalise_opcode_map(metadata: Optional[Dict[str, Any]]) -> Dict[int, str]:
    mapping: Dict[int, str] = {}
    if not isinstance(metadata, dict):
        return mapping

    def _ingest(candidate: Optional[Dict[Any, Any]]) -> None:
        if not isinstance(candidate, dict):
            return
        for key, value in candidate.items():
            try:
                if isinstance(key, str) and key.lower().startswith("0x"):
                    opcode = int(key, 16)
                elif isinstance(key, str):
                    opcode = int(key)
                else:
                    opcode = int(key)
            except (TypeError, ValueError):
                continue
            mapping[opcode] = str(value).strip() or f"OP_{opcode:02X}"

    _ingest(metadata.get("opcode_map"))
    dispatch = metadata.get("opcode_dispatch")
    if isinstance(dispatch, dict):
        _ingest(dispatch.get("mapping"))
    sample = metadata.get("opcode_map_sample")
    if isinstance(sample, list):
        for entry in sample:
            if not isinstance(entry, dict):
                continue
            for key, value in entry.items():
                try:
                    opcode = int(str(key), 16) if str(key).lower().startswith("0x") else int(str(key))
                except (TypeError, ValueError):
                    continue
                mapping.setdefault(opcode, str(value))
    return mapping


def _write_bootstrap_blob(
    decoded_bytes: Optional[bytes],
    script_key: Optional[str],
    *,
    emit_binary: bool,
) -> None:
    if ensure_out is None or write_b64_text is None or try_xor is None:
        return
    out_dir = ensure_out(OUT_DIR)
    logs_dir = ensure_out(out_dir, "logs")
    raw = bytes(decoded_bytes or b"")
    if not raw:
        if write_text is not None:
            write_text(os.path.join(out_dir, "bootstrap_blob.b64.txt"), "# no bootstrap blob decoded\n")
        return
    preferred = raw
    if script_key:
        key_bytes = script_key.encode("utf-8")
        xored = try_xor(raw, key_bytes)
        lower = xored.lower()
        if b"function" in lower or b"\x1blua" in lower:
            preferred = xored
    write_b64_text(os.path.join(out_dir, "bootstrap_blob.b64.txt"), preferred)
    if emit_binary and raw:
        with open(os.path.join(logs_dir, "bootstrap_blob.bin"), "wb") as handle:
            handle.write(raw)
        if preferred != raw:
            with open(os.path.join(logs_dir, "bootstrap_blob_xored.bin"), "wb") as handle:
                handle.write(preferred)


def _write_alphabet_file(metadata: Optional[Dict[str, Any]]) -> None:
    if ensure_out is None or write_text is None:
        return
    out_dir = ensure_out(OUT_DIR)
    value = _alphabet_from_metadata(metadata) or "# alphabet not available\n"
    if not value.endswith("\n"):
        value += "\n"
    write_text(os.path.join(out_dir, "alphabet.txt"), value)


def _write_opcode_map_file(metadata: Optional[Dict[str, Any]]) -> None:
    if ensure_out is None or write_text is None:
        return
    out_dir = ensure_out(OUT_DIR)
    mapping = _normalise_opcode_map(metadata)
    if not mapping:
        contents = "# opcode map not available\n"
    else:
        lines = [f"0x{opcode:02X} -> {mnemonic}" for opcode, mnemonic in sorted(mapping.items())]
        contents = "\n".join(lines) + "\n"
    write_text(os.path.join(out_dir, "opcode_map.txt"), contents)


def _write_unpacked_json(report: Dict[str, Any]) -> None:
    if ensure_out is None or write_json is None:
        return
    out_dir = ensure_out(OUT_DIR)
    payload: Dict[str, Any] = {}
    meta = report.get("bootstrapper_metadata")
    if isinstance(meta, dict):
        raw = meta.get("_decoded_bytes")
        if isinstance(raw, (bytes, bytearray)) and raw:
            payload["bootstrap_blob_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
        for key in ("unpackedData", "unpacked_data"):
            if key in meta and meta[key]:
                payload["unpacked"] = meta[key]
                break
    raw_blobs = report.get("raw_decoded_blobs")
    if raw_blobs:
        payload["raw_decoded_blobs"] = raw_blobs
    if not payload:
        payload["note"] = "unpackedData not available"
    write_json(os.path.join(out_dir, "unpacked.json"), payload)


def _write_lua_artifacts(lua_source: str, chunk_size: int, prefix: str) -> None:
    if ensure_out is None or write_text is None or chunk_lines is None:
        return
    out_dir = ensure_out(OUT_DIR)
    if not lua_source:
        write_text(os.path.join(out_dir, f"{prefix}.lua"), "")
        return
    chunks = chunk_lines(lua_source, max(1, chunk_size))
    if len(chunks) == 1:
        write_text(os.path.join(out_dir, f"{prefix}.lua"), chunks[0])
        return
    for index, chunk in enumerate(chunks, start=1):
        write_text(os.path.join(out_dir, f"{prefix}.part{index:02d}.lua"), chunk)


def _sanitise_bootstrap_metadata(metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(metadata, dict):
        return metadata
    clean: Dict[str, Any] = {}
    for key, value in metadata.items():
        if key == "_decoded_bytes" and isinstance(value, (bytes, bytearray)):
            clean["bootstrap_blob_b64"] = base64.b64encode(bytes(value)).decode("ascii")
        elif key == "_vm_bytecode_bytes" and isinstance(value, (bytes, bytearray)):
            clean["vm_bytecode_b64"] = base64.b64encode(bytes(value)).decode("ascii")
        elif isinstance(value, dict):
            clean[key] = _sanitise_bootstrap_metadata(value) or {}
        elif isinstance(value, list):
            clean[key] = [
                _sanitise_bootstrap_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            clean[key] = value
    return clean

# CLI
def build_parser():
    p = argparse.ArgumentParser(prog="luraph-deobfuscator", description="Luraph deobfuscator")
    p.add_argument("inputs", nargs="+", help="Input file(s) -- JSON or Lua")
    p.add_argument("--script-key", help="Script key required for initv4 decoding")
    p.add_argument("--bootstrapper", help="Path to initv4.lua bootstrapper")
    p.add_argument("--allow-lua-run", action="store_true", help="Permit sandboxed Lua fallback for bootstrap extraction")
    p.add_argument("--debug-bootstrap", action="store_true", help="Dump raw bootstrapper matches and debug logs")
    p.add_argument("--alphabet", help="Force a manual initv4 alphabet (override extraction)")
    p.add_argument("--opcode-map-json", help="Path to opcode map JSON to use instead of extraction")
    p.add_argument("--yes", "-y", action="store_true", help="Auto-confirm prompts")
    p.add_argument("--force", action="store_true", help="Force continue despite warnings")
    p.add_argument("--format", choices=("lua", "json", "both"), default="both", help="Output format")
    p.add_argument("--out", "-o", help="Explicit output path (single input)")
    p.add_argument("--max-iterations", type=int, default=5, help="Max nested decode iterations")
    p.add_argument("--jobs", type=int, default=1, help="Parallel jobs (future)")
    p.add_argument("--verbose", "-v", action="count", default=0, help="Verbose logging (-v, -vv)")
    p.add_argument(
        "--emit-binary",
        action="store_true",
        help="Also write binary bootstrap blobs to out/logs (requires --no-emit-readable-only)",
    )
    p.add_argument(
        "--emit-readable-only",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Write only text/JSON/Lua artifacts (default: True)",
    )
    p.add_argument("--chunk-lines", type=int, default=800, help="Maximum lines per Lua chunk in out/ directory")
    p.add_argument("--output-prefix", default="deobfuscated", help="Base filename for Lua artifacts in out/")
    p.add_argument(
        "--artifact-only",
        action="store_true",
        help="Emit readable artifacts without running the full deobfuscation pipeline",
    )
    return p

def setup_logging(verbosity: int):
    level = logging.WARNING
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    # ensure logs dir exists
    os.makedirs(LOGS_DIR, exist_ok=True)

def prompt_confirm(msg: str, auto_yes: bool):
    if auto_yes:
        logging.debug("Auto-confirm enabled; assuming YES for: %s", msg)
        return True
    try:
        r = input(f"{msg} (Y/N): ").strip().lower()
        return r in ("y", "yes")
    except KeyboardInterrupt:
        return False

def write_report(output_path: Path, report: dict):
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    logging.info("Wrote report %s", output_path)

def load_opcode_map(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # validate basic shape: keys numeric or hex-like
        if not isinstance(data, dict):
            raise ValueError("opcode map must be a JSON object")
        return data
    except Exception as e:
        logging.error("Failed to load opcode map %s: %s", path, e)
        raise

def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    if not Deobfuscator:
        logging.error("Deobfuscator core module not found. Make sure src/luraph_deobfuscator.py exists.")
        sys.exit(2)

    effective_emit_binary = bool(args.emit_binary and not args.emit_readable_only)

    # Prepare global metadata container
    global_meta = {
        "cmd": " ".join(sys.argv),
        "start_time": datetime.utcnow().isoformat() + "Z",
        "bootstrapper_used": args.bootstrapper or None,
        "script_key_provided": bool(args.script_key)
    }

    # Load manual overrides early
    manual_alphabet = args.alphabet
    manual_opcode_map = None
    if args.opcode_map_json:
        manual_opcode_map = load_opcode_map(args.opcode_map_json)

    # iterate inputs sequentially (one-by-one as requested)
    for inpath in args.inputs:
        path = Path(inpath)
        if not path.exists():
            logging.error("Input does not exist: %s", inpath)
            continue

        base_name = path.stem
        out_lua = Path(args.out) if args.out else path.with_name(f"{path.stem}{DEFAULT_OUTPUT_SUFFIX_LUA}")
        out_json = path.with_name(f"{path.stem}{DEFAULT_OUTPUT_SUFFIX_JSON}")

        report = {
            "input": str(path),
            "start_time": datetime.utcnow().isoformat() + "Z",
            "warnings": [],
            "errors": [],
            "bootstrapper_metadata": None,
            "passes": {},
        }

        # 1) Detect version and whether initv4 handling is required
        det = Deobfuscator.detect_version(str(path))
        report["detected_version"] = det.get("name")
        report["detection_confidence"] = det.get("confidence", 0.0)
        logging.info("Detected version: %s (confidence %.2f)", det.get("name"), det.get("confidence", 0.0))

        # If version suggests v14.4.1 / initv4, require a script key
        handler_name = det.get("handler")
        version_name = det.get("name", "")
        needs_key = handler_name == "initv4" or version_name == "luraph_v14_4_1"
        if needs_key and not args.script_key and not args.force:
            msg = f"Detected Luraph initv4 (v14.4.x) which requires --script-key. Abort?"
            if not prompt_confirm("No --script-key provided. Abort run? (Y to abort)", auto_yes=args.yes):
                logging.info("User chose to continue without script key (--force recommended).")
            else:
                logging.error("Missing required --script-key for initv4. Use --script-key <KEY> or --force to continue.")
                report["errors"].append("missing_script_key")
                write_report(out_json, report)
                continue

        # 2) Bootstrapper extraction
        bootstrap_metadata = None
        bootstrap_result = None
        if manual_alphabet or manual_opcode_map:
            logging.info("Using manual overrides for alphabet/opcode map.")
            bootstrap_metadata = {
                "alphabet": manual_alphabet,
                "opcode_map": manual_opcode_map,
                "extraction_method": "manual_override",
                "confidence": 1.0
            }
        else:
            # if a bootstrapper path was given or auto-locate
            bootstrap_path = args.bootstrapper
            if not bootstrap_path:
                # try auto locate in same dir as input or repo root
                candidate = Path("initv4.lua")
                if candidate.exists():
                    bootstrap_path = str(candidate)
                else:
                    logging.debug("No bootstrapper provided and none auto-located.")
                    bootstrap_path = None

            if bootstrap_path:
                if BootstrapDecoder is None:
                    logging.warning("BootstrapDecoder module not found; skipping bootstrap extraction. Provide manual maps via flags.")
                    report["warnings"].append("bootstrap_decoder_missing")
                else:
                    logging.info("Attempting bootstrapper extraction using %s", bootstrap_path)
                    bd = BootstrapDecoder(
                        bootstrap_path,
                        script_key=args.script_key,
                        debug=args.debug_bootstrap,
                        emit_binary=effective_emit_binary,
                        out_dir=OUT_DIR,
                    )
                    try:
                        bootstrap_result = bd.run_full_extraction(allow_lua_run=args.allow_lua_run)
                        logging.debug("Bootstrapper extraction result: %s", getattr(bootstrap_result, "summary", "<no summary>"))
                        bootstrap_metadata = bootstrap_result.metadata_dict
                    except Exception as e:
                        logging.exception("Bootstrapper extraction failed: %s", e)
                        report["warnings"].append("bootstrap_extraction_failed")
                        if not args.force:
                            logging.error("Bootstrap extraction failed and --force not provided; aborting this input.")
                            report["errors"].append("bootstrap_extraction_failed")
                            write_report(out_json, report)
                            continue
                        else:
                            logging.warning("Continuing despite bootstrap extraction failure (--force).")

        report["bootstrapper_metadata"] = bootstrap_metadata

        # 3) Run full deobfuscation pipeline
        try:
            dec = Deobfuscator(
                input_path=str(path),
                script_key=args.script_key,
                bootstrapper_metadata=bootstrap_metadata,
                max_iterations=args.max_iterations,
                debug=args.verbose >= 1,
            )
            result = dec.run()
            # result should contain: lua_source (str), json_report (dict)
            # write outputs
            if ensure_out is not None:
                ensure_out(OUT_DIR)
                ensure_out(LOGS_DIR)

            decoded_blob_bytes: Optional[bytes] = None
            if isinstance(bootstrap_metadata, dict):
                raw_value = bootstrap_metadata.get("_decoded_bytes")
                if isinstance(raw_value, (bytes, bytearray)):
                    decoded_blob_bytes = bytes(raw_value)
            if decoded_blob_bytes is None and isinstance(bootstrap_result, BootstrapperExtractionResult):
                if isinstance(bootstrap_result.decoded_bytes, (bytes, bytearray)):
                    decoded_blob_bytes = bytes(bootstrap_result.decoded_bytes)

            _write_bootstrap_blob(decoded_blob_bytes, args.script_key, emit_binary=effective_emit_binary)
            _write_alphabet_file(bootstrap_metadata)
            _write_opcode_map_file(bootstrap_metadata)

            clean_bootstrap_meta = _sanitise_bootstrap_metadata(bootstrap_metadata)

            if args.artifact_only:
                placeholder_source = "-- artifact-only run (readable outputs only)\n"
                if args.format in ("lua", "both"):
                    with open(out_lua, "w", encoding="utf-8") as fh:
                        fh.write(placeholder_source)
                if args.format in ("json", "both"):
                    final_report = {
                        "bootstrapper_metadata": clean_bootstrap_meta or {},
                        "invocation": global_meta,
                        "artifact_only": True,
                    }
                    write_report(out_json, final_report)
                    _write_unpacked_json(final_report)
                else:
                    _write_unpacked_json({
                        "bootstrapper_metadata": clean_bootstrap_meta or {},
                        "artifact_only": True,
                    })
                _write_lua_artifacts(placeholder_source, args.chunk_lines, args.output_prefix)
                logging.info("Artifact-only mode enabled; skipping deobfuscation for %s", path)
                continue

            if args.format in ("lua", "both"):
                with open(out_lua, "w", encoding="utf-8") as fh:
                    fh.write(result.get("lua_source", ""))
                logging.info("Wrote deobfuscated Lua to %s", out_lua)
            if args.format in ("json", "both"):
                # merge pipeline report with bootstrapper metadata
                final_report = result.get("json_report", {})
                final_report.setdefault("bootstrapper_metadata", clean_bootstrap_meta)
                final_report["invocation"] = global_meta
                write_report(out_json, final_report)
                _write_unpacked_json(final_report)
            else:
                report = result.get("json_report", {})
                if isinstance(report, dict):
                    report.setdefault("bootstrapper_metadata", clean_bootstrap_meta)
                    _write_unpacked_json(report)

            lua_source = result.get("lua_source", "")
            if isinstance(lua_source, str):
                _write_lua_artifacts(lua_source, args.chunk_lines, args.output_prefix)

            logging.info("Completed processing %s", path)
        except Exception as e:
            logging.exception("Unhandled error during deobfuscation: %s", e)
            report["errors"].append(str(e))
            write_report(out_json, report)
            continue

    logging.info("All inputs processed.")

if __name__ == "__main__":
    main()
