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
import json
import logging
import os
import sys
from pathlib import Path
from datetime import datetime

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

# Fallback constants
DEFAULT_OUTPUT_SUFFIX_LUA = "_deob.lua"
DEFAULT_OUTPUT_SUFFIX_JSON = "_deob.json"
LOGS_DIR = "out/logs"

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
        out_lua = Path(args.out) if args.out else Path(f"{path.stem}{DEFAULT_OUTPUT_SUFFIX_LUA}")
        out_json = Path(f"{path.stem}{DEFAULT_OUTPUT_SUFFIX_JSON}")

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
        needs_key = det.get("handler") == "initv4" or "14.4" in det.get("name", "")
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
                    bd = BootstrapDecoder(bootstrap_path, script_key=args.script_key, debug=args.debug_bootstrap)
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
            if args.format in ("lua", "both"):
                with open(out_lua, "w", encoding="utf-8") as fh:
                    fh.write(result.get("lua_source", ""))
                logging.info("Wrote deobfuscated Lua to %s", out_lua)
            if args.format in ("json", "both"):
                # merge pipeline report with bootstrapper metadata
                final_report = result.get("json_report", {})
                final_report.setdefault("bootstrapper_metadata", bootstrap_metadata)
                final_report["invocation"] = global_meta
                write_report(out_json, final_report)
            logging.info("Completed processing %s", path)
        except Exception as e:
            logging.exception("Unhandled error during deobfuscation: %s", e)
            report["errors"].append(str(e))
            write_report(out_json, report)
            continue

    logging.info("All inputs processed.")

if __name__ == "__main__":
    main()
