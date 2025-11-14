#!/usr/bin/env python3
"""
Advanced Lua Deobfuscator - Fixed Entry Point with Method Checks

Comprehensive tool for inspecting and deobfuscating Lua code with pattern
recognition and VM-aware analysis.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Add src directory to path so we can import the internal modules when the
# script is executed from the repository root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

try:
    from deobfuscator import LuaDeobfuscator
    from utils import create_output_path, setup_logging, validate_file
except ImportError as e:  # pragma: no cover - import-time guard
    print(f"Error importing modules: {e}")
    sys.exit(1)


def load_config() -> dict:
    """Load configuration from config.json if present."""
    config_path = Path(__file__).parent / "config.json"
    if not config_path.exists():
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        logging.warning("Invalid config.json, using defaults")
        return {}


def dump_bootstrap_summary(analysis: dict, logger: logging.Logger | None = None) -> None:
    """
    Emit a compact summary of any bootstrap/VM metadata discovered during analysis.

    This is *reporting only*: it does not attempt to peel away additional protection
    layers. The goal is to surface the structure that earlier pipeline stages have
    already annotated, so that humans and automated tests can reason about it.

    The summary is printed in two parts:
      1. A human-friendly overview.
      2. A single JSON object on one line for easy machine parsing.
    """
    log = logger or logging.getLogger(__name__)

    if not isinstance(analysis, dict):
        log.warning("dump_bootstrap_summary: analysis result is not a dict; skipping")
        return

    # Try a few common keys that earlier passes are expected to fill in.
    bootstrap_meta = analysis.get("bootstrap", {}) or {}
    version = analysis.get("version") or analysis.get("detected_version")
    vm_variant = analysis.get("vm_variant") or analysis.get("primary_vm_variant")

    state_machines = (
        bootstrap_meta.get("state_machines")
        or analysis.get("state_machines")
        or []
    )
    constant_cache = (
        bootstrap_meta.get("constant_cache")
        or analysis.get("constant_cache")
        or {}
    )
    primitive_helpers = (
        bootstrap_meta.get("primitive_helpers")
        or analysis.get("primitive_helpers")
        or {}
    )
    prototype_loader = (
        bootstrap_meta.get("prototype_loader")
        or analysis.get("prototype_loader")
        or {}
    )

    # Human-readable overview.
    print("\n" + "=" * 60)
    print("BOOTSTRAP / VM STRUCTURE SUMMARY")
    print("=" * 60)
    if version:
        print(f"Detected version: {version}")
    if vm_variant:
        print(f"VM variant:       {vm_variant}")

    print("\nState machines:")
    if isinstance(state_machines, (list, tuple)) and state_machines:
        print(f"  Count: {len(state_machines)}")
        for idx, sm in enumerate(state_machines[:5], start=1):
            label = getattr(sm, "name", None) or getattr(sm, "id", None) or str(sm)
            print(f"  [{idx}] {label}")
        if len(state_machines) > 5:
            print(f"  ... ({len(state_machines) - 5} more)")
    else:
        print("  (none recorded)")

    print("\nConstant cache layout:")
    if isinstance(constant_cache, dict) and constant_cache:
        print(f"  Slots: {len(constant_cache)}")
        preview_keys = list(constant_cache.keys())[:5]
        print(f"  Sample keys: {preview_keys}")
    else:
        print("  (no constant cache metadata)")

    print("\nPrimitive helper table:")
    if isinstance(primitive_helpers, dict) and primitive_helpers:
        print(f"  Helpers: {len(primitive_helpers)}")
        sample = list(primitive_helpers.items())[:5]
        for name, info in sample:
            print(f"  - {name}: {type(info).__name__}")
        if len(primitive_helpers) > 5:
            print(f"  ... ({len(primitive_helpers) - 5} more)")
    else:
        print("  (no helper table metadata)")

    print("\nPrototype loader structure:")
    if isinstance(prototype_loader, dict) and prototype_loader:
        keys = list(prototype_loader.keys())
        print(f"  Fields: {keys}")
    else:
        print("  (no prototype loader metadata)")

    # Machine-readable JSON on a single line so tests and tools can grep it.
    summary = {
        "version": version,
        "vm_variant": vm_variant,
        "state_machine_count": len(state_machines)
        if isinstance(state_machines, (list, tuple))
        else 0,
        "constant_cache_slots": len(constant_cache)
        if isinstance(constant_cache, dict)
        else 0,
        "primitive_helper_count": len(primitive_helpers)
        if isinstance(primitive_helpers, dict)
        else 0,
        "prototype_loader_keys": list(prototype_loader.keys())
        if isinstance(prototype_loader, dict)
        else [],
        # Optionally expose the raw structures if earlier stages want to
        # consume them directly. They should remain JSON-serialisable.
        "state_machines": state_machines,
        "constant_cache": constant_cache,
        "primitive_helpers": primitive_helpers,
        "prototype_loader": prototype_loader,
    }

    try:
        print("\nBOOTSTRAP_JSON_SUMMARY " + json.dumps(summary, separators=(",", ":")))
    except TypeError:
        # If something in the structures is not JSON-serialisable, fall back
        # to a simplified summary rather than crashing.
        log.warning(
            "dump_bootstrap_summary: non-serialisable bootstrap metadata; "
            "falling back to simplified JSON."
        )
        safe_summary = {
            k: v
            for k, v in summary.items()
            if isinstance(v, (str, int, float, bool, type(None), list, dict))
        }
        print(
            "\nBOOTSTRAP_JSON_SUMMARY " + json.dumps(safe_summary, separators=(",", ":"))
        )


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Advanced Lua Deobfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python run.py script.lua                    # Basic deobfuscation
  python run.py script.lua --analyze          # Analysis mode only
  python run.py script.lua --analyze --dump-bootstrap
                                              # Analysis + bootstrap summary
  python run.py script.lua -o clean.lua       # Specify output file
  python run.py script.lua --verbose          # Verbose output
  python run.py script.lua --method luraph    # Specific method
""",
    )

    parser.add_argument("input", help="Input Lua file to deobfuscate")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Run analysis only (no rewriting of the input file)",
    )
    parser.add_argument(
        "--dump-bootstrap",
        action="store_true",
        help=(
            "After analysis, print a compact summary of any bootstrap/VM "
            "metadata (state machines, constant cache, helper table, "
            "prototype loader layout)."
        ),
    )
    parser.add_argument(
        "--method",
        choices=["generic", "luraph", "ironbrew"],
        help="Hint to the deobfuscation engine about the obfuscation style",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--config",
        help="Optional configuration file path (JSON). "
        "If provided, values are merged into config.json.",
    )

    return parser


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging as early as possible.
    log_level = logging.DEBUG if args.verbose else logging.INFO
    try:
        setup_logging(log_level)
    except Exception:  # pragma: no cover - fallback
        logging.basicConfig(level=log_level)

    logger = logging.getLogger(__name__)

    try:
        # Validate input file.
        if not validate_file(args.input):
            logger.error("Input file not found or not readable: %s", args.input)
            return 1

        # Load configuration (base + optional override).
        config: dict = load_config()
        if args.config:
            try:
                with open(args.config, "r", encoding="utf-8") as f:
                    extra = json.load(f)
                if isinstance(extra, dict):
                    config.update(extra)
                else:
                    logger.warning("Config override is not a JSON object; ignoring")
            except Exception as e:  # pragma: no cover - defensive
                logger.warning("Failed to load config file %s: %s", args.config, e)

        # Read the input Lua file.
        logger.info("Reading input file: %s", args.input)
        with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        if not code.strip():
            logger.error("Input file is empty")
            return 1

        # Initialise the deobfuscator.
        # NOTE: The constructor is expected to be tolerant of a single
        # configuration object. If your local branch uses keyword-only
        # options instead, adapt this call accordingly.
        deobfuscator = LuaDeobfuscator(config)

        # Ensure the minimum methods we rely on are present.
        required_methods = ("analyze_code", "deobfuscate")
        if not all(hasattr(deobfuscator, m) for m in required_methods):
            logger.error(
                "LuaDeobfuscator is missing required methods: %s",
                ", ".join(m for m in required_methods if not hasattr(deobfuscator, m)),
            )
            return 1

        if args.analyze:
            logger.info("Analyzing code...")
            try:
                analysis = deobfuscator.analyze_code(code)

                print("\n" + "=" * 60)
                print("ANALYSIS RESULTS")
                print("=" * 60)
                print(f"File size: {len(code)} bytes")
                print(f"Lines of code: {len(code.splitlines())}")

                if analysis.get("obfuscated", False):
                    print("Status: OBFUSCATED")
                    confidence = analysis.get("confidence", 0)
                    if confidence <= 1:
                        print(f"Confidence: {confidence:.1%}")
                    else:
                        print(f"Confidence: {confidence}%")

                    if "method" in analysis:
                        print(f"Detected method: {analysis['method']}")

                    patterns = analysis.get("patterns") or []
                    if patterns:
                        print("\nDetected patterns:")
                        for pattern in patterns:
                            print(f" - {pattern}")

                    complexity = analysis.get("complexity") or {}
                    if complexity:
                        print("\nComplexity metrics:")
                        print(
                            f" - Control flow: {complexity.get('control_flow', 0)}"
                        )
                        print(
                            " - String obfuscation: "
                            f"{complexity.get('string_obfuscation', 0)}"
                        )
                        print(
                            " - Variable mangling: "
                            f"{complexity.get('variable_mangling', 0)}"
                        )
                else:
                    print("Status: CLEAN (not obviously obfuscated)")

                # Step 14: optional bootstrap/VM structure dump.
                if args.dump_bootstrap:
                    dump_bootstrap_summary(analysis, logger)

                print("=" * 60)
            except Exception as e:  # pragma: no cover - analysis failure
                logger.error("Analysis failed: %s", e)
                if args.verbose:
                    import traceback

                    traceback.print_exc()
                return 1
        else:
            logger.info("Starting deobfuscation process...")
            try:
                analysis = deobfuscator.analyze_code(code)

                # Optionally emit the bootstrap/VM summary before rewriting.
                if args.dump_bootstrap:
                    dump_bootstrap_summary(analysis, logger)

                if not analysis.get("obfuscated", False):
                    logger.info("Code appears clean, no deobfuscation needed")
                    deobfuscated_code = code
                else:
                    logger.info(
                        "Detected obfuscation method: %s",
                        analysis.get("method", "unknown"),
                    )
                    deobfuscated_code = deobfuscator.deobfuscate(code, args.method)

                if not args.output:
                    args.output = create_output_path(args.input)

                output_dir = os.path.dirname(args.output)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)

                logger.info("Writing deobfuscated code to: %s", args.output)
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(deobfuscated_code)

                logger.info("Deobfuscation completed successfully!")
                original_lines = len(code.splitlines())
                deobfuscated_lines = len(deobfuscated_code.splitlines())
                print("\nStatistics:")
                print(
                    f" Original size: {len(code)} bytes ({original_lines} lines)"
                )
                print(
                    " Deobfuscated size: "
                    f"{len(deobfuscated_code)} bytes ({deobfuscated_lines} lines)"
                )
            except Exception as e:  # pragma: no cover - deobfuscation failure
                logger.error("Deobfuscation failed: %s", e)
                if args.verbose:
                    import traceback

                    traceback.print_exc()
                return 1

    except KeyboardInterrupt:  # pragma: no cover - user cancel
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:  # pragma: no cover - top-level guard
        logger.error("Unexpected error: %s", e)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
