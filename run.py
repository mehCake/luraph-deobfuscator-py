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
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Iterable, Optional

# Add src directory to path so we can import the internal modules when the
# script is executed from the repository root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

try:
    from deobfuscator import LuaDeobfuscator
    from pattern_analyzer import (
        Constant,
        SerializedChunk,
        SerializedChunkDescriptor,
        SerializedPrototype,
        infer_constant_kind,
        make_constant,
    )
    from src.versions import v14_3_loader
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


def _version_tokens(value: Any) -> list[str]:
    tokens: list[str] = []
    if value is None:
        return tokens
    if isinstance(value, str):
        tokens.append(value)
        return tokens
    if isinstance(value, Mapping):
        for key in ("name", "label", "version", "detected_version", "variant"):
            if key in value:
                tokens.extend(_version_tokens(value[key]))
        major = value.get("major")
        minor = value.get("minor")
        if major is not None:
            if minor is not None:
                tokens.append(f"{major}.{minor}")
            else:
                tokens.append(str(major))
        features = value.get("features")
        if isinstance(features, (list, tuple, set)):
            for feature in features:
                tokens.extend(_version_tokens(feature))
        return tokens
    if hasattr(value, "name"):
        tokens.extend(_version_tokens(getattr(value, "name")))
    if hasattr(value, "major") and hasattr(value, "minor"):
        try:
            tokens.append(f"{getattr(value, 'major')}.{getattr(value, 'minor')}")
        except Exception:  # pragma: no cover - defensive
            pass
    if isinstance(value, (list, tuple, set)):
        for entry in value:
            tokens.extend(_version_tokens(entry))
        return tokens
    tokens.append(str(value))
    return tokens


def _analysis_is_v14_3(analysis: Mapping[str, Any]) -> bool:
    version_hints: list[Any] = []
    for key in ("version", "detected_version", "primary_vm_variant"):
        if key in analysis:
            version_hints.append(analysis[key])
    for key in ("vm_variants", "version_features"):
        if key in analysis and isinstance(analysis[key], Sequence) and not isinstance(
            analysis[key], (str, bytes, bytearray)
        ):
            version_hints.extend(list(analysis[key]))
    for hint in version_hints:
        for token in _version_tokens(hint):
            lowered = token.lower()
            if "14.3" in lowered or "14_3" in lowered:
                return True
    return False


def _coerce_constant_entry(value: Any) -> Constant:
    if isinstance(value, Constant):
        return value
    if isinstance(value, Mapping) and "value" in value:
        metadata = value.get("metadata") if isinstance(value.get("metadata"), Mapping) else {}
        kind = value.get("kind")
        raw_value = value.get("raw_value")
        inferred_kind = kind or infer_constant_kind(value.get("value"))
        return Constant(
            kind=inferred_kind,
            value=value.get("value"),
            raw_value=raw_value,
            metadata=dict(metadata),
        )
    return make_constant(value)


def _coerce_serialized_prototype(value: Any) -> Optional[SerializedPrototype]:
    if isinstance(value, SerializedPrototype):
        return value
    if isinstance(value, Mapping):
        constants_raw = value.get("constants") or []
        instructions_raw = value.get("instructions") or []
        prototypes_raw = value.get("prototypes") or []
        constants = [_coerce_constant_entry(entry) for entry in constants_raw]
        instructions = list(instructions_raw)
        prototypes = []
        for child in prototypes_raw:
            coerced = _coerce_serialized_prototype(child)
            if coerced is not None:
                prototypes.append(coerced)
        return SerializedPrototype(
            constants=constants,
            instructions=instructions,
            prototypes=prototypes,
        )
    return None


def _coerce_serialized_chunk(value: Any) -> Optional[SerializedChunk]:
    if isinstance(value, SerializedChunk):
        return value
    if isinstance(value, Mapping):
        descriptor_value = value.get("descriptor")
        if isinstance(descriptor_value, SerializedChunkDescriptor):
            descriptor = descriptor_value
        elif isinstance(descriptor_value, Mapping):
            try:
                descriptor = SerializedChunkDescriptor(**descriptor_value)
            except Exception:  # pragma: no cover - defensive
                return None
        else:
            return None
        prototypes = []
        for entry in value.get("prototypes", []) or []:
            proto = _coerce_serialized_prototype(entry)
            if proto is not None:
                prototypes.append(proto)
        prototype_count = value.get("prototype_count") or len(prototypes)
        return SerializedChunk(
            descriptor=descriptor,
            prototype_count=prototype_count,
            prototypes=prototypes,
        )
    return None


def _extract_serialized_chunk(analysis: Mapping[str, Any]) -> Optional[SerializedChunk]:
    def _from_candidate(candidate: Any) -> Optional[SerializedChunk]:
        if candidate is None:
            return None
        return _coerce_serialized_chunk(candidate)

    for key in ("serialized_chunk_model", "serialized_chunk", "chunk"):
        chunk = _from_candidate(analysis.get(key))
        if chunk is not None:
            return chunk

    bootstrap = analysis.get("bootstrap")
    if bootstrap is not None:
        for key in ("serialized_chunk_model", "serialized_chunk", "chunk"):
            candidate = None
            if isinstance(bootstrap, Mapping):
                candidate = bootstrap.get(key)
            else:
                candidate = getattr(bootstrap, key, None)
            chunk = _from_candidate(candidate)
            if chunk is not None:
                return chunk

    return None


def _attach_v14_3_serialized_chunk(
    analysis: Mapping[str, Any] | None,
    source: str,
    *,
    logger: logging.Logger | None = None,
) -> None:
    """Populate ``analysis`` with a serialized chunk extracted directly from *source*."""

    if not isinstance(analysis, Mapping):
        return
    if not _analysis_is_v14_3(analysis):
        return
    if _extract_serialized_chunk(analysis) is not None:
        return

    log = logger or logging.getLogger(__name__)
    try:
        descriptor, data = v14_3_loader.extract_v14_3_serialized_chunk_bytes_from_source(
            source
        )
        chunk = v14_3_loader.build_v14_3_serialized_chunk_from_bytes(descriptor, data)
    except Exception as exc:  # pragma: no cover - extraction is best-effort
        log.debug("v14.3 serialized chunk extraction failed: %s", exc)
        return

    if isinstance(analysis, dict):
        analysis.setdefault("serialized_chunk", chunk)
        analysis.setdefault("serialized_chunk_model", chunk)
        bootstrap = analysis.setdefault("bootstrap", {})
        if isinstance(bootstrap, dict):
            bootstrap.setdefault("serialized_chunk", chunk)
            bootstrap.setdefault("serialized_chunk_model", chunk)

def _string_preview(value: str, limit: int = 64) -> str:
    escaped = value.encode("unicode_escape", errors="backslashreplace").decode("ascii")
    if len(escaped) > limit:
        escaped = escaped[: limit - 3] + "..."
    return f'"{escaped}"'


def _format_constant_preview(constant: Constant) -> str:
    value = constant.value
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _string_preview(value)
    if isinstance(value, (bytes, bytearray)):
        preview = value[:16].hex()
        if len(value) > 16:
            preview += "..."
        return f"0x{preview}"
    return str(value)


def dump_v14_3_constants(
    analysis: Mapping[str, Any] | None, logger: logging.Logger | None = None
) -> bool:
    """Print the decoded constant pools for v14.3 prototypes."""

    if not isinstance(analysis, Mapping):
        return False

    log = logger or logging.getLogger(__name__)
    if not _analysis_is_v14_3(analysis):
        return False

    chunk = _extract_serialized_chunk(analysis)
    if chunk is None:
        log.warning(
            "dump_v14_3_constants: serialized chunk metadata unavailable; "
            "rerun analysis with bootstrap extraction enabled"
        )
        return False

    def _walk_prototypes(proto: SerializedPrototype, label: str, depth: int) -> None:
        indent = "  " * depth
        print(f"{indent}Prototype {label} (constants: {len(proto.constants)})")
        if not proto.constants:
            print(f"{indent}  (no constants)")
        for index, entry in enumerate(proto.constants):
            constant = entry if isinstance(entry, Constant) else make_constant(entry)
            preview = _format_constant_preview(constant)
            print(f"{indent}  [{index:02d}] {constant.kind:<7} {preview}")
        for child_index, child in enumerate(proto.prototypes):
            _walk_prototypes(child, f"{label}.{child_index}", depth + 1)

    print("\n" + "=" * 60)
    print("V14.3 CONSTANT TABLE")
    print("=" * 60)
    for proto_index, prototype in enumerate(chunk.prototypes):
        _walk_prototypes(prototype, str(proto_index), 0)

    return True


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
        "--dump-constants",
        action="store_true",
        help=(
            "After analysis, print decoded v14.3 prototype constants "
            "(index, type, preview)."
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
                _attach_v14_3_serialized_chunk(analysis, code, logger=logger)

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

                if args.dump_constants:
                    dump_v14_3_constants(analysis, logger)

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
                _attach_v14_3_serialized_chunk(analysis, code, logger=logger)

                # Optionally emit the bootstrap/VM summary before rewriting.
                if args.dump_bootstrap:
                    dump_bootstrap_summary(analysis, logger)

                if args.dump_constants:
                    dump_v14_3_constants(analysis, logger)

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
