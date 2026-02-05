"""Run a full Luraph deobfuscation flow against one or more inputs.

This runner is designed to exercise the core pipeline modules, verify the
Python module tree is syntactically healthy, and emit both deobfuscated Lua
and structured reports for supported Luraph versions.
"""

from __future__ import annotations

import argparse
import logging
import py_compile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

from src import pipeline, utils
from src.deobfuscator import LuaDeobfuscator
from src.luraph_deobfuscator import Deobfuscator as LegacyDeobfuscator
from src.opcode_verifier import run_verification as run_opcode_semantics
from src.tools.ensure_license import ensure_license, insert_license_header
from src.utils.io_utils import write_json, write_text
from src.vm import disassembler as vm_disassembler
from src.vm.opcode_map_validator import validate_opcode_map, write_validation_report

LOGGER = logging.getLogger(__name__)

DEFAULT_EXTENSIONS = (".lua", ".json", ".lph", ".b64", ".bin", ".txt")


@dataclass(frozen=True)
class ModuleCheck:
    path: Path
    ok: bool
    detail: str


@dataclass(frozen=True)
class DeobfuscationResult:
    input_path: Path
    output_path: Path
    report_path: Path
    used_legacy: bool
    extra_reports: List[Path]


def _iter_input_files(paths: Iterable[Path], extensions: Iterable[str]) -> List[Path]:
    exts = {ext.lower() for ext in extensions}
    discovered: List[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_file() and candidate.suffix.lower() in exts:
                    discovered.append(candidate)
        elif path.is_file() and path.suffix.lower() in exts:
            discovered.append(path)
    return discovered


def verify_module_tree(module_root: Path) -> List[ModuleCheck]:
    """Compile Python modules under ``module_root`` to ensure syntax health."""

    checks: List[ModuleCheck] = []
    for path in sorted(module_root.rglob("*.py")):
        if path.is_dir():
            continue
        if path.stat().st_size == 0:
            checks.append(ModuleCheck(path, False, "empty module"))
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as exc:
            checks.append(ModuleCheck(path, False, str(exc)))
        else:
            checks.append(ModuleCheck(path, True, "ok"))
    return checks


def _write_module_report(output_dir: Path, checks: Iterable[ModuleCheck]) -> Path:
    payload = [
        {
            "path": str(check.path),
            "ok": check.ok,
            "detail": check.detail,
        }
        for check in checks
    ]
    report_path = output_dir / "module_verification.json"
    write_json(report_path, payload, sort_keys=True)
    return report_path


def _best_disassembly(
    bytecode: bytes,
    *,
    endianness: str,
) -> Optional[vm_disassembler.DisassemblyCandidate]:
    configs: List[Tuple[str, vm_disassembler.DisassemblerConfig]] = []
    for name, config in vm_disassembler.DEFAULT_CONFIGS.items():
        split = config.split_signature()
        rebuilt = vm_disassembler.build_config_from_split(
            split,
            endianness=endianness,
            word_size=config.word_size,
            order=config.order,
        )
        configs.append((name, rebuilt))
    candidates = vm_disassembler.analyse_disassembly(bytecode, configs, top=1)
    if not candidates:
        return None
    return candidates[0]


def _run_opcode_behaviour_analysis(
    *,
    output_dir: Path,
    bytecode: bytes,
    opcode_map: Mapping[int, str],
    version_hint: Optional[str],
    endianness: str,
    label: str,
) -> Optional[Path]:
    candidate = _best_disassembly(bytecode, endianness=endianness)
    if not candidate:
        return None
    summary = validate_opcode_map(
        candidate.instructions,
        opcode_map,
        candidate=label,
        strictness="balanced",
        version_hint=version_hint,
    )
    report_dir = output_dir / "opcode_validation"
    report_path = write_validation_report(
        summary,
        output_dir=report_dir,
        filename=f"{label}.md",
    )
    return report_path


def _dump_constants(
    *,
    output_dir: Path,
    label: str,
    const_pool: Sequence[object],
) -> List[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: List[Path] = []

    if const_pool:
        constants_path = output_dir / f"{label}_constants.json"
        write_json(constants_path, {"constants": list(const_pool)}, sort_keys=True)
        artifacts.append(constants_path)

    return artifacts


def _run_pipeline(
    input_path: Path,
    *,
    output_dir: Path,
    script_key: Optional[str],
    bootstrapper: Optional[Path],
    iterations: int,
    allow_lua_run: bool,
) -> tuple[str, dict, Optional[pipeline.Context], bool]:
    raw_text = utils.safe_read_file(str(input_path)) or ""
    deobfuscator = LuaDeobfuscator(
        script_key=script_key,
        bootstrapper=bootstrapper,
        debug_bootstrap=False,
        allow_lua_run=allow_lua_run,
    )
    previous = raw_text
    final_ctx: Optional[pipeline.Context] = None

    for iteration in range(max(1, iterations)):
        ctx = pipeline.Context(
            input_path=input_path,
            raw_input=previous,
            stage_output=previous,
            original_text=previous,
            working_text=previous,
            version_override=None,
            artifacts=output_dir / "artifacts" / input_path.stem / f"iter-{iteration}",
            deobfuscator=deobfuscator,
            iteration=iteration,
            from_json=input_path.suffix.lower() == ".json",
            reconstructed_lua="",
            script_key=script_key,
            bootstrapper_path=bootstrapper,
            yes=True,
            force=True,
            debug_bootstrap=False,
            allow_lua_run=allow_lua_run,
            output_prefix=None,
            artifact_only=False,
        )
        ctx.options.update(
            {
                "auto_confirm": True,
                "confirm_detected_version": False,
                "force": True,
                "script_key": script_key,
                "allow_lua_run": allow_lua_run,
                "debug_bootstrap": False,
                "payload_decode_max_iterations": max(1, iterations),
            }
        )
        timings = pipeline.PIPELINE.run_passes(ctx, profile=True)
        ctx.result["timings"] = [
            {"name": name, "duration": duration} for name, duration in timings
        ]
        final_ctx = ctx
        produced = ctx.output or ctx.stage_output or previous
        if produced == previous:
            break
        previous = produced

    if final_ctx is None:
        return "", {"errors": ["pipeline produced no context"]}, None, False

    final_ctx.report.output_length = len(final_ctx.output or final_ctx.stage_output or "")
    report_payload = final_ctx.report.to_json()
    report_payload["timings"] = final_ctx.result.get("timings", [])
    report_payload["metadata"] = final_ctx.pass_metadata
    output_text = final_ctx.output or final_ctx.stage_output or previous
    return output_text, report_payload, final_ctx, False


def _run_legacy(
    input_path: Path,
    *,
    script_key: Optional[str],
) -> tuple[str, dict, Optional[pipeline.Context], bool]:
    legacy = LegacyDeobfuscator(str(input_path), script_key=script_key)
    legacy_result = legacy.run()
    output_text = legacy_result.get("lua_source", "")
    report_payload = legacy_result.get("json_report", {})
    return output_text, report_payload, None, True


def deobfuscate_file(
    input_path: Path,
    *,
    output_dir: Path,
    script_key: Optional[str],
    bootstrapper: Optional[Path],
    iterations: int,
    allow_lua_run: bool,
) -> DeobfuscationResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    extra_reports: List[Path] = []

    try:
        output_text, report_payload, ctx, used_legacy = _run_pipeline(
            input_path,
            output_dir=output_dir,
            script_key=script_key,
            bootstrapper=bootstrapper,
            iterations=iterations,
            allow_lua_run=allow_lua_run,
        )
    except Exception as exc:  # pragma: no cover - defensive fallback
        LOGGER.warning("Pipeline failed for %s (%s); falling back", input_path, exc)
        output_text, report_payload, ctx, used_legacy = _run_legacy(
            input_path,
            script_key=script_key,
        )

    output_path = output_dir / f"{input_path.stem}_deobfuscated.lua"
    report_path = output_dir / f"{input_path.stem}_report.json"
    write_text(output_path, output_text)
    insert_license_header(output_path)
    if not used_legacy and ctx is not None:
        const_pool = ctx.vm.const_pool or []
        extra_reports.extend(
            _dump_constants(
                output_dir=output_dir / "constants",
                label=input_path.stem,
                const_pool=const_pool,
            )
        )
        opcode_map = {}
        if isinstance(ctx.vm_metadata, dict):
            opcode_map = ctx.vm_metadata.get("opcode_map", {}) or {}
        bytecode = ctx.vm.bytecode
        if isinstance(opcode_map, Mapping) and bytecode:
            endianness = "little"
            if isinstance(ctx.vm.meta, dict):
                endianness = str(ctx.vm.meta.get("endianness", "little"))
            version_hint = ctx.report.version_detected
            report = _run_opcode_behaviour_analysis(
                output_dir=output_dir,
                bytecode=bytecode,
                opcode_map=opcode_map,
                version_hint=version_hint,
                endianness=endianness,
                label=f"{input_path.stem}_opcode_behaviour",
            )
            if report:
                extra_reports.append(report)

        if input_path.suffix.lower() == ".json":
            semantics_dir = output_dir / "opcode_semantics"
            try:
                result = run_opcode_semantics(input_path, semantics_dir)
            except Exception as exc:  # pragma: no cover - best effort
                LOGGER.warning("opcode semantics verification failed: %s", exc)
            else:
                semantics_report = semantics_dir / f"{input_path.stem}_opcode_semantics.json"
                write_json(semantics_report, result, sort_keys=True)
                extra_reports.append(semantics_report)

    if extra_reports:
        report_payload.setdefault("extra_reports", [])
        report_payload["extra_reports"] = [str(path) for path in extra_reports]

    write_json(report_path, report_payload, sort_keys=True)
    return DeobfuscationResult(
        input_path=input_path,
        output_path=output_path,
        report_path=report_path,
        used_legacy=used_legacy,
        extra_reports=extra_reports,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the full deobfuscation pipeline for Luraph payloads and emit outputs."
        )
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Input files or directories containing Luraph payloads",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out") / "full_deobfuscation",
        help="Directory for deobfuscated outputs and reports",
    )
    parser.add_argument(
        "--script-key",
        help="Optional script key used for encrypted payloads",
    )
    parser.add_argument(
        "--bootstrapper",
        type=Path,
        help="Optional initv4.lua bootstrapper path",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Maximum pipeline iterations to run per payload",
    )
    parser.add_argument(
        "--allow-lua-run",
        action="store_true",
        help="Allow Lua sandbox execution for bootstrap extraction",
    )
    parser.add_argument(
        "--skip-module-verification",
        action="store_true",
        help="Skip verifying that Python modules under src compile cleanly",
    )
    parser.add_argument(
        "--extensions",
        default=",".join(DEFAULT_EXTENSIONS),
        help="Comma-separated file extensions to include",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    utils.setup_logging(logging.INFO)

    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    ensure_license(output_dir)

    if not args.skip_module_verification:
        checks = verify_module_tree(Path(__file__).resolve().parents[1])
        report_path = _write_module_report(output_dir, checks)
        failed = [check for check in checks if not check.ok]
        if failed:
            LOGGER.warning("Module verification reported %d issue(s)", len(failed))
        LOGGER.info("Module verification written to %s", report_path)

    extensions = [ext.strip() for ext in args.extensions.split(",") if ext.strip()]
    inputs = _iter_input_files(args.inputs, extensions)
    if not inputs:
        LOGGER.error("No input files found for %s", ", ".join(map(str, args.inputs)))
        return 2

    results: List[DeobfuscationResult] = []
    for input_path in inputs:
        if not utils.validate_file(str(input_path)):
            LOGGER.warning("Skipping unreadable file: %s", input_path)
            continue
        result = deobfuscate_file(
            input_path,
            output_dir=output_dir,
            script_key=args.script_key,
            bootstrapper=args.bootstrapper,
            iterations=max(1, args.iterations),
            allow_lua_run=args.allow_lua_run,
        )
        results.append(result)
        LOGGER.info(
            "Deobfuscated %s -> %s (legacy=%s)",
            result.input_path,
            result.output_path,
            result.used_legacy,
        )

    if not results:
        LOGGER.error("No files were processed successfully")
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
