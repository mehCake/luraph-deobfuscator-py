"""Pass-based orchestration for the deobfuscation pipeline."""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
)

from version_detector import VersionInfo

from . import utils
from .detect import ask_confirm, detect_version_from_text, legacy_detector
from .report import DeobReport
from .deobfuscator import LuaDeobfuscator, VMIR
from .versions import VersionHandler
from .passes.preprocess import run as preprocess_run
from .passes.payload_decode import run as payload_decode_run
from .passes.vm_devirtualize import run as vm_devirtualize_run
from .passes.vm_lift import run as vm_lift_run
from .passes.cleanup import run as cleanup_run
from .passes.string_reconstruction import run as string_reconstruction_run
from .passes.render import run as render_run

LOG = logging.getLogger(__name__)

_ROOT_DIR = Path(__file__).resolve().parent.parent
_KNOWN_BOOTSTRAPPERS = {
    "initv4": _ROOT_DIR / "initv4.lua",
}

_VERSION_BOOTSTRAPPERS = {
    "luraph_v14_4_initv4": "initv4",
    "v14.4.1": "initv4",
}

PassFn = Callable[["Context"], None]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .utils_pkg.ir import IRModule


def _default_report() -> DeobReport:
    return DeobReport(
        version_detected="unknown",
        script_key_used=None,
        bootstrapper_used=None,
        blob_count=0,
        decoded_bytes=0,
        opcode_stats={},
        unknown_opcodes=[],
        traps_removed=0,
        constants_decrypted=0,
        variables_renamed=0,
        output_length=0,
    )


@dataclass
class VMPayload:
    """Container for bytecode artefacts extracted during payload decoding."""

    bytecode: bytes | None = None
    const_pool: List[Any] | None = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Context:
    """Shared state threaded through individual pipeline passes."""

    input_path: Path
    raw_input: str = ""
    stage_output: str = ""
    output: str = ""
    original_text: str = ""
    working_text: str = ""
    detected_version: VersionInfo | None = None
    version_override: str | None = None
    vm_ir: VMIR | None = None
    decoded_payloads: List[str] = field(default_factory=list)
    pass_metadata: Dict[str, Any] = field(default_factory=dict)
    artifacts: Optional[Path] = None
    deobfuscator: LuaDeobfuscator | None = None
    iteration: int = 0
    options: Dict[str, Any] = field(default_factory=dict)
    script_key: str | None = None
    bootstrapper_path: Path | None = None
    yes: bool = False
    force: bool = False
    temp_paths: Dict[str, Path] = field(default_factory=dict)
    vm: VMPayload = field(default_factory=VMPayload)
    vm_metadata: Dict[str, Any] = field(default_factory=dict)
    ir_module: "IRModule | None" = None
    from_json: bool = False
    reconstructed_lua: str = ""
    version_handler: VersionHandler | None = None
    report: DeobReport = field(default_factory=_default_report)
    result: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.deobfuscator is None:
            self.deobfuscator = LuaDeobfuscator(
                script_key=self.script_key,
                bootstrapper=self.bootstrapper_path,
            )
        if self.script_key and not self.report.script_key_used:
            self.report.script_key_used = self.script_key
        if self.bootstrapper_path and not self.report.bootstrapper_used:
            self.report.bootstrapper_used = str(self.bootstrapper_path)
        try:
            suffix = self.input_path.suffix.lower()
        except AttributeError:
            suffix = ""
        if suffix == ".json":
            self.from_json = True
        if self.raw_input:
            if not self.original_text:
                self.original_text = self.raw_input
            if not self.working_text:
                self.working_text = self.raw_input
            if not self.stage_output:
                self.stage_output = self.raw_input
        elif self.reconstructed_lua:
            self.raw_input = self.reconstructed_lua
            self.stage_output = self.reconstructed_lua
            self.working_text = self.reconstructed_lua
            if not self.original_text:
                self.original_text = self.reconstructed_lua
        if self.artifacts:
            utils.ensure_directory(self.artifacts)

    # ------------------------------------------------------------------
    def ensure_raw_input(self) -> None:
        if self.input_path.suffix.lower() == ".json":
            self.from_json = True

        if self.raw_input:
            if not self.original_text:
                self.original_text = self.raw_input
            if not self.working_text:
                self.working_text = self.raw_input
            return
        if self.reconstructed_lua:
            self.raw_input = self.reconstructed_lua
            self.stage_output = self.reconstructed_lua
            self.working_text = self.reconstructed_lua
            if not self.original_text:
                self.original_text = self.reconstructed_lua
            return
        data = utils.safe_read_file(str(self.input_path))
        self.raw_input = data or ""
        self.stage_output = self.raw_input
        self.original_text = self.raw_input
        self.working_text = self.raw_input

    @property
    def version(self) -> VersionInfo | None:
        """Return the currently detected version, if available."""

        return self.detected_version

    def record_metadata(self, name: str, metadata: Dict[str, Any]) -> None:
        summary = utils.summarise_metadata(metadata)
        self.pass_metadata[name] = summary
        if self.artifacts:
            utils.ensure_directory(self.artifacts)
            meta_path = self.artifacts / f"{name}.json"
            meta_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    def write_artifact(self, name: str, content: str, *, extension: str = ".lua") -> None:
        if not self.artifacts:
            return
        if content is None or content == "":
            return
        utils.ensure_directory(self.artifacts)
        safe_name = name.replace(" ", "_")
        path = self.artifacts / f"{safe_name}{extension}"
        path.write_text(content, encoding="utf-8")


def _is_interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:  # pragma: no cover - defensive
        return False


def _should_prompt_confirmation(ctx: Context) -> bool:
    if getattr(ctx, "force", False):
        return False
    if getattr(ctx, "yes", False):
        return False
    option = ctx.options.get("confirm_detected_version") if isinstance(ctx.options, dict) else None
    if isinstance(ctx.options, dict) and ctx.options.get("auto_confirm"):
        return False
    if isinstance(ctx.options, dict) and ctx.options.get("force"):
        return False
    if option is False:
        return False
    if option is True:
        return _is_interactive()
    if ctx.iteration > 0:
        return False
    return _is_interactive()


def _prompt_yes_no(message: str) -> bool:
    prompt = message
    while True:
        try:
            response = input(prompt)
        except EOFError:  # pragma: no cover - treat EOF as acceptance
            return True
        answer = response.strip().lower()
        if not answer:
            return True
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        prompt = "Please answer Y or N: "


def _confirm_detected_version(ctx: Context, version: VersionInfo) -> None:
    if version.is_unknown or ctx.version_override:
        return
    if ctx.options.get("_version_confirmed"):
        return
    if not _should_prompt_confirmation(ctx):
        ctx.options["_version_confirmed"] = True
        return
    accepted = _prompt_yes_no(
        f"Detected Luraph version '{version.name}'. Is this correct? [Y/n]: "
    )
    if not accepted:
        raise RuntimeError(
            "User rejected detected Luraph version. Rerun with --force-version to override."
        )
    ctx.options["_version_confirmed"] = True


def _expected_bootstrapper(version: VersionInfo) -> str | None:
    return _VERSION_BOOTSTRAPPERS.get(version.name)


def _locate_bootstrapper(name: str) -> Path | None:
    candidate = _KNOWN_BOOTSTRAPPERS.get(name.lower())
    if candidate and candidate.exists():
        return candidate
    fallback = Path(f"{name}.lua")
    if fallback.exists():
        try:
            return fallback.resolve()
        except OSError:  # pragma: no cover - defensive
            return fallback
    return None


def _bootstrap_matches(path: Path, expected: str) -> bool:
    try:
        if expected.lower() in path.name.lower():
            return True
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return expected.lower() in text.lower()


def _validate_bootstrapper(ctx: Context, version: VersionInfo) -> None:
    if ctx.options.get("_bootstrap_validated"):
        return
    expected = _expected_bootstrapper(version)
    if not expected:
        ctx.options["_bootstrap_validated"] = True
        return

    expected_key = expected.lower()
    bootstrap_path = ctx.bootstrapper_path
    resolved: Path | None = None
    if bootstrap_path is None:
        resolved = _locate_bootstrapper(expected_key)
        if resolved:
            ctx.bootstrapper_path = resolved
            if ctx.report is not None:
                ctx.report.bootstrapper_used = str(resolved)
            ctx.options.setdefault("bootstrapper", str(resolved))
            LOG.info("Using default %s bootstrapper at %s", expected, resolved)
        else:
            LOG.warning(
                "Detected version %s expects %s bootstrapper but none was provided",
                version.name,
                expected,
            )
            ctx.options["_bootstrap_validated"] = True
            return
    else:
        resolved = Path(bootstrap_path)
        if not resolved.exists():
            LOG.warning("Bootstrapper path %s does not exist", resolved)
            ctx.options["_bootstrap_validated"] = True
            return
        ctx.bootstrapper_path = resolved

    assert resolved is not None
    if not _bootstrap_matches(resolved, expected_key):
        if _should_prompt_confirmation(ctx):
            accepted = _prompt_yes_no(
                (
                    f"Bootstrapper '{resolved.name}' does not appear to match expected "
                    f"'{expected}'. Continue? [Y/n]: "
                )
            )
            if not accepted:
                raise RuntimeError(
                    "Bootstrapper rejected by user confirmation. Provide the correct init stub."
                )
        else:
            LOG.warning(
                "Bootstrapper %s may not match expected %s for version %s",
                resolved,
                expected,
                version.name,
            )
    if ctx.report is not None and ctx.report.bootstrapper_used is None:
        ctx.report.bootstrapper_used = str(resolved)
    ctx.options["_bootstrap_validated"] = True


class PassRegistry:
    def __init__(self) -> None:
        self._passes: Dict[str, Tuple[int, PassFn]] = {}

    def register_pass(self, name: str, fn: PassFn, order: int) -> None:
        self._passes[name] = (order, fn)

    def run_passes(
        self,
        ctx: Context,
        skip: Optional[Iterable[str]] = None,
        only: Optional[Iterable[str]] = None,
        profile: bool = False,
    ) -> List[Tuple[str, float]]:
        selected: List[Tuple[int, str, PassFn]] = []
        skip_set = {name.strip() for name in (skip or []) if name}
        only_set = {name.strip() for name in (only or []) if name}

        for name, (order, fn) in self._passes.items():
            if skip_set and name in skip_set:
                continue
            if only_set and name not in only_set:
                continue
            selected.append((order, name, fn))
        selected.sort()

        timings: List[Tuple[str, float]] = []
        for _, name, fn in selected:
            start = time.perf_counter()
            fn(ctx)
            duration = time.perf_counter() - start
            timings.append((name, duration))
            metadata = ctx.pass_metadata.get(name)
            summary_parts: List[str] = []
            if isinstance(metadata, dict):
                instructions = metadata.get("instructions")
                blocks = metadata.get("blocks")
                unknown = metadata.get("unknown_opcodes")
                warnings = metadata.get("warnings")
                if isinstance(instructions, int):
                    summary_parts.append(f"ops={instructions}")
                if isinstance(blocks, int):
                    summary_parts.append(f"blocks={blocks}")
                if isinstance(unknown, int):
                    summary_parts.append(f"unknown={unknown}")
                elif isinstance(warnings, list):
                    summary_parts.append(f"warnings={len(warnings)}")
                for key in ("step_limit_hit", "time_limit_hit", "skipped"):
                    if metadata.get(key):
                        summary_parts.append(f"{key}=true")
            suffix = f" ({', '.join(summary_parts)})" if summary_parts else ""
            LOG.info("pass %s completed in %.3fs%s", name, duration, suffix)
        return timings


PIPELINE = PassRegistry()


# ---------------------------------------------------------------------------
# Pass implementations


def _pass_detect(ctx: Context) -> None:
    ctx.ensure_raw_input()
    deob = ctx.deobfuscator
    assert deob is not None

    raw_text = ctx.raw_input
    candidate_name = detect_version_from_text(raw_text)

    if ctx.version_override:
        version = deob._resolve_version(  # type: ignore[attr-defined]
            raw_text,
            ctx.version_override,
            from_json=ctx.from_json,
        )
    elif candidate_name:
        if candidate_name.startswith("luraph_v14_4"):
            version = deob._version_detector.info_for_name(candidate_name)  # type: ignore[attr-defined]
            prompt = f"Detected Luraph v14.4.1 in {ctx.input_path}. Use v14.4.1 handler?"
            if _should_prompt_confirmation(ctx):
                if not ask_confirm(ctx, prompt):
                    version = legacy_detector(raw_text, from_json=ctx.from_json)
        else:
            version = legacy_detector(raw_text, from_json=ctx.from_json)
    else:
        version = deob.detect_version(raw_text, from_json=ctx.from_json)
    ctx.detected_version = version

    _confirm_detected_version(ctx, version)
    _validate_bootstrapper(ctx, version)

    if ctx.report:
        ctx.report.version_detected = version.name

    metadata: Dict[str, Any] = {
        "name": version.name,
        "major": version.major,
        "minor": version.minor,
        "confidence": version.confidence,
        "features": sorted(version.features) if version.features else [],
    }
    if version.matched_categories:
        metadata["matched_categories"] = list(version.matched_categories)
    if ctx.bootstrapper_path:
        metadata["bootstrapper_path"] = str(ctx.bootstrapper_path)
    ctx.record_metadata("detect", metadata)
    if ctx.iteration == 0:
        ctx.write_artifact("raw_input", ctx.raw_input)


def _pass_preprocess(ctx: Context) -> None:
    metadata = preprocess_run(ctx)
    ctx.record_metadata("preprocess", metadata)
    if ctx.stage_output:
        ctx.write_artifact("preprocess", ctx.stage_output)


def _pass_payload_decode(ctx: Context) -> None:
    metadata = payload_decode_run(ctx)
    ctx.record_metadata("payload_decode", metadata)
    if ctx.stage_output:
        ctx.write_artifact("payload_decode", ctx.stage_output)


def _pass_vm_lift(ctx: Context) -> None:
    metadata = vm_lift_run(ctx)
    module = ctx.ir_module
    if module is not None:
        lifter_meta = ctx.vm_metadata.setdefault("lifter", {})
        lifter_meta.update(
            {
                "instruction_count": module.instruction_count,
                "block_count": module.block_count,
                "bytecode_size": module.bytecode_size,
            }
        )
        block_lookup: Dict[int, str] = {}
        for label, block in module.blocks.items():
            for inst in block.instructions:
                block_lookup[inst.pc] = label
        markers: List[Dict[str, Any]] = []
        for inst in module.instructions:
            entry: Dict[str, Any] = {"pc": inst.pc, "opcode": inst.opcode}
            if inst.args:
                entry["args"] = dict(inst.args)
            if inst.dest is not None:
                entry["dest"] = inst.dest
            origin_offset = inst.origin.get("offset") if isinstance(inst.origin, dict) else None
            if isinstance(origin_offset, int):
                entry["offset"] = origin_offset
            block_label = block_lookup.get(inst.pc)
            if block_label:
                entry["block"] = block_label
            markers.append(entry)
        if markers:
            lifter_meta["instruction_total"] = len(markers)
            sample_limit = 256
            lifter_meta["instruction_markers"] = markers[:sample_limit]
            if len(markers) > sample_limit:
                lifter_meta["instruction_sample_size"] = sample_limit
        block_meta: List[Dict[str, Any]] = []
        for label, block in sorted(module.blocks.items()):
            block_meta.append(
                {
                    "label": label,
                    "start_pc": block.start_pc,
                    "size": len(block.instructions),
                    "successors": list(block.successors),
                }
            )
        if block_meta:
            lifter_meta["blocks"] = block_meta
    report = ctx.report
    if report is not None and ctx.ir_module is not None:
        stats: Dict[str, int] = {}
        unknowns: set[int] = set()
        for inst in ctx.ir_module.instructions:
            opcode = inst.opcode or "UNKNOWN_OP"
            stats[opcode] = stats.get(opcode, 0) + 1
            if opcode == "UNKNOWN_OP":
                raw_value = inst.args.get("opcode") if isinstance(inst.args, dict) else None
                if isinstance(raw_value, int):
                    unknowns.add(raw_value)
        report.opcode_stats.clear()
        report.opcode_stats.update(stats)
        report.unknown_opcodes = sorted(unknowns)
        warnings = metadata.get("warnings")
        if isinstance(warnings, list):
            report.warnings.extend(str(item) for item in warnings if item)
    ctx.record_metadata("vm_lift", metadata)


def _pass_vm_devirtualize(ctx: Context) -> None:
    if ctx.ir_module is None:
        ctx.record_metadata("vm_devirtualize", {"skipped": True})
        return
    metadata = vm_devirtualize_run(ctx)
    if metadata:
        devirt_meta = ctx.vm_metadata.setdefault("devirtualizer", {})
        for key in (
            "pc_mapping",
            "statement_map",
            "block_map",
            "reachable_blocks",
            "unreachable_blocks",
            "unreachable_pcs",
            "eliminated_instructions",
        ):
            value = metadata.get(key)
            if value is not None:
                devirt_meta[key] = value
        unreachable = metadata.get("unreachable_pcs")
        if isinstance(unreachable, list) and unreachable:
            traps_meta = ctx.vm_metadata.setdefault("traps", {})
            traps_meta["unreachable_pcs"] = list(unreachable)
        eliminated = metadata.get("eliminated_instructions")
        if isinstance(eliminated, int) and eliminated > 0:
            traps_meta = ctx.vm_metadata.setdefault("traps", {})
            traps_meta["eliminated_instructions"] = eliminated
    ctx.record_metadata("vm_devirtualize", dict(metadata))
    if ctx.stage_output:
        ctx.write_artifact("vm_devirtualize", ctx.stage_output)


def _pass_cleanup(ctx: Context) -> None:
    metadata = cleanup_run(ctx)
    report = ctx.report
    if report is not None:
        traps = 0
        assert_traps = metadata.get("assert_traps")
        if isinstance(assert_traps, int):
            traps += max(assert_traps, 0)
        dummy_loops = metadata.get("dummy_loops")
        if isinstance(dummy_loops, int):
            traps += max(dummy_loops, 0)
        report.traps_removed = traps
        trap_meta = ctx.vm_metadata.setdefault("traps", {})
        if isinstance(assert_traps, int):
            trap_meta["assert_traps"] = max(assert_traps, 0)
        if isinstance(dummy_loops, int):
            trap_meta["dummy_loops"] = max(dummy_loops, 0)
        trap_meta["total_removed"] = traps

        constants = 0
        if metadata.get("constant_folded"):
            constants += 1
        const_expr = metadata.get("constant_expressions")
        if isinstance(const_expr, int):
            constants += max(const_expr, 0)
        report.constants_decrypted = constants

        warnings = metadata.get("warnings")
        if isinstance(warnings, list):
            report.warnings.extend(str(item) for item in warnings if item)
    ctx.record_metadata("cleanup", metadata)
    if ctx.stage_output:
        ctx.write_artifact("cleanup", ctx.stage_output)


def _pass_string_reconstruction(ctx: Context) -> None:
    metadata = string_reconstruction_run(ctx)
    report = ctx.report
    if report is not None:
        warnings = metadata.get("warnings")
        if isinstance(warnings, list):
            report.warnings.extend(str(item) for item in warnings if item)
    ctx.record_metadata("string_reconstruction", metadata)
    if ctx.stage_output:
        ctx.write_artifact("string_reconstruction", ctx.stage_output)


def _pass_render(ctx: Context) -> None:
    metadata = render_run(ctx)
    report = ctx.report
    if report is not None:
        length = metadata.get("length")
        if isinstance(length, int) and length >= 0:
            report.output_length = length
        warnings = metadata.get("warnings")
        if isinstance(warnings, list):
            report.warnings.extend(str(item) for item in warnings if item)
    ctx.record_metadata("render", metadata)
    if ctx.stage_output:
        ctx.write_artifact("render", ctx.stage_output)


PIPELINE.register_pass("detect", _pass_detect, 10)
PIPELINE.register_pass("preprocess", _pass_preprocess, 20)
PIPELINE.register_pass("payload_decode", _pass_payload_decode, 30)
PIPELINE.register_pass("vm_lift", _pass_vm_lift, 40)
PIPELINE.register_pass("vm_devirtualize", _pass_vm_devirtualize, 50)
PIPELINE.register_pass("cleanup", _pass_cleanup, 60)
PIPELINE.register_pass("string_reconstruction", _pass_string_reconstruction, 65)
PIPELINE.register_pass("render", _pass_render, 70)


__all__ = ["Context", "PassRegistry", "PIPELINE"]
