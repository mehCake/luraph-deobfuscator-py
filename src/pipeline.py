"""Pass-based orchestration for the deobfuscation pipeline."""

from __future__ import annotations

import json
import logging
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
from .deobfuscator import LuaDeobfuscator, VMIR
from .passes.preprocess import run as preprocess_run
from .passes.payload_decode import run as payload_decode_run
from .passes.vm_devirtualize import run as vm_devirtualize_run
from .passes.vm_lift import run as vm_lift_run
from .passes.cleanup import run as cleanup_run
from .passes.render import run as render_run

LOG = logging.getLogger(__name__)

PassFn = Callable[["Context"], None]

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .utils_pkg.ir import IRModule


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
    temp_paths: Dict[str, Path] = field(default_factory=dict)
    vm: VMPayload = field(default_factory=VMPayload)
    ir_module: "IRModule | None" = None

    def __post_init__(self) -> None:
        if self.deobfuscator is None:
            self.deobfuscator = LuaDeobfuscator()
        if self.raw_input:
            if not self.original_text:
                self.original_text = self.raw_input
            if not self.working_text:
                self.working_text = self.raw_input
            if not self.stage_output:
                self.stage_output = self.raw_input
        if self.artifacts:
            utils.ensure_directory(self.artifacts)

    # ------------------------------------------------------------------
    def ensure_raw_input(self) -> None:
        if self.raw_input:
            if not self.original_text:
                self.original_text = self.raw_input
            if not self.working_text:
                self.working_text = self.raw_input
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

    if ctx.version_override:
        version = deob._resolve_version(ctx.raw_input, ctx.version_override)  # type: ignore[attr-defined]
    else:
        version = deob.detect_version(ctx.raw_input)
    ctx.detected_version = version

    metadata: Dict[str, Any] = {
        "name": version.name,
        "major": version.major,
        "minor": version.minor,
        "confidence": version.confidence,
        "features": sorted(version.features) if version.features else [],
    }
    if version.matched_categories:
        metadata["matched_categories"] = list(version.matched_categories)
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
    ctx.record_metadata("vm_lift", metadata)


def _pass_vm_devirtualize(ctx: Context) -> None:
    if ctx.ir_module is None:
        ctx.record_metadata("vm_devirtualize", {"skipped": True})
        return
    metadata = vm_devirtualize_run(ctx)
    ctx.record_metadata("vm_devirtualize", dict(metadata))
    if ctx.stage_output:
        ctx.write_artifact("vm_devirtualize", ctx.stage_output)


def _pass_cleanup(ctx: Context) -> None:
    metadata = cleanup_run(ctx)
    ctx.record_metadata("cleanup", metadata)
    if ctx.stage_output:
        ctx.write_artifact("cleanup", ctx.stage_output)


def _pass_render(ctx: Context) -> None:
    metadata = render_run(ctx)
    ctx.record_metadata("render", metadata)
    if ctx.stage_output:
        ctx.write_artifact("render", ctx.stage_output)


PIPELINE.register_pass("detect", _pass_detect, 10)
PIPELINE.register_pass("preprocess", _pass_preprocess, 20)
PIPELINE.register_pass("payload_decode", _pass_payload_decode, 30)
PIPELINE.register_pass("vm_lift", _pass_vm_lift, 40)
PIPELINE.register_pass("vm_devirtualize", _pass_vm_devirtualize, 50)
PIPELINE.register_pass("cleanup", _pass_cleanup, 60)
PIPELINE.register_pass("render", _pass_render, 70)


__all__ = ["Context", "PassRegistry", "PIPELINE"]
