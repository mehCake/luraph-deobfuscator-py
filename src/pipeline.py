"""Simple pass registry and runner used by the CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
import time

from . import utils
from .deobfuscator import LuaDeobfuscator

PassFn = Callable[["Context"], None]


@dataclass
class Context:
    input_path: str
    raw_input: str = ""
    decoded_payloads: List[str] = field(default_factory=list)
    detected_version: Optional[str] = None
    string_table: Dict[str, str] = field(default_factory=dict)
    ir: Any = None
    ast: Any = None
    output: str = ""
    logs: List[str] = field(default_factory=list)
    artifacts: Optional[Path] = None


class PassRegistry:
    def __init__(self) -> None:
        self._passes: Dict[str, Tuple[int, PassFn]] = {}

    def register_pass(self, name: str, fn: PassFn, order: int) -> None:
        self._passes[name] = (order, fn)

    # core runner
    def run_passes(
        self,
        ctx: Context,
        skip: Optional[Iterable[str]] = None,
        only: Optional[Iterable[str]] = None,
        profile: bool = False,
    ) -> List[Tuple[str, float]]:
        selected: List[Tuple[int, str, PassFn]] = []
        for name, (order, fn) in self._passes.items():
            if skip and name in skip:
                continue
            if only and name not in only:
                continue
            selected.append((order, name, fn))
        selected.sort()
        results: List[Tuple[str, float]] = []
        if ctx.artifacts:
            Path(ctx.artifacts).mkdir(parents=True, exist_ok=True)
        for _, name, fn in selected:
            start = time.time()
            fn(ctx)
            duration = time.time() - start
            results.append((name, duration))
            if ctx.artifacts:
                log_path = Path(ctx.artifacts) / f"{name}.log"
                with log_path.open("w", encoding="utf8") as fh:
                    fh.write(f"{name} completed in {duration:.3f}s\n")
        return results


PIPELINE = PassRegistry()


# ---------------------------------------------------------------------------
# Default pass implementations


def _pass_detect(ctx: Context) -> None:
    ctx.raw_input = utils.safe_read_file(ctx.input_path) or ""
    deob = LuaDeobfuscator()
    ctx.detected_version = deob.detect_version(ctx.raw_input)


def _pass_decode(ctx: Context) -> None:
    if not ctx.raw_input:
        return
    deob = LuaDeobfuscator()
    ctx.output = deob.deobfuscate_content(ctx.raw_input)


def _pass_format(ctx: Context) -> None:
    # Placeholder hook for future pretty-printing.  For now it simply ensures
    # the output is a string.
    if ctx.output is None:
        ctx.output = ""


PIPELINE.register_pass("detect", _pass_detect, 10)
PIPELINE.register_pass("decode", _pass_decode, 20)
PIPELINE.register_pass("format", _pass_format, 30)


__all__ = ["Context", "PassRegistry", "PIPELINE"]
