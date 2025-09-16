"""Final rendering pass producing formatted Lua output files."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, TYPE_CHECKING

from .. import utils

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..pipeline import Context


LOG = logging.getLogger(__name__)


def _output_path(ctx: "Context") -> Path:
    override = ctx.options.get("render_output") if ctx.options else None
    if override:
        return Path(override)
    return ctx.input_path.with_name(f"{ctx.input_path.stem}_deob.lua")


def run(ctx: "Context") -> Dict[str, object]:
    deob = ctx.deobfuscator
    assert deob is not None

    text = ctx.stage_output or ""
    if not text:
        ctx.output = ""
        return {"empty": True}

    rendered = deob.render(text)
    ctx.stage_output = rendered
    ctx.output = rendered

    destination = _output_path(ctx)
    utils.ensure_directory(destination.parent)
    success = utils.safe_write_file(str(destination), rendered, encoding="utf-8")
    metadata: Dict[str, object] = {
        "output_path": str(destination),
        "length": len(rendered),
        "encoding": "utf-8",
        "written": success,
    }

    if not success:
        LOG.warning("failed writing render output to %s", destination)

    return metadata


__all__ = ["run"]

