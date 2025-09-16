"""Preprocessing helpers for normalising input sources."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from .. import utils

if TYPE_CHECKING:  # pragma: no cover - import for typing only
    from ..pipeline import Context

LOG = logging.getLogger(__name__)


def flatten_json_to_lua(obj: Any) -> str:
    """Flatten nested JSON arrays of strings into a single Lua source string."""

    pieces: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            pieces.append(node)
        elif isinstance(node, list):
            for item in node:
                _walk(item)
        # ignore other node types silently

    _walk(obj)
    return "".join(pieces)


def _write_reconstructed(ctx: "Context", combined: str) -> None:
    stem = ctx.input_path.stem or "reconstructed"
    filename = f"{stem}_reconstructed.lua"

    if ctx.artifacts:
        utils.ensure_directory(ctx.artifacts)
        target = ctx.artifacts / filename
    else:
        temp_dir = Path(tempfile.mkdtemp(prefix="luraph_preprocess_"))
        target = temp_dir / filename
    target.write_text(combined, encoding="utf-8")
    ctx.temp_paths["reconstructed_lua"] = target


def run(ctx: "Context") -> Dict[str, Any]:
    """Normalise the current input text and record preprocessing metadata."""

    ctx.ensure_raw_input()
    deob = ctx.deobfuscator
    assert deob is not None

    text = ctx.stage_output or ctx.raw_input
    if not text:
        ctx.stage_output = ""
        ctx.working_text = ""
        if not ctx.original_text:
            ctx.original_text = ""
        return {"empty": True}

    metadata: Dict[str, Any] = {"input_length": len(text)}

    suffix = ctx.input_path.suffix.lower()
    combined = text
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:  # pragma: no cover - rare path
            LOG.warning("failed to decode JSON input %s: %s", ctx.input_path, exc)
            metadata["json_error"] = str(exc)
        else:
            combined = flatten_json_to_lua(data)
            metadata["json_flattened"] = True
            metadata["flattened_length"] = len(combined)
            _write_reconstructed(ctx, combined)
    ctx.original_text = ctx.original_text or text
    ctx.working_text = combined

    processed = deob.preprocess(combined)
    ctx.stage_output = processed
    ctx.working_text = processed
    metadata["output_length"] = len(processed)
    metadata["changed"] = processed != text
    if suffix == ".json":
        metadata.setdefault("json_flattened", combined != text)
    return metadata


__all__ = ["flatten_json_to_lua", "run"]
