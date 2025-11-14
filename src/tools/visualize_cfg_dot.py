"""Control-flow graph visualisation helpers.

This module converts dispatcher control-flow graphs stored as JSON into DOT
representations and, when possible, SVG images rendered with Graphviz.  The DOT
output intentionally includes rich node labels so analysts can understand the
IR metadata attached to each block without cross-referencing multiple artefacts.

The visualiser is purely static – it does not execute any Lua code and it never
persists sensitive material such as session keys.  Any metadata entry that looks
like a secret is omitted from the rendered labels.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

__all__ = [
    "CFGBlock",
    "CFG",
    "load_cfg",
    "render_cfg_dot",
    "write_cfg_visualisation",
    "main",
]


@dataclass(frozen=True)
class CFGBlock:
    """Light-weight representation of a dispatcher block."""

    block_id: str
    kind: str
    start: int
    end: int
    successors: Tuple[str, ...]
    opcode: Optional[int] = None
    handler: Optional[str] = None
    hints: Tuple[str, ...] = ()
    metadata: Mapping[str, object] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "CFGBlock":
        block_id = str(payload.get("id") or payload.get("block_id") or "block")
        kind = str(payload.get("kind", "unknown"))
        start = int(payload.get("start", 0))
        end = int(payload.get("end", 0))
        successors_raw = payload.get("successors", [])
        if isinstance(successors_raw, (list, tuple)):
            successors = tuple(str(item) for item in successors_raw)
        else:
            successors = ()
        hints_raw = payload.get("hints", [])
        if isinstance(hints_raw, (list, tuple)):
            hints = tuple(str(item) for item in hints_raw)
        else:
            hints = ()
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, Mapping):
            metadata = {}
        opcode_val = payload.get("opcode")
        handler_val = payload.get("handler")
        opcode: Optional[int]
        if opcode_val is None:
            opcode = None
        else:
            try:
                opcode = int(opcode_val)
            except (TypeError, ValueError):
                opcode = None
        handler = str(handler_val) if handler_val is not None else None
        return cls(
            block_id=block_id,
            kind=kind,
            start=start,
            end=end,
            successors=successors,
            opcode=opcode,
            handler=handler,
            hints=hints,
            metadata=metadata,
        )


@dataclass(frozen=True)
class CFG:
    """Container for dispatcher CFG data."""

    entry: str
    blocks: Tuple[CFGBlock, ...]

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> "CFG":
        entry = str(payload.get("entry", "entry"))
        block_payloads = payload.get("blocks", [])
        blocks: List[CFGBlock] = []
        if isinstance(block_payloads, Sequence):
            for block in block_payloads:
                if isinstance(block, Mapping):
                    blocks.append(CFGBlock.from_mapping(block))
        return cls(entry=entry, blocks=tuple(blocks))


def load_cfg(path: Path) -> CFG:
    """Load a CFG JSON file into :class:`CFG`."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:  # pragma: no cover - defensive guard
        raise SystemExit(f"cfg json not found: {path}") from exc
    except json.JSONDecodeError as exc:  # pragma: no cover - invalid data
        raise SystemExit(f"invalid cfg json: {path}: {exc}") from exc
    if not isinstance(raw, Mapping):  # pragma: no cover - defensive
        raise SystemExit(f"cfg json must be an object: {path}")
    return CFG.from_mapping(raw)


def _escape_label(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\"", "\\\"")


def _render_metadata(metadata: Mapping[str, object]) -> List[str]:
    lines: List[str] = []
    candidate_keys = (
        "ir_summary",
        "ir_ops",
        "ir",
        "operations",
        "ops",
        "description",
        "opaque_predicate",
        "trap_reason",
        "label",
    )
    for key in candidate_keys:
        value = metadata.get(key)
        if value in (None, ""):
            continue
        if "key" in key.lower():
            continue
        if isinstance(value, str):
            if "key" in value.lower():
                continue
            lines.append(f"{key}: {value}")
        elif isinstance(value, Mapping):
            if any("key" in str(k).lower() for k in value.keys()):
                continue
            summary = ", ".join(f"{k}={v}" for k, v in value.items())
            if "key" in summary.lower():
                continue
            lines.append(f"{key}: {summary}")
        elif isinstance(value, Sequence):
            parts: List[str] = []
            for item in value:
                if isinstance(item, Mapping):
                    fragment = ", ".join(f"{k}={v}" for k, v in item.items())
                else:
                    fragment = str(item)
                if "key" in fragment.lower():
                    continue
                parts.append(fragment)
            if parts:
                lines.append(f"{key}: {', '.join(parts)}")
        else:
            lines.append(f"{key}: {value}")
    return lines


def _summarise_block(block: CFGBlock) -> List[str]:
    lines = [f"{block.block_id} [{block.kind}]", f"range: {block.start}-{block.end}"]
    if block.opcode is not None:
        lines.append(f"opcode: {block.opcode}")
    if block.handler:
        lines.append(f"handler: {block.handler}")
    if block.hints:
        cleaned_hints = [hint for hint in block.hints if "key" not in hint.lower()]
        if cleaned_hints:
            lines.append("hints: " + ", ".join(cleaned_hints))
    if block.metadata:
        lines.extend(_render_metadata(block.metadata))
    return lines


def render_cfg_dot(cfg: CFG, *, title: Optional[str] = None) -> str:
    """Render *cfg* as DOT text."""

    lines = ["digraph CFG {"]
    lines.append("  graph [rankdir=LR, splines=true, nodesep=0.6, fontname=Helvetica, fontsize=10];")
    lines.append("  node [shape=box, style=rounded, fontname=Helvetica, fontsize=9, align=left];")
    lines.append("  edge [fontname=Helvetica, fontsize=8];")
    if title:
        lines.append(f'  label="{_escape_label(title)}";')
        lines.append("  labelloc=\"t\";")
    entry = cfg.entry
    for block in cfg.blocks:
        label_lines = _summarise_block(block)
        label_text = "\\l".join(_escape_label(line) for line in label_lines) + "\\l"
        attrs: List[str] = [f'label="{label_text}"]']
        if block.block_id == entry:
            attrs.extend(["peripheries=2", "shape=doubleoctagon"])
        elif block.kind.lower() == "trap":
            attrs.extend(["color=\"#b0413e\"", "fontcolor=\"#b0413e\""])
        elif block.kind.lower() == "branch":
            attrs.append("color=\"#2a6f97\"")
        node_decl = f'  "{_escape_label(block.block_id)}" [' + ", ".join(attrs) + "];"
        lines.append(node_decl)
        for successor in block.successors:
            if not successor:
                continue
            edge = f'  "{_escape_label(block.block_id)}" -> "{_escape_label(str(successor))}";'
            lines.append(edge)
    lines.append("}")
    return "\n".join(lines) + "\n"


def _try_render_with_graphviz(dot: str, destination: Path) -> bool:
    try:
        from graphviz import Source  # type: ignore
    except Exception:  # pragma: no cover - optional dependency missing
        Source = None
    if Source is not None:
        try:
            svg_bytes = Source(dot).pipe(format="svg")
        except Exception as exc:  # pragma: no cover - runtime error
            LOGGER.debug("Graphviz.Source render failed: %s", exc)
        else:
            destination.write_bytes(svg_bytes)
            return True
    dot_exec = shutil.which("dot")
    if dot_exec:
        try:
            proc = subprocess.run(
                [dot_exec, "-Tsvg"],
                input=dot.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - environment specific
            LOGGER.debug("dot command failed: %s", exc)
        else:
            destination.write_bytes(proc.stdout)
            return True
    return False


def _fallback_svg(cfg: CFG, title: Optional[str]) -> str:
    lines: List[str] = []
    width = 640
    line_height = 16
    padding = 20
    total_lines = sum(len(_summarise_block(block)) + 1 for block in cfg.blocks)
    total_height = padding * 2 + max(1, total_lines) * line_height
    lines.append(
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{total_height}' viewBox='0 0 {width} {total_height}'>"
    )
    y = padding
    if title:
        lines.append(
            f"  <text x='{width/2:.1f}' y='{y}' font-family='Helvetica' font-size='16' text-anchor='middle'>{_escape_label(title)}</text>"
        )
        y += line_height * 2
    for block in cfg.blocks:
        lines.append(
            f"  <text x='{padding}' y='{y}' font-family='Courier' font-size='12' fill='#1f2933'>{_escape_label(block.block_id)}:</text>"
        )
        y += line_height
        for detail in _summarise_block(block):
            lines.append(
                f"  <text x='{padding + 20}' y='{y}' font-family='Courier' font-size='11' fill='#334155'>{_escape_label(detail)}</text>"
            )
            y += line_height
        y += line_height // 2
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def write_cfg_visualisation(cfg: CFG, output_dir: Path, candidate: str, *, title: Optional[str] = None) -> Tuple[Path, Path]:
    """Write DOT and SVG artefacts for *cfg* and return their paths."""

    output_dir.mkdir(parents=True, exist_ok=True)
    dot_path = output_dir / f"{candidate}.dot"
    svg_path = output_dir / f"{candidate}.svg"

    dot_text = render_cfg_dot(cfg, title=title)
    dot_path.write_text(dot_text, encoding="utf-8")

    if not _try_render_with_graphviz(dot_text, svg_path):
        svg_path.write_text(_fallback_svg(cfg, title), encoding="utf-8")
    return dot_path, svg_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Render dispatcher CFG JSON to DOT/SVG")
    parser.add_argument("source", type=Path, help="Path to cfg JSON produced by block_recover")
    parser.add_argument(
        "--candidate",
        default=None,
        help="Candidate name used for output filenames (default: derived from source)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out/cfg"),
        help="Directory for DOT/SVG artefacts (default: out/cfg)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Print generated paths for convenience",
    )
    args = parser.parse_args(argv)

    cfg = load_cfg(args.source)
    candidate = args.candidate or args.source.stem
    dot_path, svg_path = write_cfg_visualisation(cfg, args.output_dir, candidate, title=candidate)
    if args.open:
        print(dot_path)
        print(svg_path)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
