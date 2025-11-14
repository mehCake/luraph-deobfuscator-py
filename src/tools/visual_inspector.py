"""Interactive IR inspector and rename-map helper.

This module provides a lightweight text user interface (TUI) that allows an
analyst to review lifted intermediate representation (IR) payloads produced by
the Luraph tooling pipeline.  The inspector focuses on safety: it never
executes untrusted code, does not persist sensitive keys, and requires explicit
confirmation before writing any artefacts to disk.

Typical usage::

    python -m src.tools.visual_inspector out/ir/candidate.json

Once launched, the tool offers navigation commands (``next``, ``prev``,
``block``) to step through the IR, utilities to preview associated raw bytes,
and helpers to stage ad-hoc rename maps.  Rename maps can be exported to
``out/rename_maps/manual-<timestamp>.json`` after the user acknowledges a
warning about writing to disk.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from cmd import Cmd
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from . import heuristics  # re-exported for existing CLI expectations

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# data loading helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> MutableMapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, MutableMapping):
        raise TypeError(f"Expected JSON object in {path}")
    return payload


def _normalise_blocks(payload: Mapping[str, Any]) -> List[MutableMapping[str, Any]]:
    program = payload.get("program", payload)
    blocks = program.get("blocks", [])
    if not isinstance(blocks, Iterable):
        raise TypeError("IR payload does not contain block list")
    result: List[MutableMapping[str, Any]] = []
    for raw_block in blocks:
        if not isinstance(raw_block, MutableMapping):
            raise TypeError("IR block is not a mapping")
        block_id = raw_block.get("id") or raw_block.get("block_id")
        if not block_id:
            raise ValueError("IR block is missing an identifier")
        block = dict(raw_block)
        block.setdefault("ops", [])
        block.setdefault("metadata", {})
        block.setdefault("raw_offsets", [])
        block.setdefault("start_index", 0)
        block.setdefault("end_index", block["start_index"])
        block["id"] = block_id
        result.append(block)
    if not result:
        raise ValueError("IR payload does not contain any blocks")
    return result


def _guess_byte_path(payload: Mapping[str, Any], ir_path: Path) -> Optional[Path]:
    metadata_sources: Sequence[Mapping[str, Any]] = []
    program = payload.get("program")
    if isinstance(program, Mapping):
        metadata = program.get("metadata")
        if isinstance(metadata, Mapping):
            metadata_sources = [metadata]
    fallback = payload.get("metadata")
    if isinstance(fallback, Mapping):
        metadata_sources = [*metadata_sources, fallback]

    candidate_keys = {
        "bytecode_path",
        "raw_bytes_path",
        "byte_path",
        "payload_path",
        "bytecode_file",
    }

    for source in metadata_sources:
        for key in candidate_keys:
            value = source.get(key)
            if isinstance(value, str):
                candidate = (ir_path.parent / value).resolve()
                if candidate.exists():
                    return candidate
    return None


def _format_operand(operand: Mapping[str, Any], rename_map: Mapping[str, str]) -> str:
    kind = str(operand.get("kind", "")).lower()
    value = operand.get("value")
    alias = None

    if kind == "reg" and value is not None:
        alias = rename_map.get(f"R{int(value)}")
    elif kind == "proto" and value is not None:
        alias = rename_map.get(f"PROTO_{int(value)}")

    resolved = operand.get("resolved")
    field = operand.get("field", "?")

    parts = [f"{field}={value}"]
    if resolved is not None:
        parts.append(f"resolved={resolved!r}")
    if alias:
        parts.append(f"alias={alias}")
    return " ".join(parts)


def _hexdump(data: bytes, *, start: int = 0, width: int = 16) -> str:
    lines: List[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02X}" for byte in chunk)
        lines.append(f"0x{start + offset:08X}: {hex_bytes}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# core inspector
# ---------------------------------------------------------------------------


@dataclass
class InspectorState:
    blocks: List[MutableMapping[str, Any]]
    block_index: Dict[str, int]
    current_block: int = 0
    current_op: int = 0


class VisualInspector:
    """Maintain navigation state for an IR payload."""

    def __init__(
        self,
        payload: MutableMapping[str, Any],
        *,
        ir_path: Path,
        raw_bytes_path: Optional[Path] = None,
    ) -> None:
        self.payload = payload
        self.ir_path = ir_path
        self.blocks = _normalise_blocks(payload)
        self.state = InspectorState(
            blocks=self.blocks,
            block_index={block["id"]: index for index, block in enumerate(self.blocks)},
        )
        self.rename_map: Dict[str, str] = {}
        self._warned_about_edits = False
        self.raw_bytes_path = raw_bytes_path or _guess_byte_path(payload, ir_path)

    # ------------------------------------------------------------------
    # navigation helpers
    # ------------------------------------------------------------------

    def list_blocks(self) -> List[str]:
        return [block["id"] for block in self.blocks]

    def current(self) -> MutableMapping[str, Any]:
        return self.blocks[self.state.current_block]

    def current_op(self) -> Mapping[str, Any]:
        block = self.current()
        ops = block.get("ops", [])
        if not ops:
            raise IndexError("Current block does not contain any operations")
        return ops[self.state.current_op]

    def describe_current(self) -> str:
        block = self.current()
        op = self.current_op()
        offset = None
        offsets = block.get("raw_offsets") or []
        if isinstance(offsets, Sequence) and offsets:
            try:
                offset = int(offsets[self.state.current_op])
            except (ValueError, TypeError, IndexError):
                offset = None

        operands = op.get("operands", [])
        operand_desc = ", ".join(
            _format_operand(operand, self.rename_map) for operand in operands
        )
        comment_parts = []
        if offset is not None:
            comment_parts.append(f"offset=0x{offset:04X}")
        raw = op.get("raw")
        if isinstance(raw, int):
            comment_parts.append(f"raw=0x{raw:08X}")
        comment = f" -- {' '.join(comment_parts)}" if comment_parts else ""
        return (
            f"[{block['id']} #{self.state.current_op}] {op.get('mnemonic', 'UNKNOWN')}"
            f"({operand_desc}){comment}"
        )

    def step(self, delta: int) -> str:
        block = self.current()
        ops = block.get("ops", [])
        if not ops:
            raise IndexError("Cannot step: current block has no operations")

        new_index = self.state.current_op + delta
        if 0 <= new_index < len(ops):
            self.state.current_op = new_index
        else:
            new_block = self.state.current_block + (1 if delta > 0 else -1)
            if 0 <= new_block < len(self.blocks):
                self.state.current_block = new_block
                self.state.current_op = 0 if delta > 0 else max(
                    0, len(self.blocks[new_block].get("ops", [])) - 1
                )
            else:
                raise IndexError("Cannot move beyond available blocks")
        return self.describe_current()

    def goto_block(self, block_id: str) -> str:
        if block_id not in self.state.block_index:
            raise KeyError(f"Unknown block {block_id}")
        self.state.current_block = self.state.block_index[block_id]
        self.state.current_op = 0
        return self.describe_current()

    # ------------------------------------------------------------------
    # rename helpers
    # ------------------------------------------------------------------

    def _ensure_edit_warning(self) -> None:
        if not self._warned_about_edits:
            LOGGER.warning(
                "Edits modify in-memory state only. Keys must be supplied explicitly"
                " and will never be written to disk."
            )
            self._warned_about_edits = True

    def set_alias(self, target: str, alias: str) -> None:
        if not target:
            raise ValueError("Target register/function cannot be empty")
        if not alias:
            raise ValueError("Alias cannot be empty")
        normalised = target.upper()
        if not (normalised.startswith("R") or normalised.startswith("PROTO_")):
            raise ValueError("Targets must start with 'R' or 'PROTO_'")
        self._ensure_edit_warning()
        self.rename_map[normalised] = alias

    def clear_alias(self, target: str) -> None:
        normalised = target.upper()
        self._ensure_edit_warning()
        self.rename_map.pop(normalised, None)

    def export_manual_map(self, *, out_dir: Path = Path("out/rename_maps")) -> Path:
        if not self.rename_map:
            raise ValueError("No rename entries to export")
        self._ensure_edit_warning()
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        path = out_dir / f"manual-{timestamp}.json"
        payload = {
            "source": str(self.ir_path),
            "created_utc": timestamp,
            "rename_map": dict(self.rename_map),
        }
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        LOGGER.info("Wrote rename map to %s", path)
        return path

    # ------------------------------------------------------------------
    # raw byte helpers
    # ------------------------------------------------------------------

    def preview_bytes(self, *, start: int = 0, count: int = 64) -> str:
        if self.raw_bytes_path is None:
            raise FileNotFoundError("No raw byte path associated with this IR")
        data = self.raw_bytes_path.read_bytes()
        slice_end = min(len(data), start + count)
        snippet = data[start:slice_end]
        return _hexdump(snippet, start=start)


# ---------------------------------------------------------------------------
# command shell
# ---------------------------------------------------------------------------


class InspectorShell(Cmd):
    intro = (
        "Visual inspector ready. Type 'help' to list commands."
        " This tool never persists keys and requires confirmation before saving."
    )
    prompt = "(visual) "

    def __init__(self, inspector: VisualInspector, *, auto_confirm: bool = False) -> None:
        super().__init__()
        self.inspector = inspector
        self.auto_confirm = auto_confirm

    # navigation --------------------------------------------------------

    def do_next(self, arg: str) -> None:  # type: ignore[override]
        """Advance to the next operation (alias: n)."""

        try:
            print(self.inspector.step(1))
        except Exception as exc:  # pragma: no cover - user feedback
            print(f"Error: {exc}")

    do_n = do_next

    def do_prev(self, arg: str) -> None:  # type: ignore[override]
        """Move to the previous operation (alias: p)."""

        try:
            print(self.inspector.step(-1))
        except Exception as exc:  # pragma: no cover - user feedback
            print(f"Error: {exc}")

    do_p = do_prev

    def do_block(self, arg: str) -> None:  # type: ignore[override]
        """Jump to a block by identifier: block block_3"""

        block_id = arg.strip()
        if not block_id:
            print("Usage: block <block_id>")
            return
        try:
            print(self.inspector.goto_block(block_id))
        except Exception as exc:  # pragma: no cover
            print(f"Error: {exc}")

    def do_list(self, arg: str) -> None:  # type: ignore[override]
        """List available block identifiers."""

        for block_id in self.inspector.list_blocks():
            print(block_id)

    def do_show(self, arg: str) -> None:  # type: ignore[override]
        """Show the current operation."""

        try:
            print(self.inspector.describe_current())
        except Exception as exc:  # pragma: no cover
            print(f"Error: {exc}")

    # rename operations -------------------------------------------------

    def do_rename(self, arg: str) -> None:  # type: ignore[override]
        """Assign an alias: rename R0 player_ctx"""

        parts = arg.split()
        if len(parts) != 2:
            print("Usage: rename <target> <alias>")
            return
        try:
            self.inspector.set_alias(parts[0], parts[1])
            print(f"Set alias {parts[0].upper()} -> {parts[1]}")
        except Exception as exc:  # pragma: no cover
            print(f"Error: {exc}")

    def do_unalias(self, arg: str) -> None:  # type: ignore[override]
        """Remove an alias: unalias R0"""

        target = arg.strip()
        if not target:
            print("Usage: unalias <target>")
            return
        self.inspector.clear_alias(target)
        print(f"Cleared alias for {target.upper()}")

    def do_aliases(self, arg: str) -> None:  # type: ignore[override]
        """List current alias assignments."""

        if not self.inspector.rename_map:
            print("(no aliases configured)")
            return
        for key, value in sorted(self.inspector.rename_map.items()):
            print(f"{key} -> {value}")

    def do_save(self, arg: str) -> None:  # type: ignore[override]
        """Persist aliases to out/rename_maps/manual-<timestamp>.json."""

        if not self.inspector.rename_map:
            print("Nothing to save")
            return
        if not self.auto_confirm:
            response = input("Write rename map to disk? [y/N] ").strip().lower()
            if response not in {"y", "yes"}:
                print("Aborted")
                return
        try:
            path = self.inspector.export_manual_map()
            print(f"Wrote rename map to {path}")
        except Exception as exc:  # pragma: no cover
            print(f"Error: {exc}")

    # byte helpers ------------------------------------------------------

    def do_bytes(self, arg: str) -> None:  # type: ignore[override]
        """Display a hexdump from the associated raw bytes file."""

        parts = arg.split()
        start = int(parts[0], 0) if parts else 0
        count = int(parts[1], 0) if len(parts) > 1 else 64
        try:
            print(self.inspector.preview_bytes(start=start, count=count))
        except Exception as exc:  # pragma: no cover
            print(f"Error: {exc}")

    # misc --------------------------------------------------------------

    def do_quit(self, arg: str) -> bool:  # type: ignore[override]
        """Exit the inspector."""

        print("Bye")
        return True

    do_exit = do_quit
    do_q = do_quit


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactive IR visual inspector")
    parser.add_argument("ir", type=Path, help="Path to IR JSON produced by the lifter")
    parser.add_argument(
        "--bytes",
        type=Path,
        default=None,
        help="Optional raw byte file associated with the IR",
    )
    parser.add_argument(
        "--commands",
        nargs="*",
        help="Optional non-interactive command list (used for scripting/tests)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Auto-confirm prompts (useful for automated testing)",
    )
    return parser


def _run_commands(shell: InspectorShell, commands: Sequence[str]) -> None:
    for command in commands:
        stripped = command.strip()
        if not stripped:
            continue
        shell.onecmd(stripped)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    ir_path: Path = args.ir
    if not ir_path.exists():
        parser.error(f"IR file {ir_path} does not exist")

    payload = _load_json(ir_path)
    inspector = VisualInspector(
        payload,
        ir_path=ir_path,
        raw_bytes_path=args.bytes,
    )

    shell = InspectorShell(inspector, auto_confirm=args.yes)

    if args.commands:
        _run_commands(shell, args.commands)
        return 0

    shell.cmdloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

