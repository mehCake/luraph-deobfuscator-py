"""Interactive helper for refining opcode mnemonic mappings."""

from __future__ import annotations

import argparse
import cmd
import json
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from .opcode_map import OpcodeMap

__all__ = [
    "HandlerInfo",
    "OpcodeMappingSession",
    "OpcodeMappingShell",
    "load_handler_index",
    "load_mapping_file",
    "main",
]


@dataclass
class HandlerInfo:
    """Aggregated details for a single opcode handler."""

    opcode: int
    handlers: List[str] = field(default_factory=list)
    bodies: List[str] = field(default_factory=list)
    candidates: List[str] = field(default_factory=list)

    def candidate_summary(self) -> str:
        if not self.candidates:
            return "-"
        return ", ".join(self.candidates[:4]) + (" …" if len(self.candidates) > 4 else "")

    def formatted_bodies(self, *, max_lines: int = 40) -> List[str]:
        blocks: List[str] = []
        for index, body in enumerate(self.bodies, start=1):
            if not body:
                continue
            lines = body.splitlines()
            if max_lines and len(lines) > max_lines:
                display = lines[: max_lines - 1] + ["…"]
            else:
                display = lines
            numbered = [f"{i + 1:>4}: {line}" for i, line in enumerate(display)]
            blocks.append(f"Handler variant {index}\n" + "\n".join(numbered))
        if not blocks:
            blocks.append("<no handler body available>")
        return blocks


@dataclass
class OpcodeMappingSession:
    """Stateful container used by the interactive shell and tests."""

    handlers: Mapping[int, HandlerInfo]
    mapping: MutableMapping[int, str] = field(default_factory=dict)

    def assign(self, opcode: int, mnemonic: str) -> None:
        self.mapping[opcode] = mnemonic.upper()

    def clear(self, opcode: int) -> None:
        self.mapping.pop(opcode, None)

    def to_opcode_map(self) -> OpcodeMap:
        opcode_map = OpcodeMap()
        for opcode, mnemonic in sorted(self.mapping.items()):
            opcode_map.register(opcode, mnemonic)
        return opcode_map

    def save(self, path: Path) -> Path:
        payload = self.to_opcode_map().as_dict()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path


class OpcodeMappingShell(cmd.Cmd):
    intro = "Interactive opcode mapping shell. Type 'help' for commands."
    prompt = "opcode-map> "

    def __init__(self, session: OpcodeMappingSession, output_path: Path):
        super().__init__()
        self.session = session
        self.output_path = output_path

    # Helpers -----------------------------------------------------------------

    def _parse_opcode(self, token: str) -> Optional[int]:
        token = token.strip()
        if not token:
            return None
        try:
            if token.lower().startswith("0x"):
                return int(token, 16)
            return int(token)
        except ValueError:
            self.stdout.write(f"Invalid opcode value: {token}\n")
            return None

    def _display_handler(self, opcode: int) -> None:
        info = self.session.handlers.get(opcode)
        if info is None:
            self.stdout.write(f"No handler information for opcode {opcode}.\n")
            return
        assigned = self.session.mapping.get(opcode, "<unassigned>")
        self.stdout.write(f"Opcode {opcode} — current mnemonic: {assigned}\n")
        if info.handlers:
            self.stdout.write("Handlers: " + ", ".join(info.handlers) + "\n")
        if info.candidates:
            self.stdout.write("Suggested mnemonics: " + ", ".join(info.candidates) + "\n")
        for block in info.formatted_bodies():
            self.stdout.write(textwrap.indent(block, "  ") + "\n")

    # Commands ----------------------------------------------------------------

    def do_list(self, arg: str) -> None:
        """List known opcodes and their current assignments."""

        for opcode in sorted(self.session.handlers):
            info = self.session.handlers[opcode]
            assigned = self.session.mapping.get(opcode, "<unset>")
            self.stdout.write(
                f"0x{opcode:02X} ({opcode:3d}) -> {assigned} | candidates: {info.candidate_summary()}\n"
            )

    def do_show(self, arg: str) -> None:
        """show <opcode> -- Display handler body for an opcode."""

        opcode = self._parse_opcode(arg)
        if opcode is None:
            return
        self._display_handler(opcode)

    def do_set(self, arg: str) -> None:
        """set <opcode> <mnemonic> -- Assign mnemonic to opcode."""

        parts = arg.split()
        if len(parts) < 2:
            self.stdout.write("Usage: set <opcode> <mnemonic>\n")
            return
        opcode = self._parse_opcode(parts[0])
        if opcode is None:
            return
        mnemonic = parts[1]
        self.session.assign(opcode, mnemonic)
        self.stdout.write(f"Set opcode {opcode} to {mnemonic.upper()}\n")

    def do_clear(self, arg: str) -> None:
        """clear <opcode> -- Remove mnemonic assignment."""

        opcode = self._parse_opcode(arg)
        if opcode is None:
            return
        self.session.clear(opcode)
        self.stdout.write(f"Cleared opcode {opcode}\n")

    def do_save(self, arg: str) -> None:
        """save [path] -- Save mapping to disk."""

        path = self.output_path
        if arg.strip():
            path = Path(arg.strip())
        saved = self.session.save(path)
        self.stdout.write(f"Wrote mapping to {saved}\n")

    def do_quit(self, arg: str) -> bool:  # type: ignore[override]
        """Exit the shell."""

        return True

    def do_exit(self, arg: str) -> bool:  # type: ignore[override]
        return self.do_quit(arg)

    def do_EOF(self, arg: str) -> bool:  # type: ignore[override]
        self.stdout.write("\n")
        return self.do_quit(arg)


# ---------------------------------------------------------------------------


def load_handler_index(pipeline_report: Mapping[str, object]) -> Dict[int, HandlerInfo]:
    """Build a mapping of opcode -> handler metadata from pipeline JSON."""

    handlers: Dict[int, HandlerInfo] = {}

    def ensure(opcode: int) -> HandlerInfo:
        info = handlers.get(opcode)
        if info is None:
            info = HandlerInfo(opcode=opcode)
            handlers[opcode] = info
        return info

    chunk_entries = pipeline_report.get("chunks")
    if isinstance(chunk_entries, Sequence):
        for chunk in chunk_entries:
            if not isinstance(chunk, Mapping):
                continue
            for handler_entry in chunk.get("handler_map", []) or []:
                if not isinstance(handler_entry, Mapping):
                    continue
                try:
                    opcode = int(handler_entry.get("opcode"))
                except (TypeError, ValueError):
                    continue
                info = ensure(opcode)
                handler_name = handler_entry.get("handler")
                if isinstance(handler_name, str) and handler_name and handler_name not in info.handlers:
                    info.handlers.append(handler_name)
                mnemonics = handler_entry.get("mnemonics") or []
                if isinstance(mnemonics, Mapping):
                    mnemonic_iter: Iterable[str] = (
                        str(value) for value in mnemonics.values() if value
                    )
                else:
                    mnemonic_iter = (
                        str(value) for value in mnemonics if isinstance(value, str) and value
                    )
                for mnemonic in mnemonic_iter:
                    upper = mnemonic.upper()
                    if upper not in info.candidates:
                        info.candidates.append(upper)
                body = handler_entry.get("body")
                if isinstance(body, str) and body and body not in info.bodies:
                    info.bodies.append(body)

    mnemonic_table = pipeline_report.get("opcode_mnemonics")
    if isinstance(mnemonic_table, Mapping):
        for opcode_key, values in mnemonic_table.items():
            try:
                opcode = int(opcode_key)
            except (TypeError, ValueError):
                continue
            info = ensure(opcode)
            if isinstance(values, Mapping):
                iterable: Iterable[str] = (
                    str(value) for value in values.values() if isinstance(value, str)
                )
            else:
                iterable = (
                    str(value) for value in values
                    if isinstance(value, str)
                )
            for mnemonic in iterable:
                upper = mnemonic.upper()
                if upper not in info.candidates:
                    info.candidates.append(upper)

    for info in handlers.values():
        info.handlers.sort()
        info.candidates.sort()

    return handlers


def load_mapping_file(path: Path) -> Dict[int, str]:
    """Load an existing mapping file or candidate output."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return {}
    except json.JSONDecodeError:
        return {}

    mapping: Dict[int, str] = {}
    if isinstance(payload, Mapping):
        if "mnemonics" in payload and isinstance(payload["mnemonics"], Mapping):
            for opcode, mnemonic in payload["mnemonics"].items():
                try:
                    mapping[int(opcode)] = str(mnemonic).upper()
                except (TypeError, ValueError):
                    continue
        elif "mapping" in payload and isinstance(payload["mapping"], Mapping):
            for opcode, mnemonic in payload["mapping"].items():
                try:
                    mapping[int(opcode)] = str(mnemonic).upper()
                except (TypeError, ValueError):
                    continue
    return mapping


def _initial_mapping(args: argparse.Namespace, default_path: Path) -> Dict[int, str]:
    if args.map is not None:
        return load_mapping_file(args.map)
    if default_path.exists():
        return load_mapping_file(default_path)
    return {}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Interactive opcode mapping helper")
    parser.add_argument(
        "--pipeline",
        type=Path,
        default=Path("out") / "pipeline_candidates.json",
        help="Pipeline candidate JSON generated by run_all_detection",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out") / "opcode_maps" / "manual_map.json",
        help="Destination JSON file for the curated opcode map",
    )
    parser.add_argument(
        "--map",
        type=Path,
        help="Optional existing map to preload assignments",
    )

    args = parser.parse_args(argv)

    if not args.pipeline.is_file():
        parser.error(f"Pipeline report not found: {args.pipeline}")

    pipeline_payload = json.loads(args.pipeline.read_text(encoding="utf-8"))
    handler_index = load_handler_index(pipeline_payload)
    if not handler_index:
        parser.error("No handler information found in pipeline report")

    session = OpcodeMappingSession(
        handlers=handler_index,
        mapping=_initial_mapping(args, args.output),
    )

    shell = OpcodeMappingShell(session, args.output)
    shell.cmdloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
