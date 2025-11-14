"""Interactive opcode map editor with undo and merge support.

This module provides a terminal-friendly workflow for reviewing opcode handler
suggestions, vetting mnemonic proposals, and persisting an "approved" opcode
map without clobbering previous research.  It never executes untrusted code and
never stores sensitive keys; all actions operate on JSON artefacts already
produced by the static analysis pipeline.

Typical usage::

    python -m src.tools.interactive_map_editor \
        --handlers out/handler_suggestions.json \
        --proposals out/opcode_proposals.json \
        --candidate candidate-01

The editor loads handler bodies (when available), proposed mnemonics, and any
pre-existing approved maps.  Analysts can walk through each opcode, accept or
modify suggestions using single-key shortcuts, and rely on the built-in undo and
merge facilities to experiment safely.  Each accepted change is written to
``out/opcode_maps/approved-<candidate>.json`` by default while preserving
existing assignments.
"""

from __future__ import annotations

import argparse
import json
import logging
from cmd import Cmd
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from src.vm.opcode_map import OpcodeMap, load_map

LOGGER = logging.getLogger(__name__)

DEFAULT_VERSION = "14.4.2"
DEFAULT_OUTPUT_DIR = Path("out/opcode_maps")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class HandlerEntry:
    """Describes a single opcode handler suggestion."""

    opcode: int
    name: str
    body: str
    suggestions: Tuple[str, ...] = ()
    proposed: Optional[str] = None

    def default_choice(self) -> Optional[str]:
        if self.proposed:
            return self.proposed
        if self.suggestions:
            return self.suggestions[0]
        return None

    def render_body(self, *, max_lines: int = 40) -> str:
        if not self.body:
            return "<no handler body available>"
        lines = self.body.splitlines()
        if max_lines and len(lines) > max_lines:
            lines = lines[: max_lines - 1] + ["…"]
        return "\n".join(f"{index + 1:>4}: {line}" for index, line in enumerate(lines))


@dataclass
class HistoryEntry:
    opcode: int
    previous: Optional[str]
    current: Optional[str]
    reason: str


@dataclass
class MapEditorSession:
    """State container for the interactive opcode map editor."""

    entries: List[HandlerEntry]
    candidate_name: str
    output_path: Path
    version_hint: str = DEFAULT_VERSION
    auto_save: bool = True
    mapping: MutableMapping[int, str] = field(default_factory=dict)
    history: List[HistoryEntry] = field(default_factory=list)
    current_index: int = 0

    def __post_init__(self) -> None:
        self.entries.sort(key=lambda entry: entry.opcode)
        if self.entries:
            self.current_index = 0

    # Convenience -----------------------------------------------------------------

    def _entry_by_opcode(self, opcode: int) -> Optional[HandlerEntry]:
        for entry in self.entries:
            if entry.opcode == opcode:
                return entry
        return None

    def current_entry(self) -> HandlerEntry:
        if not self.entries:
            raise IndexError("No handler entries available")
        return self.entries[self.current_index]

    def step(self, delta: int) -> int:
        if not self.entries:
            return 0
        self.current_index = (self.current_index + delta) % len(self.entries)
        return self.current_index

    # Mapping management -----------------------------------------------------------

    def _record_change(self, opcode: int, previous: Optional[str], current: Optional[str], reason: str) -> None:
        if previous == current:
            return
        self.history.append(HistoryEntry(opcode=opcode, previous=previous, current=current, reason=reason))

    def accept(self, mnemonic: Optional[str] = None, *, advance: bool = True) -> str:
        entry = self.current_entry()
        choice = mnemonic or entry.default_choice()
        if not choice:
            raise ValueError("No mnemonic provided for acceptance")
        choice = choice.upper()
        previous = self.mapping.get(entry.opcode)
        self.mapping[entry.opcode] = choice
        entry.proposed = choice
        self._record_change(entry.opcode, previous, choice, "accept")
        if self.auto_save:
            self.save()
        if advance:
            self.step(1)
        return choice

    def modify(self, mnemonic: str, *, advance: bool = False) -> str:
        if not mnemonic:
            raise ValueError("Mnemonic must be non-empty")
        entry = self.current_entry()
        previous = self.mapping.get(entry.opcode)
        choice = mnemonic.upper()
        self.mapping[entry.opcode] = choice
        entry.proposed = choice
        self._record_change(entry.opcode, previous, choice, "modify")
        if self.auto_save:
            self.save()
        if advance:
            self.step(1)
        return choice

    def reject(self, *, advance: bool = True) -> bool:
        entry = self.current_entry()
        previous = self.mapping.pop(entry.opcode, None)
        entry.proposed = None
        if previous is None:
            if advance:
                self.step(1)
            return False
        self._record_change(entry.opcode, previous, None, "reject")
        if self.auto_save:
            self.save()
        if advance:
            self.step(1)
        return True

    def merge_from_map(self, other: Mapping[int, str], *, reason: str = "merge") -> None:
        for opcode, mnemonic in other.items():
            entry = self._entry_by_opcode(opcode)
            previous = self.mapping.get(opcode)
            upper = mnemonic.upper()
            self.mapping[opcode] = upper
            if entry is not None:
                entry.proposed = upper
            self._record_change(opcode, previous, upper, reason)
        if self.auto_save:
            self.save()

    def undo(self) -> Optional[HistoryEntry]:
        if not self.history:
            return None
        last = self.history.pop()
        if last.previous is None:
            self.mapping.pop(last.opcode, None)
        else:
            self.mapping[last.opcode] = last.previous
        entry = self._entry_by_opcode(last.opcode)
        if entry is not None:
            entry.proposed = self.mapping.get(last.opcode)
        if self.auto_save:
            self.save()
        return last

    def to_opcode_map(self) -> OpcodeMap:
        opcode_map = OpcodeMap()
        for opcode, mnemonic in sorted(self.mapping.items()):
            opcode_map.mnemonics[opcode] = mnemonic
        return opcode_map

    def save(self) -> Path:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        current_map = self.to_opcode_map()
        if self.output_path.exists():
            try:
                existing = load_map(self.output_path)
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.warning("Unable to load existing map %s: %s", self.output_path, exc)
                existing = None
            if existing is not None:
                for opcode, mnemonic in current_map.mnemonics.items():
                    existing.mnemonics[opcode] = mnemonic
                payload = existing.as_dict()
            else:
                payload = current_map.as_dict()
        else:
            payload = current_map.as_dict()
        self.output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        LOGGER.info("wrote approved map to %s", self.output_path)
        return self.output_path

    # Display helpers -------------------------------------------------------------

    def status_lines(self) -> List[str]:
        lines: List[str] = []
        for entry in self.entries:
            assigned = self.mapping.get(entry.opcode)
            suggestion = entry.proposed or entry.default_choice() or "<none>"
            status = assigned or "<unassigned>"
            lines.append(
                f"0x{entry.opcode:02X} ({entry.opcode:3d}) -> {status} | suggested: {suggestion} | handler: {entry.name}"
            )
        return lines


# ---------------------------------------------------------------------------
# Loading utilities
# ---------------------------------------------------------------------------


def _normalise_candidates(entry: Mapping[str, object]) -> Tuple[str, ...]:
    suggestions: List[str] = []
    raw_candidates = entry.get("candidates")
    if isinstance(raw_candidates, Sequence) and not isinstance(raw_candidates, (str, bytes)):
        for candidate in raw_candidates:
            if isinstance(candidate, Mapping):
                mnemonic = candidate.get("mnemonic")
                if isinstance(mnemonic, str):
                    suggestions.append(mnemonic.upper())
            elif isinstance(candidate, str):
                suggestions.append(candidate.upper())
    elif isinstance(raw_candidates, str):
        suggestions.append(raw_candidates.upper())
    return tuple(dict.fromkeys(suggestions))


def load_handler_entries(path: Path) -> List[HandlerEntry]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - filesystem
        LOGGER.error("Unable to load handler suggestions from %s: %s", path, exc)
        return []

    entries: List[HandlerEntry] = []
    candidates: Iterable[Mapping[str, object]]
    if isinstance(payload, Mapping) and isinstance(payload.get("handlers"), Sequence):
        candidates = [item for item in payload["handlers"] if isinstance(item, Mapping)]
    elif isinstance(payload, Sequence):
        candidates = [item for item in payload if isinstance(item, Mapping)]
    else:
        candidates = []

    for item in candidates:
        opcode = item.get("opcode")
        if opcode is None:
            continue
        try:
            opcode_int = int(opcode)
        except (TypeError, ValueError):
            continue
        name = str(item.get("name", f"opcode_{opcode_int}"))
        body_fields = ("body", "source", "snippet", "text")
        body = ""
        for field in body_fields:
            value = item.get(field)
            if isinstance(value, str) and value.strip():
                body = value
                break
        suggestions = _normalise_candidates(item)
        proposed = None
        if isinstance(item.get("proposed"), str):
            proposed = str(item["proposed"]).upper()
        entries.append(HandlerEntry(opcode=opcode_int, name=name, body=body, suggestions=suggestions, proposed=proposed))
    return entries


def load_candidate_mapping(path: Optional[Path], *, candidate: Optional[str] = None) -> Tuple[str, Dict[int, str]]:
    """Return ``(candidate_name, mapping)`` from a proposal or map file."""

    if path is None:
        return (candidate or "manual", {})

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - filesystem
        LOGGER.error("Unable to read opcode proposals from %s: %s", path, exc)
        return (candidate or path.stem, {})

    def _normalise_mapping(raw: Mapping[str, object]) -> Dict[int, str]:
        mapping: Dict[int, str] = {}
        for key, value in raw.items():
            try:
                opcode = int(key)
            except (TypeError, ValueError):
                continue
            if isinstance(value, str):
                mapping[opcode] = value.upper()
        return mapping

    if isinstance(payload, Mapping):
        candidates = payload.get("candidates")
        if isinstance(candidates, Sequence):
            selected: Optional[Mapping[str, object]] = None
            fallback: Optional[Mapping[str, object]] = None
            for entry in candidates:
                if not isinstance(entry, Mapping):
                    continue
                mapping_obj = entry.get("mapping")
                if not isinstance(mapping_obj, Mapping):
                    continue
                entry_name = str(entry.get("name") or entry.get("label") or f"candidate-{entry.get('rank', 0)}")
                if candidate and candidate == entry_name:
                    selected = entry
                    break
                if fallback is None:
                    fallback = entry
            target = selected or fallback
            if target:
                mapping = _normalise_mapping(target.get("mapping", {}))  # type: ignore[arg-type]
                chosen_name = candidate or str(target.get("name") or target.get("label") or path.stem)
                return (chosen_name, mapping)
        if "map" in payload and isinstance(payload["map"], Mapping):
            mapping = _normalise_mapping(payload["map"].get("mnemonics", {}))  # type: ignore[arg-type]
            return (candidate or path.stem, mapping)
        if "mnemonics" in payload and isinstance(payload["mnemonics"], Mapping):
            return (candidate or path.stem, _normalise_mapping(payload["mnemonics"]))
        if "mapping" in payload and isinstance(payload["mapping"], Mapping):
            return (candidate or path.stem, _normalise_mapping(payload["mapping"]))
    return (candidate or path.stem, {})


def load_base_mapping(path: Optional[Path]) -> Dict[int, str]:
    if path is None:
        return {}
    try:
        opcode_map = load_map(path)
    except Exception as exc:  # pragma: no cover - filesystem
        LOGGER.error("Unable to load base opcode map from %s: %s", path, exc)
        return {}
    return dict(opcode_map.mnemonics)


def create_session(
    *,
    entries: Sequence[HandlerEntry],
    candidate_name: str,
    proposed_mapping: Mapping[int, str],
    base_mapping: Mapping[int, str],
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    version_hint: str = DEFAULT_VERSION,
) -> MapEditorSession:
    session_entries = [HandlerEntry(**vars(entry)) for entry in entries]
    for entry in session_entries:
        if entry.opcode in proposed_mapping:
            entry.proposed = proposed_mapping[entry.opcode]
    output_path = output_dir / f"approved-{candidate_name}.json"
    session = MapEditorSession(
        entries=session_entries,
        candidate_name=candidate_name,
        output_path=output_path,
        version_hint=version_hint,
    )
    session.mapping.update({opcode: mnemonic.upper() for opcode, mnemonic in base_mapping.items()})
    return session


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------


class MapEditorShell(Cmd):
    intro = "Interactive opcode map editor. Type 'help' for commands."
    prompt = "map-editor> "

    def __init__(self, session: MapEditorSession) -> None:
        super().__init__()
        self.session = session

    # Utility --------------------------------------------------------------------

    def _display_current(self) -> None:
        try:
            entry = self.session.current_entry()
        except IndexError:
            self.stdout.write("No handler entries loaded.\n")
            return
        assigned = self.session.mapping.get(entry.opcode, "<unassigned>")
        suggestion = entry.default_choice() or "<none>"
        self.stdout.write(f"Opcode 0x{entry.opcode:02X} ({entry.opcode}) — handler {entry.name}\n")
        self.stdout.write(f"  Current mnemonic : {assigned}\n")
        self.stdout.write(f"  Suggested mnemonic: {suggestion}\n")
        if entry.suggestions:
            self.stdout.write("  Ranked suggestions: " + ", ".join(entry.suggestions) + "\n")
        self.stdout.write("  Handler body:\n")
        self.stdout.write(entry.render_body() + "\n")

    def _parse_opcode(self, token: str) -> Optional[int]:
        token = token.strip()
        if not token:
            return None
        try:
            return int(token, 0)
        except ValueError:
            self.stdout.write(f"Invalid opcode: {token}\n")
            return None

    # Commands -------------------------------------------------------------------

    def do_show(self, arg: str) -> None:
        """Show the current handler entry or a specific opcode."""

        if arg.strip():
            opcode = self._parse_opcode(arg)
            if opcode is None:
                return
            for index, entry in enumerate(self.session.entries):
                if entry.opcode == opcode:
                    self.session.current_index = index
                    break
            else:
                self.stdout.write(f"Opcode {opcode} not present in session.\n")
                return
        self._display_current()

    def do_next(self, arg: str) -> None:  # noqa: ARG002 - interface requirement
        """Move to the next handler entry."""

        self.session.step(1)
        self._display_current()

    def do_prev(self, arg: str) -> None:  # noqa: ARG002 - interface requirement
        """Move to the previous handler entry."""

        self.session.step(-1)
        self._display_current()

    def do_accept(self, arg: str) -> None:
        """Accept the proposed mnemonic for the current opcode."""

        mnemonic = arg.strip() or None
        try:
            chosen = self.session.accept(mnemonic)
        except ValueError as exc:
            self.stdout.write(str(exc) + "\n")
            return
        self.stdout.write(f"Accepted mnemonic {chosen} for opcode 0x{self.session.history[-1].opcode:02X}.\n")
        self._display_current()

    def do_modify(self, arg: str) -> None:
        """modify <mnemonic> -- Set a custom mnemonic for the current opcode."""

        mnemonic = arg.strip()
        if not mnemonic:
            self.stdout.write("Usage: modify <mnemonic>\n")
            return
        try:
            chosen = self.session.modify(mnemonic)
        except ValueError as exc:
            self.stdout.write(str(exc) + "\n")
            return
        self.stdout.write(f"Set mnemonic to {chosen}.\n")
        self._display_current()

    def do_reject(self, arg: str) -> None:  # noqa: ARG002 - interface requirement
        """Reject the current mnemonic assignment."""

        changed = self.session.reject()
        if changed:
            self.stdout.write("Cleared mnemonic assignment.\n")
        else:
            self.stdout.write("No mnemonic was assigned to clear.\n")
        self._display_current()

    def do_undo(self, arg: str) -> None:  # noqa: ARG002 - interface requirement
        """Undo the last mapping change."""

        result = self.session.undo()
        if result is None:
            self.stdout.write("No history to undo.\n")
        else:
            previous = result.previous or "<unset>"
            self.stdout.write(
                f"Restored opcode 0x{result.opcode:02X} to {previous}. (from {result.reason})\n"
            )
        self._display_current()

    def do_merge(self, arg: str) -> None:
        """merge <path> -- Merge assignments from another map JSON."""

        path_text = arg.strip()
        if not path_text:
            self.stdout.write("Usage: merge <path>\n")
            return
        path = Path(path_text)
        if not path.exists():
            self.stdout.write(f"Path {path} does not exist.\n")
            return
        merged = load_base_mapping(path)
        if not merged:
            self.stdout.write("No mnemonics found to merge.\n")
            return
        self.session.merge_from_map(merged, reason=f"merge:{path.name}")
        self.stdout.write(f"Merged {len(merged)} entries from {path}.\n")
        self._display_current()

    def do_save(self, arg: str) -> None:  # noqa: ARG002 - interface requirement
        """Persist the current mapping to disk."""

        path = self.session.save()
        self.stdout.write(f"Mapping saved to {path}.\n")

    def do_list(self, arg: str) -> None:  # noqa: ARG002 - interface requirement
        """List all opcodes and their current status."""

        for line in self.session.status_lines():
            self.stdout.write(line + "\n")

    def do_quit(self, arg: str) -> bool:  # noqa: ARG002 - interface requirement
        """Exit the editor."""

        return True

    def do_exit(self, arg: str) -> bool:  # noqa: ARG002 - interface requirement
        return self.do_quit(arg)

    def do_EOF(self, arg: str) -> bool:  # noqa: ARG002 - interface requirement
        self.stdout.write("\n")
        return self.do_quit(arg)

    # Shortcuts ------------------------------------------------------------------

    def do_a(self, arg: str) -> None:
        self.do_accept(arg)

    def do_m(self, arg: str) -> None:
        self.do_modify(arg)

    def do_r(self, arg: str) -> None:
        self.do_reject(arg)

    def do_u(self, arg: str) -> None:
        self.do_undo(arg)

    def do_n(self, arg: str) -> None:
        self.do_next(arg)

    def do_p(self, arg: str) -> None:
        self.do_prev(arg)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactive opcode map editor")
    parser.add_argument("--handlers", type=Path, required=True, help="Handler suggestion JSON with opcode metadata")
    parser.add_argument("--proposals", type=Path, help="Opcode proposal JSON with candidate mappings")
    parser.add_argument("--candidate", help="Candidate name or label to load from proposals")
    parser.add_argument("--base-map", type=Path, help="Existing approved map to merge on startup")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Destination directory for approved maps")
    parser.add_argument("--version", default=DEFAULT_VERSION, help="Version hint used for defaults (informational)")
    parser.add_argument(
        "--auto-accept",
        action="store_true",
        help="Automatically accept all proposed mnemonics without starting the interactive shell",
    )
    return parser


def run_editor(
    *,
    handler_path: Path,
    proposal_path: Optional[Path],
    candidate: Optional[str],
    base_map_path: Optional[Path],
    output_dir: Path,
    version: str,
    auto_accept: bool = False,
) -> MapEditorSession:
    entries = load_handler_entries(handler_path)
    if not entries:
        raise SystemExit("No handler entries could be loaded; aborting")

    candidate_name, proposed_mapping = load_candidate_mapping(proposal_path, candidate=candidate)
    base_mapping = load_base_mapping(base_map_path)
    session = create_session(
        entries=entries,
        candidate_name=candidate_name,
        proposed_mapping=proposed_mapping,
        base_mapping=base_mapping,
        output_dir=output_dir,
        version_hint=version,
    )
    if base_mapping:
        LOGGER.info("Loaded %d baseline mnemonics from %s", len(base_mapping), base_map_path)
    if proposed_mapping:
        LOGGER.info(
            "Loaded %d proposed mnemonics from %s (candidate %s)",
            len(proposed_mapping),
            proposal_path,
            candidate_name,
        )
    if auto_accept:
        LOGGER.info("Auto-accept enabled; applying proposed mnemonics without interaction")
        for entry in session.entries:
            if entry.opcode in proposed_mapping:
                session.current_index = session.entries.index(entry)
                session.accept(proposed_mapping[entry.opcode], advance=False)
        session.save()
    return session


def main(argv: Optional[Sequence[str]] = None) -> int:  # pragma: no cover - exercised via tests
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    session = run_editor(
        handler_path=args.handlers,
        proposal_path=args.proposals,
        candidate=args.candidate,
        base_map_path=args.base_map,
        output_dir=args.output_dir,
        version=args.version,
        auto_accept=args.auto_accept,
    )

    if not args.auto_accept:
        shell = MapEditorShell(session)
        shell.cmdloop()
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
