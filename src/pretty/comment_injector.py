"""Inline comment injection utilities for pseudo-Lua listings.

The helpers in this module operate purely on text; no extracted code is
executed.  They provide a light-weight way to annotate suspicious regions in
lifted output with structured diagnostic comments.  Analysts can feed the
resulting file to other pretty-printing passes to retain the annotations.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, MutableMapping, Optional, Sequence

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommentHint:
    """Structured description of a comment to inject.

    Parameters
    ----------
    offset:
        Byte offset (from the original payload) associated with the
        suspicious instruction.  This is rendered as ``0x????`` and used to
        locate the matching line in the pseudo-Lua listing.
    raw_opcode:
        Optional raw opcode bytes as an integer.  When provided an
        ``-- AMBIGUOUS_OPCODE raw=0xNN`` comment is emitted.
    suggested_mnemonic:
        Proposed mnemonic name for the opcode, accompanied by a confidence
        score where available.
    confidence:
        Confidence score in the range ``[0.0, 1.0]``.  The comment only renders
        the value when present.
    notes:
        Additional free-form bullet points that explain why the comment was
        generated.
    artifacts:
        Paths to artefacts (relative or absolute) that help the analyst
        investigate further, such as intermediate byte dumps.  Each entry is
        rendered as ``-- SEE: <path>``.
    """

    offset: int
    raw_opcode: Optional[int] = None
    suggested_mnemonic: Optional[str] = None
    confidence: Optional[float] = None
    notes: Sequence[str] = field(default_factory=tuple)
    artifacts: Sequence[str] = field(default_factory=tuple)

    def render(self, indent: str) -> List[str]:
        """Return comment lines for this hint using *indent*."""

        location = f"0x{self.offset:04X}"
        lines: List[str] = [f"{indent}-- [offset {location}] analysis hint"]

        if self.raw_opcode is not None:
            lines.append(f"{indent}-- AMBIGUOUS_OPCODE raw=0x{self.raw_opcode:02X}")

        if self.suggested_mnemonic:
            if self.confidence is not None:
                lines.append(
                    f"{indent}-- SUGGESTED_MNEMONIC: {self.suggested_mnemonic} "
                    f"(confidence {self.confidence:.2f})"
                )
            else:
                lines.append(f"{indent}-- SUGGESTED_MNEMONIC: {self.suggested_mnemonic}")

        for note in self.notes:
            lines.append(f"{indent}-- NOTE: {note}")

        for artifact in self.artifacts:
            lines.append(f"{indent}-- SEE: {artifact}")

        return lines


def inject_comments(source: str, hints: Sequence[CommentHint]) -> str:
    """Return *source* with comment *hints* injected in-line.

    The routine searches for ``0x????`` offset markers in the text.  When a
    matching offset is found the hint comments are inserted immediately below
    the first occurrence.  Hints whose offsets cannot be located are appended
    to the end of the output with a warning log entry so analysts can adjust
    their metadata.
    """

    if not hints:
        return source

    lines = source.splitlines()
    output: List[str] = []
    pending = list(hints)

    def _pop_matches(offset_token: str) -> List[CommentHint]:
        matches: List[CommentHint] = []
        remaining: List[CommentHint] = []
        for hint in pending:
            token = f"0x{hint.offset:04X}".lower()
            if token == offset_token:
                matches.append(hint)
            else:
                remaining.append(hint)
        pending.clear()
        pending.extend(remaining)
        return matches

    for line in lines:
        output.append(line)
        stripped = line.strip()
        if "0x" in stripped:
            for match in re.findall(r"0x[0-9A-Fa-f]+", stripped):
                matches = _pop_matches(match.lower())
                if not matches:
                    continue
                indent = _leading_whitespace(line)
                for hint in matches:
                    output.extend(hint.render(indent))

    if pending:
        LOGGER.warning("%d comment hints did not match any offsets", len(pending))
        output.append("-- unmatched analysis hints")
        for hint in pending:
            output.extend(hint.render(""))

    return "\n".join(output) + ("\n" if source.endswith("\n") else "")


def load_hints(path: Path) -> List[CommentHint]:
    """Load :class:`CommentHint` entries from *path* (JSON)."""

    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, MutableMapping):
        payload = data.get("hints")
    else:
        payload = data

    if not isinstance(payload, Iterable):
        raise ValueError("hint container must be a list or mapping with 'hints'")

    hints: List[CommentHint] = []
    for entry in payload:
        if not isinstance(entry, MutableMapping):
            raise ValueError("each hint must be a mapping")

        offset = entry.get("offset")
        if not isinstance(offset, int):
            raise ValueError("hint offset must be an integer")

        raw_opcode = entry.get("raw_opcode")
        if raw_opcode is not None and not isinstance(raw_opcode, int):
            raise ValueError("raw_opcode must be an integer if provided")

        suggested = entry.get("suggested_mnemonic")
        if suggested is not None and not isinstance(suggested, str):
            raise ValueError("suggested_mnemonic must be a string if provided")

        confidence = entry.get("confidence")
        if confidence is not None:
            if not isinstance(confidence, (int, float)):
                raise ValueError("confidence must be numeric if provided")
            confidence = float(confidence)

        notes = entry.get("notes") or []
        if not isinstance(notes, Sequence) or isinstance(notes, (str, bytes, bytearray)):
            raise ValueError("notes must be a list of strings")
        notes_list = [str(item) for item in notes]

        artifacts = entry.get("artifacts") or []
        if not isinstance(artifacts, Sequence) or isinstance(artifacts, (str, bytes, bytearray)):
            raise ValueError("artifacts must be a list of strings")
        artifact_list = [str(item) for item in artifacts]

        hints.append(
            CommentHint(
                offset=offset,
                raw_opcode=raw_opcode,
                suggested_mnemonic=suggested,
                confidence=confidence,
                notes=tuple(notes_list),
                artifacts=tuple(artifact_list),
            )
        )

    return hints


def write_with_comments(
    source_path: Path,
    hints_path: Path,
    *,
    output_path: Optional[Path] = None,
) -> str:
    """Load *source_path* and apply hints from *hints_path* returning the text."""

    source = source_path.read_text(encoding="utf-8")
    hints = load_hints(hints_path)
    rendered = inject_comments(source, hints)

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        LOGGER.info("Wrote annotated pseudo-Lua to %s", output_path)

    return rendered


def _leading_whitespace(line: str) -> str:
    index = 0
    while index < len(line) and line[index].isspace():
        index += 1
    return line[:index]


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pseudo_lua", type=Path, help="Path to the pseudo-Lua input file")
    parser.add_argument("hints", type=Path, help="JSON file describing comment hints")
    parser.add_argument(
        "--output",
        type=Path,
        dest="output",
        default=None,
        help="Optional destination file. Default prints to stdout.",
    )
    parser.add_argument(
        "--print",
        dest="print_to_stdout",
        action="store_true",
        help="Also print the resulting text to stdout.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)

    rendered = write_with_comments(args.pseudo_lua, args.hints, output_path=args.output)

    if args.print_to_stdout or args.output is None:
        print(rendered, end="")

    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
