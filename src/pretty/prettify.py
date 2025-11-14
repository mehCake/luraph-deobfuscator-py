"""Utilities for formatting pseudo-Lua output for human review.

The formatter intentionally performs only textual transformations – no
execution of any extracted code is attempted.  Callers can supply
configuration options to control indentation, wrapping, provenance header
insertion, and ad-hoc comment annotations.
"""
from __future__ import annotations

import argparse
import json
import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, List, Mapping, MutableMapping, Optional, Sequence


@dataclass(frozen=True)
class Provenance:
    """Metadata rendered in the leading ``-- PROVENANCE`` header.

    Attributes
    ----------
    summary:
        A single-line summary describing the pipeline configuration.
    details:
        Optional detail lines rendered underneath the summary, each prefixed
        with ``--`` so they remain Lua comments.
    """

    summary: str
    details: Sequence[str] = field(default_factory=tuple)

    @classmethod
    def from_profile(
        cls,
        profile: Mapping[str, Any],
        *,
        label: Optional[str] = None,
    ) -> "Provenance":
        """Create provenance information from a transform profile mapping.

        The routine extracts simple scalar key/value pairs for the summary and
        emits richer values as detail lines.  The heuristic remains defensive:
        large containers are truncated to avoid overwhelming the output.
        """

        simple_items: List[str] = []
        detail_lines: List[str] = []

        for key, value in profile.items():
            if isinstance(value, bool):
                simple_items.append(f"{key}={'true' if value else 'false'}")
                continue

            if isinstance(value, (str, int, float)) or value is None:
                simple_items.append(f"{key}={value}")
                continue

            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                preview = ", ".join(map(_short_repr, list(value)[:3]))
                detail_lines.append(f"{key}: [{preview}{' …' if len(value) > 3 else ''}]")
                continue

            if isinstance(value, Mapping):
                keys_preview = ", ".join(map(str, list(value.keys())[:3]))
                detail_lines.append(
                    f"{key}: mapping with {len(value)} entries"
                    + (f" (keys: {keys_preview}{' …' if len(value) > 3 else ''})" if value else "")
                )
                continue

            detail_lines.append(f"{key}: {_short_repr(value)}")

        summary_core = "; ".join(simple_items) if simple_items else "transform profile loaded"
        if label:
            summary = f"{label}: {summary_core}"
        else:
            summary = summary_core

        return cls(summary=summary, details=tuple(detail_lines))

    @classmethod
    def from_file(
        cls,
        profile_path: Path,
        *,
        label: Optional[str] = None,
    ) -> "Provenance":
        """Load provenance information from a JSON file.

        The loader tolerates absent files by returning a placeholder summary so
        that callers still receive a header, as required by the specification.
        """

        if not profile_path.exists():
            return cls(summary=f"{label or 'transform profile'} missing")

        with profile_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, MutableMapping):
            raise ValueError("transform profile must contain a JSON object")
        return cls.from_profile(data, label=label)


@dataclass(frozen=True)
class CommentInjection:
    """Description of an inline comment to add to formatted output."""

    match: str
    comment: str
    position: str = "append"  # "append", "above", or "below"
    regex: bool = False
    case_sensitive: bool = False

    def matches(self, line: str) -> bool:
        candidate = line if self.case_sensitive else line.lower()
        target = self.match if self.case_sensitive else self.match.lower()
        if self.regex:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            return re.search(self.match, line, flags=flags) is not None
        return target in candidate

    def normalized_position(self) -> str:
        if self.position not in {"append", "above", "below"}:
            raise ValueError(f"unsupported comment injection position: {self.position}")
        return self.position


def format_pseudo_lua(
    source: str,
    *,
    indent_width: int = 4,
    max_column: int = 100,
    provenance: Optional[Provenance] = None,
    comment_rules: Optional[Sequence[CommentInjection]] = None,
) -> str:
    """Format pseudo-Lua text according to the configured preferences."""

    lines = source.splitlines()
    formatted: List[str] = _format_lines(lines, indent_width, max_column)

    if comment_rules:
        formatted = _apply_comment_injections(formatted, comment_rules, indent_width, max_column)

    header_lines: List[str] = []
    if provenance:
        header_lines = _build_provenance_header(provenance, indent_width, max_column)

    output_lines = header_lines + formatted
    return "\n".join(output_lines) + ("\n" if output_lines and not output_lines[-1].endswith("\n") else "")


def format_file(
    input_path: Path,
    *,
    output_path: Optional[Path] = None,
    indent_width: int = 4,
    max_column: int = 100,
    provenance: Optional[Provenance] = None,
    comment_rules: Optional[Sequence[CommentInjection]] = None,
) -> str:
    """Format a file on disk, optionally writing the result to ``output_path``."""

    with input_path.open("r", encoding="utf-8") as handle:
        source = handle.read()

    formatted = format_pseudo_lua(
        source,
        indent_width=indent_width,
        max_column=max_column,
        provenance=provenance,
        comment_rules=comment_rules,
    )

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            handle.write(formatted)
    return formatted


def _format_lines(lines: Sequence[str], indent_width: int, max_column: int) -> List[str]:
    block_openers = {"function", "then", "do", "repeat"}
    block_closers = {"end", "elseif", "else", "until"}

    formatted: List[str] = []
    indent_level = 0

    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            formatted.append("")
            continue

        lower = stripped.lower()
        first_token = lower.split()[0]

        if first_token in block_closers:
            indent_level = max(indent_level - 1, 0)

        indent = " " * (indent_level * indent_width)
        line_to_render = indent + stripped

        formatted.extend(_wrap_line(line_to_render, indent_width, max_column))

        opens_block = any(_line_opens_block(lower, token) for token in block_openers)
        if opens_block:
            indent_level += 1
        elif first_token == "else":
            indent_level += 1

    return formatted


def _line_opens_block(line: str, token: str) -> bool:
    if token == "then":
        trimmed = line.rstrip()
        return trimmed.endswith(" then") or " then --" in trimmed
    if token == "do":
        return line.endswith(" do") or " do --" in line or line.startswith("do ")
    if token == "repeat":
        return line.startswith("repeat")
    if token == "function":
        return line.startswith("function") or line.startswith("local function")
    return False


def _wrap_line(line: str, indent_width: int, max_column: int) -> List[str]:
    if max_column <= 0 or len(line) <= max_column:
        return [line.rstrip()]

    indent_length = len(line) - len(line.lstrip())
    prefix = line[:indent_length]
    body = line[indent_length:]
    wrap_width = max(max_column - indent_length, max(10, indent_width))

    wrapped = textwrap.wrap(
        body,
        width=wrap_width,
        break_long_words=False,
        break_on_hyphens=False,
    )
    if len(wrapped) <= 1:
        return [line.rstrip()]

    continuation_prefix = prefix + (" " * indent_width)
    result = [prefix + wrapped[0].rstrip()]
    for chunk in wrapped[1:]:
        trimmed = chunk.lstrip()
        if trimmed.split(" ", 1)[0] in {"end", "else", "elseif", "until"}:
            result.append(prefix + trimmed.rstrip())
        else:
            result.append(continuation_prefix + chunk.rstrip())
    return result


def _apply_comment_injections(
    lines: Sequence[str],
    rules: Sequence[CommentInjection],
    indent_width: int,
    max_column: int,
) -> List[str]:
    result: List[str] = []
    for line in lines:
        indent_length = len(line) - len(line.lstrip(" "))
        indent_prefix = " " * indent_length
        above: List[str] = []
        below: List[str] = []
        augmented_line = line

        for rule in rules:
            if not rule.matches(line):
                continue
            position = rule.normalized_position()
            if position == "append":
                augmented_line = _append_comment(augmented_line, rule.comment)
            elif position == "above":
                above.append(rule.comment)
            elif position == "below":
                below.append(rule.comment)

        for comment in above:
            comment_line = f"{indent_prefix}-- {comment}"
            result.extend(_wrap_line(comment_line, indent_width, max_column))

        result.extend(_wrap_line(augmented_line, indent_width, max_column))

        for comment in below:
            comment_line = f"{indent_prefix}-- {comment}"
            result.extend(_wrap_line(comment_line, indent_width, max_column))
    return result


def _append_comment(line: str, comment: str) -> str:
    stripped = line.rstrip()
    if "--" in stripped:
        return f"{stripped} | {comment}"
    return f"{stripped} -- {comment}"


def _build_provenance_header(
    provenance: Provenance, indent_width: int, max_column: int
) -> List[str]:
    header = [f"-- PROVENANCE: {provenance.summary}"]
    for detail in provenance.details:
        header.append(f"-- {detail}")
    rendered: List[str] = []
    for line in header:
        rendered.extend(_wrap_line(line, indent_width, max_column))
    return rendered


def _short_repr(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 40 else text[:37] + "…"


def _load_comment_rules(path: Optional[Path]) -> List[CommentInjection]:
    if path is None:
        return []
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    entries: Iterable[MutableMapping[str, Any]]
    if isinstance(payload, MutableMapping):
        entries = [payload]
    elif isinstance(payload, Sequence):
        entries = payload  # type: ignore[assignment]
    else:
        raise ValueError("comment injection file must contain an object or array")

    rules: List[CommentInjection] = []
    for entry in entries:
        if not isinstance(entry, MutableMapping):
            raise ValueError("comment injection entries must be JSON objects")
        try:
            match = entry["match"]
            comment = entry["comment"]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError("comment injection entries require 'match' and 'comment'") from exc
        rules.append(
            CommentInjection(
                match=str(match),
                comment=str(comment),
                position=str(entry.get("position", "append")),
                regex=bool(entry.get("regex", False)),
                case_sensitive=bool(entry.get("case_sensitive", False)),
            )
        )
    return rules


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Format pseudo-Lua output deterministically")
    parser.add_argument("input", type=Path, help="Path to pseudo-Lua input file")
    parser.add_argument("-o", "--output", type=Path, help="Destination path for formatted output")
    parser.add_argument("--indent", type=int, default=4, help="Indent width in spaces (default: 4)")
    parser.add_argument(
        "--max-column",
        type=int,
        default=100,
        help="Maximum column width before wrapping (default: 100)",
    )
    parser.add_argument(
        "--transform-profile",
        type=Path,
        help="Optional transform_profile.json to summarise in the provenance header",
    )
    parser.add_argument(
        "--profile-label",
        type=str,
        help="Override label for the provenance summary line",
    )
    parser.add_argument(
        "--inject-comments",
        type=Path,
        help="JSON file describing comment injection rules",
    )

    args = parser.parse_args(argv)

    provenance: Optional[Provenance] = None
    if args.transform_profile:
        provenance = Provenance.from_file(args.transform_profile, label=args.profile_label)
    else:
        provenance = Provenance(summary="transform profile unavailable")

    comment_rules = _load_comment_rules(args.inject_comments)

    format_file(
        args.input,
        output_path=args.output,
        indent_width=args.indent,
        max_column=args.max_column,
        provenance=provenance,
        comment_rules=comment_rules,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
