"""Diff utilities for comparing deobfuscated Lua outputs.

This module provides helpers that highlight structural differences between two
generated sources.  It classifies edits that impact control-flow constructs or
constant literals, produces machine readable summaries, and can emit an HTML
viewer suitable for manual inspection.  The implementation is intentionally
static: it never executes the compared sources and it never touches secret
material such as session keys.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import argparse
import datetime as _dt
import difflib
import json
import re
from pathlib import Path
from typing import List, Optional, Sequence

CONTROL_FLOW_KEYWORDS = {
    "if",
    "elseif",
    "else",
    "while",
    "for",
    "repeat",
    "until",
    "goto",
    "function",
    "return",
    "break",
    "continue",
}

CONSTANT_PATTERN = re.compile(
    r"("  # start capture group
    r"0x[0-9a-fA-F]+"  # hex literals
    r"|\b\d+\b"  # decimal numbers
    r"|\".*?\""  # double-quoted strings
    r"|'.*?'"  # single-quoted strings
    r")"
)


@dataclass
class DiffEntry:
    """Represents a single differing line between two sources."""

    category: str
    tag: str
    line_a: Optional[int]
    line_b: Optional[int]
    offset_a: Optional[int]
    offset_b: Optional[int]
    text_a: Optional[str]
    text_b: Optional[str]

    def to_summary(self) -> str:
        """Generate a one-line human friendly summary for reporting."""

        parts = [f"[{self.category}] {self.tag}"]
        if self.line_a is not None:
            parts.append(f"A@L{self.line_a}")
        if self.line_b is not None:
            parts.append(f"B@L{self.line_b}")
        if self.text_a is not None or self.text_b is not None:
            excerpt_a = (self.text_a or "").strip()
            excerpt_b = (self.text_b or "").strip()
            parts.append(f"{excerpt_a!r} -> {excerpt_b!r}")
        return " | ".join(parts)


@dataclass
class ComparisonResult:
    """Container returned by :func:`compare_outputs`."""

    differences: List[DiffEntry]
    control_flow_changes: int
    constant_changes: int
    other_changes: int
    html_report: Path
    summary_report: Path
    json_report: Path

    @property
    def total_changes(self) -> int:
        return len(self.differences)


def _normalise_lines(content: str) -> List[str]:
    return content.replace("\r\n", "\n").replace("\r", "\n").splitlines()


def _line_offsets(lines: Sequence[str]) -> List[int]:
    offsets: List[int] = []
    running = 0
    for line in lines:
        offsets.append(running)
        running += len(line) + 1  # account for newline that was split
    return offsets


def _classify_line(*lines: Optional[str]) -> str:
    for line in lines:
        if not line:
            continue
        lowered = line.lower()
        if any(keyword in lowered for keyword in CONTROL_FLOW_KEYWORDS):
            return "control_flow"
    for line in lines:
        if not line:
            continue
        if CONSTANT_PATTERN.search(line):
            return "constant"
    return "other"


def compare_outputs(
    before_path: Path,
    after_path: Path,
    *,
    output_dir: Path,
    label_a: str = "before",
    label_b: str = "after",
    generate_html: bool = True,
) -> ComparisonResult:
    """Compare two text files and write diff artefacts.

    Parameters
    ----------
    before_path / after_path:
        Paths to the source files that should be compared.
    output_dir:
        Directory where reports should be written.  The directory is created if
        necessary.
    label_a / label_b:
        Friendly names that appear inside generated reports.
    generate_html:
        When ``True`` (the default) an HTML diff viewer is produced.
    """

    before_text = before_path.read_text(encoding="utf-8")
    after_text = after_path.read_text(encoding="utf-8")

    lines_a = _normalise_lines(before_text)
    lines_b = _normalise_lines(after_text)
    offsets_a = _line_offsets(lines_a)
    offsets_b = _line_offsets(lines_b)

    matcher = difflib.SequenceMatcher(None, lines_a, lines_b, autojunk=False)
    differences: List[DiffEntry] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        block_a = lines_a[i1:i2]
        block_b = lines_b[j1:j2]
        limit = max(len(block_a), len(block_b))
        for idx in range(limit):
            line_a = block_a[idx] if idx < len(block_a) else None
            line_b = block_b[idx] if idx < len(block_b) else None
            line_no_a = i1 + idx + 1 if line_a is not None else None
            line_no_b = j1 + idx + 1 if line_b is not None else None
            offset_a = offsets_a[line_no_a - 1] if line_no_a else None
            offset_b = offsets_b[line_no_b - 1] if line_no_b else None
            category = _classify_line(line_a, line_b)
            differences.append(
                DiffEntry(
                    category=category,
                    tag=tag,
                    line_a=line_no_a,
                    line_b=line_no_b,
                    offset_a=offset_a,
                    offset_b=offset_b,
                    text_a=line_a,
                    text_b=line_b,
                )
            )

    control_flow_changes = sum(1 for diff in differences if diff.category == "control_flow")
    constant_changes = sum(1 for diff in differences if diff.category == "constant")
    other_changes = sum(1 for diff in differences if diff.category == "other")

    timestamp = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    safe_label_a = re.sub(r"[^a-zA-Z0-9_-]+", "_", label_a)
    safe_label_b = re.sub(r"[^a-zA-Z0-9_-]+", "_", label_b)
    prefix = f"{safe_label_a}_vs_{safe_label_b}_{timestamp}"

    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / f"{prefix}_summary.json"
    text_report_path = output_dir / f"{prefix}_summary.md"
    html_report_path = output_dir / f"{prefix}.html"

    summary_payload = {
        "label_a": label_a,
        "label_b": label_b,
        "total_changes": len(differences),
        "control_flow_changes": control_flow_changes,
        "constant_changes": constant_changes,
        "other_changes": other_changes,
        "differences": [asdict(diff) for diff in differences],
    }
    summary_path.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")

    text_lines = [
        f"Comparison: {label_a} vs {label_b}",
        f"Total changes: {len(differences)}",
        f"Control-flow changes: {control_flow_changes}",
        f"Constant changes: {constant_changes}",
        f"Other changes: {other_changes}",
        "",
    ]
    if differences:
        text_lines.append("Detailed differences:")
        for diff in differences:
            text_lines.append(f"- {diff.to_summary()}")
    else:
        text_lines.append("No differences detected.")
    text_report_path.write_text("\n".join(text_lines), encoding="utf-8")

    if generate_html:
        html_report = difflib.HtmlDiff(wrapcolumn=120).make_file(
            lines_a,
            lines_b,
            fromdesc=f"{label_a} ({before_path})",
            todesc=f"{label_b} ({after_path})",
        )
        html_report_path.write_text(html_report, encoding="utf-8")
    else:
        html_report_path.write_text("<html><body><p>HTML output disabled.</p></body></html>", encoding="utf-8")

    return ComparisonResult(
        differences=differences,
        control_flow_changes=control_flow_changes,
        constant_changes=constant_changes,
        other_changes=other_changes,
        html_report=html_report_path,
        summary_report=text_report_path,
        json_report=summary_path,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare two deobfuscated outputs and highlight structural differences.",
    )
    parser.add_argument("before", type=Path, help="Path to the first (reference) file")
    parser.add_argument("after", type=Path, help="Path to the second file")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out/diffs"),
        help="Directory for diff artefacts (default: out/diffs)",
    )
    parser.add_argument("--label-a", default="before", help="Friendly name for the first file")
    parser.add_argument("--label-b", default="after", help="Friendly name for the second file")
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip generating the HTML diff viewer",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    result = compare_outputs(
        args.before,
        args.after,
        output_dir=args.out_dir,
        label_a=args.label_a,
        label_b=args.label_b,
        generate_html=not args.no_html,
    )

    print(
        "Comparison complete:\n"
        f"  Total changes: {result.total_changes}\n"
        f"  Control-flow changes: {result.control_flow_changes}\n"
        f"  Constant changes: {result.constant_changes}\n"
        f"  Other changes: {result.other_changes}\n"
        f"  Summary: {result.summary_report}\n"
        f"  JSON: {result.json_report}\n"
        f"  HTML: {result.html_report}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())

