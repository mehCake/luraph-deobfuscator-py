"""Reflow heuristics for pseudo-Lua control-flow listings.

The reconstructor and inline emitters produce readable but often verbose
representations of dispatcher style code.  This module applies a couple of
post-processing steps so analysts can follow the high level logic without
getting lost in redundant labels or unsorted helper blocks.

The heuristics are intentionally conservative: they only remove *obviously*
redundant ``goto`` statements (fall-through to the next label) and only merge
label aliases when no executable statements separate them.  Block helper
functions are normalised to a predictable order and – for Luraph ``v14.4.2`` –
dispatcher handler sections are re-ordered by their numeric suffix so that the
common ``handler_XX`` pattern appears sequentially.

All file level helpers write the reflowed output under ``out/`` and create a
``.bak`` copy of the inspected input so analysts never lose the original text.
"""

from __future__ import annotations

import argparse
import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger(__name__)

_GOTO_PATTERN = re.compile(r"^(?P<indent>\s*)goto\s+(?P<label>[A-Za-z_][\w]*)\s*(?:--.*)?$", re.IGNORECASE)
_LABEL_PATTERN = re.compile(r"^(?P<indent>\s*)::\s*(?P<label>[A-Za-z_][\w]*)\s*::\s*(?:--.*)?$")
_BLOCK_FUNC_PATTERN = re.compile(
    r"^(?P<indent>\s*)local\s+function\s+(?P<name>block_(?P<index>\d+))\s*\((?P<params>[^)]*)\)"
)
_DISPATCH_LABEL_PATTERN = re.compile(r"^(?:handler|dispatch|case)_(?P<index>\d+)$", re.IGNORECASE)


@dataclass
class ReflowStats:
    """Metrics describing what changed during reflow."""

    removed_gotos: int = 0
    merged_labels: int = 0
    reordered_blocks: int = 0
    reordered_dispatchers: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "removed_gotos": self.removed_gotos,
            "merged_labels": self.merged_labels,
            "reordered_blocks": self.reordered_blocks,
            "reordered_dispatchers": self.reordered_dispatchers,
        }


@dataclass
class ReflowResult:
    """Outcome for :func:`reflow_file`."""

    text: str
    stats: ReflowStats
    output_path: Path
    backup_path: Optional[Path]
    notes: List[str] = field(default_factory=list)


def reflow_pseudo_lua(source: str, *, version_hint: Optional[str] = None) -> Tuple[str, ReflowStats]:
    """Return ``source`` after applying readability improving heuristics."""

    lines = source.splitlines()
    stats = ReflowStats()

    lines, removed = _remove_direct_fallthrough_gotos(lines)
    stats.removed_gotos += removed

    lines, merged = _merge_label_aliases(lines)
    stats.merged_labels += merged

    lines, reordered = _reorder_block_functions(lines)
    stats.reordered_blocks += reordered

    if version_hint and "14.4.2" in version_hint:
        lines, dispatcher_changes = _reorder_dispatcher_sections(lines)
        stats.reordered_dispatchers += dispatcher_changes

    result = "\n".join(_trim_excess_blank_lines(lines)).rstrip() + "\n"
    return result, stats


def reflow_file(
    input_path: Path,
    *,
    output_dir: Path = Path("out/reflowed"),
    version_hint: Optional[str] = None,
    create_backup: bool = True,
) -> ReflowResult:
    """Reflow ``input_path`` and persist the result under ``output_dir``."""

    payload = input_path.read_text(encoding="utf-8")
    text, stats = reflow_pseudo_lua(payload, version_hint=version_hint)

    backup_path = None
    if create_backup:
        backup_path = _create_backup(input_path)
        LOGGER.debug("Created backup at %s", backup_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / input_path.name
    output_path.write_text(text, encoding="utf-8")
    LOGGER.info("Wrote reflowed pseudo-Lua to %s", output_path)

    return ReflowResult(text=text, stats=stats, output_path=output_path, backup_path=backup_path)


# ---------------------------------------------------------------------------
# Heuristics


def _remove_direct_fallthrough_gotos(lines: Sequence[str]) -> Tuple[List[str], int]:
    updated: List[str] = []
    removed = 0
    line_iter = list(lines)
    total = len(line_iter)
    index = 0
    while index < total:
        line = line_iter[index]
        match = _GOTO_PATTERN.match(line)
        if match:
            target = match.group("label")
            next_index = _next_meaningful_line(line_iter, index + 1)
            if next_index is not None:
                next_line = line_iter[next_index]
                label_match = _LABEL_PATTERN.match(next_line)
                if label_match and label_match.group("label") == target:
                    removed += 1
                    LOGGER.debug("Removed fall-through goto to %s at line %d", target, index + 1)
                    index += 1
                    continue
        updated.append(line)
        index += 1
    return updated, removed


def _merge_label_aliases(lines: Sequence[str]) -> Tuple[List[str], int]:
    alias_map: dict[str, str] = {}
    prev_label: Optional[str] = None
    buffer: List[str] = []

    for line in lines:
        label_match = _LABEL_PATTERN.match(line)
        if label_match:
            label = label_match.group("label")
            if prev_label and _only_non_code(buffer):
                alias_map[label] = _resolve_alias(prev_label, alias_map)
            else:
                prev_label = label
            buffer = []
        else:
            buffer.append(line)
            if not _is_whitespace_or_comment(line):
                prev_label = None

    if not alias_map:
        return list(lines), 0

    def canonical(label: str) -> str:
        return _resolve_alias(label, alias_map)

    merged = 0
    rewritten: List[str] = []
    for line in lines:
        label_match = _LABEL_PATTERN.match(line)
        if label_match:
            label = label_match.group("label")
            target = canonical(label)
            if target != label:
                merged += 1
                rewritten.append(f"-- alias {label} -> {target}")
                continue
            rewritten.append(line)
            continue

        goto_match = _GOTO_PATTERN.match(line)
        if goto_match:
            target = goto_match.group("label")
            canonical_target = canonical(target)
            if canonical_target != target:
                indent = goto_match.group("indent")
                rewritten.append(f"{indent}goto {canonical_target} -- via {target}")
                merged += 1
            else:
                rewritten.append(line)
            continue

        rewritten.append(line)

    return rewritten, merged


def _reorder_block_functions(lines: Sequence[str]) -> Tuple[List[str], int]:
    blocks: List[Tuple[int, int, int, List[str]]] = []

    index = 0
    while index < len(lines):
        line = lines[index]
        match = _BLOCK_FUNC_PATTERN.match(line)
        if not match:
            index += 1
            continue

        block_index = int(match.group("index"))
        start = index
        depth = 0
        body: List[str] = []
        while index < len(lines):
            current = lines[index]
            body.append(current)
            depth += _token_delta(current)
            index += 1
            if depth <= 0:
                break
        while index < len(lines) and not lines[index].strip():
            # Skip trailing blank lines so they can be normalised later
            index += 1
        while body and not body[-1].strip():
            body.pop()
        blocks.append((block_index, start, index, body))

    if not blocks:
        return list(lines), 0

    original_order = [block for block, _, _, _ in blocks]
    sorted_blocks = sorted(blocks, key=lambda item: item[0])

    prefix = lines[: blocks[0][1]]
    suffix = lines[blocks[-1][2] :]

    sorted_lines: List[str] = []
    for _, _, _, body in sorted_blocks:
        sorted_lines.extend(body)
        sorted_lines.append("")
    while sorted_lines and not sorted_lines[-1].strip():
        sorted_lines.pop()

    reconstructed: List[str] = list(prefix)
    if reconstructed and reconstructed[-1].strip() and sorted_lines:
        reconstructed.append("")
    reconstructed.extend(sorted_lines)
    if reconstructed and reconstructed[-1].strip() and suffix and suffix[0].strip():
        reconstructed.append("")
    reconstructed.extend(suffix)

    reordered = int(original_order != [block for block, _, _, _ in sorted_blocks])
    return reconstructed, reordered


def _reorder_dispatcher_sections(lines: Sequence[str]) -> Tuple[List[str], int]:
    result: List[str] = []
    idx = 0
    reordered = 0

    while idx < len(lines):
        match = _LABEL_PATTERN.match(lines[idx])
        if not match or not _DISPATCH_LABEL_PATTERN.match(match.group("label")):
            result.append(lines[idx])
            idx += 1
            continue

        run_segments: List[Tuple[str, List[str]]] = []
        while idx < len(lines):
            label_match = _LABEL_PATTERN.match(lines[idx])
            if not label_match or not _DISPATCH_LABEL_PATTERN.match(label_match.group("label")):
                break
            label_name = label_match.group("label")
            segment_lines: List[str] = []
            # capture the label itself and its statements until the next label
            segment_lines.append(lines[idx])
            idx += 1
            while idx < len(lines) and not _LABEL_PATTERN.match(lines[idx]):
                segment_lines.append(lines[idx])
                idx += 1
            # include trailing blank lines with the segment for readability
            while idx < len(lines) and not lines[idx].strip():
                segment_lines.append(lines[idx])
                idx += 1
            run_segments.append((label_name, segment_lines))
            next_label = _LABEL_PATTERN.match(lines[idx]) if idx < len(lines) else None
            if not next_label or not _DISPATCH_LABEL_PATTERN.match(next_label.group("label")):
                break

        sorted_segments = sorted(run_segments, key=lambda item: _dispatch_index(item[0]))
        if [label for label, _ in run_segments] != [label for label, _ in sorted_segments]:
            reordered += 1
        for _, segment_lines in sorted_segments:
            result.extend(segment_lines)
        continue

    return result, reordered


def _dispatch_index(label: str) -> int:
    match = _DISPATCH_LABEL_PATTERN.match(label)
    if match:
        return int(match.group("index"))
    return 0


def _trim_excess_blank_lines(lines: Iterable[str]) -> List[str]:
    result: List[str] = []
    previous_blank = False
    for line in lines:
        if line.strip():
            result.append(line)
            previous_blank = False
        else:
            if not previous_blank:
                result.append(line)
            previous_blank = True
    return result


# ---------------------------------------------------------------------------
# Utilities


def _next_meaningful_line(lines: Sequence[str], start: int) -> Optional[int]:
    for idx in range(start, len(lines)):
        stripped = lines[idx].strip()
        if not stripped or stripped.startswith("--"):
            continue
        return idx
    return None


def _only_non_code(lines: Sequence[str]) -> bool:
    return all(_is_whitespace_or_comment(line) for line in lines)


def _is_whitespace_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("--")


def _resolve_alias(label: str, alias_map: Mapping[str, str]) -> str:
    seen = set()
    current = label
    while current in alias_map and current not in seen:
        seen.add(current)
        current = alias_map[current]
    return current


def _token_delta(line: str) -> int:
    payload = re.sub(r"--.*", "", line)
    openings = len(re.findall(r"\bfunction\b", payload))
    closings = len(re.findall(r"\bend\b", payload))
    return openings - closings


def _create_backup(path: Path) -> Path:
    candidate = path.with_suffix(path.suffix + ".bak")
    counter = 1
    while candidate.exists():
        candidate = path.with_suffix(path.suffix + f".bak{counter}")
        counter += 1
    shutil.copy2(path, candidate)
    return candidate


# ---------------------------------------------------------------------------
# CLI


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reflow pseudo-Lua control flow for readability")
    parser.add_argument("input", type=Path, help="Pseudo-Lua file to reflow")
    parser.add_argument("--output-dir", type=Path, default=Path("out/reflowed"), help="Directory for reflowed output")
    parser.add_argument("--version-hint", help="Version hint such as v14.4.2", default=None)
    parser.add_argument("--no-backup", action="store_true", help="Skip creating a .bak copy of the input")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    result = reflow_file(
        args.input,
        output_dir=args.output_dir,
        version_hint=args.version_hint,
        create_backup=not args.no_backup,
    )

    stats = result.stats.as_dict()
    summary = ", ".join(f"{key}={value}" for key, value in stats.items() if value)
    if summary:
        print(f"Reflowed {args.input.name}: {summary}")
    else:
        print(f"Reflowed {args.input.name} (no changes)")
    print(f"Output written to {result.output_path}")
    if result.backup_path:
        print(f"Backup created at {result.backup_path}")
    return 0


__all__ = [
    "ReflowResult",
    "ReflowStats",
    "main",
    "reflow_file",
    "reflow_pseudo_lua",
]


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
