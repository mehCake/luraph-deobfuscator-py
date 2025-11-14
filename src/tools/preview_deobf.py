"""Side-by-side preview of obfuscated and deobfuscated Lua sources."""

from __future__ import annotations

import argparse
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

ANSI_RESET = "\x1b[0m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_BOLD = "\x1b[1m"
ANSI_DIM = "\x1b[2m"

DEFAULT_MAX_LINES = 200
_MIN_COLUMN_WIDTH = 24

__all__ = [
    "PreviewConfig",
    "generate_preview",
    "preview_files",
    "main",
]


@dataclass(frozen=True)
class PreviewConfig:
    """Configuration used when building preview tables."""

    max_lines: int = DEFAULT_MAX_LINES
    column_width: Optional[int] = None
    colour: Optional[bool] = None


class PreviewError(RuntimeError):
    """Raised when preview generation fails."""


def _load_lines(path: Path, limit: int) -> Tuple[List[str], bool]:
    """Return up to *limit* lines from *path* along with a truncated flag."""

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="latin-1")
    except FileNotFoundError as exc:
        raise PreviewError(f"Input file not found: {path}") from exc
    except OSError as exc:  # pragma: no cover - defensive
        raise PreviewError(f"Failed to read {path}: {exc}") from exc

    lines = text.splitlines()
    truncated = len(lines) > limit
    return lines[:limit], truncated


def _determine_width(config: PreviewConfig) -> int:
    if config.column_width and config.column_width > 0:
        return max(config.column_width, _MIN_COLUMN_WIDTH)
    total_columns = shutil.get_terminal_size((120, 40)).columns
    usable = max(total_columns - 18, _MIN_COLUMN_WIDTH * 2)
    return max(usable // 2, _MIN_COLUMN_WIDTH)


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "\u2026"


def _apply_colour(text: str, colour: Optional[str], enabled: bool) -> str:
    if not enabled or not colour:
        return text
    return f"{colour}{text}{ANSI_RESET}"


def _format_cell(text: str, width: int, colour: Optional[str], colour_enabled: bool) -> str:
    truncated = _truncate(text.replace("\t", "    "), width)
    padded = truncated.ljust(width)
    return _apply_colour(padded, colour, colour_enabled)


def _colour_for_difference(original: str, deobfuscated: str, colour_enabled: bool) -> Tuple[Optional[str], Optional[str]]:
    if not colour_enabled or original == deobfuscated:
        return None, None
    orig_colour = ANSI_RED
    deobf_colour = ANSI_GREEN
    if not original:
        orig_colour = ANSI_DIM
    if not deobfuscated:
        deobf_colour = ANSI_DIM
    return orig_colour, deobf_colour


def generate_preview(
    original_lines: Sequence[str],
    deobfuscated_lines: Sequence[str],
    *,
    max_lines: int = DEFAULT_MAX_LINES,
    column_width: Optional[int] = None,
    colour: Optional[bool] = None,
) -> str:
    """Create and return the preview table for the provided line sequences."""

    config = PreviewConfig(max_lines=max_lines, column_width=column_width, colour=colour)
    width = _determine_width(config)

    total_rows = max(len(original_lines), len(deobfuscated_lines))
    colour_enabled = bool(colour)
    header_left = _format_cell(
        "Original",
        width,
        ANSI_BOLD if colour_enabled else None,
        colour_enabled,
    )
    header_right = _format_cell(
        "Deobfuscated",
        width,
        ANSI_BOLD if colour_enabled else None,
        colour_enabled,
    )

    header = f"{'Orig':>6} │ {header_left} │ {'Deobf':>6} │ {header_right}"

    rows: List[str] = []
    rows.append(header)
    rows.append("-" * len(header))
    for index in range(total_rows):
        original_text = original_lines[index] if index < len(original_lines) else ""
        deobf_text = deobfuscated_lines[index] if index < len(deobfuscated_lines) else ""
        orig_no = f"{index + 1:>6}" if original_text or index < len(original_lines) else " " * 6
        deobf_no = f"{index + 1:>6}" if deobf_text or index < len(deobfuscated_lines) else " " * 6
        orig_colour, deobf_colour = _colour_for_difference(
            original_text, deobf_text, colour_enabled
        )
        left_cell = _format_cell(original_text, width, orig_colour, colour_enabled)
        right_cell = _format_cell(deobf_text, width, deobf_colour, colour_enabled)
        rows.append(f"{orig_no} │ {left_cell} │ {deobf_no} │ {right_cell}")

    return "\n".join(rows)


def preview_files(
    original_path: Path,
    deobfuscated_path: Path,
    *,
    max_lines: int = DEFAULT_MAX_LINES,
    column_width: Optional[int] = None,
    colour: Optional[bool] = None,
) -> str:
    """Return a formatted preview for *original_path* and *deobfuscated_path*."""

    original_lines, truncated_original = _load_lines(original_path, max_lines)
    deobf_lines, truncated_deobf = _load_lines(deobfuscated_path, max_lines)
    render_colour = colour if colour is not None else sys.stdout.isatty()
    table = generate_preview(
        original_lines,
        deobf_lines,
        max_lines=max_lines,
        column_width=column_width,
        colour=render_colour,
    )
    notes: List[str] = [table]
    if truncated_original:
        notes.append(
            f"… truncated original preview to first {max_lines} line(s)"
        )
    if truncated_deobf:
        notes.append(
            f"… truncated deobfuscated preview to first {max_lines} line(s)"
        )
    return "\n".join(notes)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Show a side-by-side preview of obfuscated and deobfuscated Lua sources."
        )
    )
    parser.add_argument("original", type=Path, help="Path to the obfuscated Lua file")
    parser.add_argument(
        "deobfuscated",
        type=Path,
        help="Path to the generated deobfuscated Lua output",
    )
    parser.add_argument(
        "--lines",
        type=int,
        default=DEFAULT_MAX_LINES,
        help="Maximum number of lines to display (default: %(default)s)",
    )
    parser.add_argument(
        "--width",
        type=int,
        default=None,
        help="Column width for each preview pane (auto-detect by default)",
    )
    parser.add_argument(
        "--color",
        dest="colour",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Force colour output on or off (default: auto)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        preview = preview_files(
            args.original,
            args.deobfuscated,
            max_lines=args.lines,
            column_width=args.width,
            colour=args.colour,
        )
    except PreviewError as exc:
        parser.error(str(exc))
        return 2
    print(preview)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
