"""Utilities for generating an index of repository documentation.

This module scans the ``docs/`` tree for Markdown pages as well as example
artifacts and produces/updates ``docs/index.md``.  The generated index is
bounded by HTML comment markers so that manual prose surrounding the section is
preserved when the file already exists.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

_BEGIN_MARKER = "<!-- AUTO-DOCS-INDEX:BEGIN -->"
_END_MARKER = "<!-- AUTO-DOCS-INDEX:END -->"
_DEFAULT_PREAMBLE = """# Documentation Index\n\nThis file is auto-generated from the contents of the `docs/` directory.\nManual edits outside of the marked section will be preserved.\n\n"""


@dataclass(slots=True)
class DocumentEntry:
    """Represents a discovered documentation artifact."""

    title: str
    relative_path: str


@dataclass(slots=True)
class DocumentationIndex:
    """Grouped documentation entries for rendering."""

    pages: List[DocumentEntry]
    examples: List[DocumentEntry]


def _extract_markdown_title(path: Path) -> str:
    """Return the first Markdown heading from ``path`` or fall back to stem."""

    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                # Drop leading ``#`` characters and whitespace.
                return stripped.lstrip("#").strip() or path.stem
    except FileNotFoundError:
        pass
    return path.stem.replace("_", " ")


def _build_entries(docs_dir: Path) -> DocumentationIndex:
    pages: List[DocumentEntry] = []
    examples: List[DocumentEntry] = []

    for doc_path in sorted(docs_dir.glob("*.md")):
        if doc_path.name.lower() == "index.md":
            continue
        title = _extract_markdown_title(doc_path)
        pages.append(
            DocumentEntry(title=title, relative_path=doc_path.name)
        )

    examples_dir = docs_dir / "examples"
    if examples_dir.exists():
        for path in sorted(p for p in examples_dir.rglob("*") if p.is_file()):
            rel_path = path.relative_to(docs_dir).as_posix()
            title = (
                _extract_markdown_title(path)
                if path.suffix.lower() == ".md"
                else path.stem.replace("_", " ")
            )
            examples.append(DocumentEntry(title=title, relative_path=rel_path))

    return DocumentationIndex(pages=pages, examples=examples)


def _render_section(entries: Iterable[DocumentEntry]) -> List[str]:
    lines: List[str] = []
    for entry in entries:
        lines.append(f"- [{entry.title}]({entry.relative_path})")
    return lines


def _render_block(index: DocumentationIndex) -> str:
    lines: List[str] = [_BEGIN_MARKER, ""]

    if index.pages:
        lines.append("## Documentation Pages")
        lines.extend(_render_section(index.pages))
        lines.append("")

    if index.examples:
        lines.append("## Examples")
        lines.extend(_render_section(index.examples))
        lines.append("")

    if len(lines) == 2:  # Only marker and blank line – ensure placeholder text.
        lines.append("No documentation pages were discovered.")
        lines.append("")

    lines.append(_END_MARKER)
    lines.append("")
    return "\n".join(lines)


def _update_index_file(index_path: Path, block: str) -> None:
    if index_path.exists():
        original = index_path.read_text(encoding="utf-8")
        if _BEGIN_MARKER in original and _END_MARKER in original:
            start = original.index(_BEGIN_MARKER)
            end = original.index(_END_MARKER) + len(_END_MARKER)
            prefix = original[:start]
            suffix = original[end:]
            # Ensure trailing newline before suffix to keep formatting stable.
            if not prefix.endswith("\n"):
                prefix += "\n"
            if suffix and not suffix.startswith("\n"):
                suffix = "\n" + suffix
            new_content = prefix + block + suffix
        else:
            content = original.rstrip() + "\n\n" + block
            new_content = content
    else:
        new_content = _DEFAULT_PREAMBLE + block
    index_path.write_text(new_content, encoding="utf-8")


def generate_documentation_index(
    docs_dir: Path, *, index_path: Optional[Path] = None, dry_run: bool = False
) -> DocumentationIndex:
    """Generate the documentation index and optionally update ``docs/index.md``."""

    docs_dir = docs_dir.resolve()
    index = _build_entries(docs_dir)
    block = _render_block(index)

    if not dry_run:
        if index_path is None:
            index_path = docs_dir / "index.md"
        _update_index_file(index_path, block)

    return index


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate docs/index.md")
    parser.add_argument(
        "--docs-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs",
        help="Root documentation directory (defaults to repo docs/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the generated index without writing files.",
    )
    args = parser.parse_args(argv)

    index = generate_documentation_index(
        args.docs_dir, dry_run=args.dry_run
    )

    if args.dry_run:
        print(_render_block(index).strip())
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
