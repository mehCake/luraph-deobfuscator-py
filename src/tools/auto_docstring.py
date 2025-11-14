"""Utilities for generating lightweight documentation for Python modules.

This module scans Python source files, extracts their public API, and
generates Markdown snippets that capture module docstrings, public
symbols, and quick usage examples.  The resulting documents are placed
under ``docs/generated`` (or a caller supplied directory) so analysts
have quick reference material for freshly generated helper modules.

The helper never overwrites existing documentation.  When a document is
re-generated the freshly produced section is appended to the existing
file so that any manually curated notes remain intact.  Modules that do
not expose a top-level docstring receive a synthetic summary paragraph,
ensuring every document has a concise introduction.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from datetime import datetime
import textwrap
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


DEFAULT_OUTPUT_DIR = Path("docs/generated")
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DOC_MARKER = "<!-- AUTODOC GENERATED -->"


@dataclass
class PublicSymbol:
    """Container describing a public symbol extracted from a module."""

    name: str
    kind: str
    signature: str
    summary: str


def _normalise_signature(node: ast.AST) -> str:
    """Return a lightweight signature representation for a definition."""

    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = []
        params = node.args

        def _fmt_arg(arg: ast.arg, *, prefix: str = "") -> str:
            annotation = ast.unparse(arg.annotation) if arg.annotation else ""
            suffix = f": {annotation}" if annotation else ""
            return f"{prefix}{arg.arg}{suffix}" if suffix else f"{prefix}{arg.arg}"

        # Positional-only arguments (Python 3.8+)
        for arg in getattr(params, "posonlyargs", []):
            args.append(_fmt_arg(arg))
        if getattr(params, "posonlyargs", []):
            args.append("/")

        for arg in params.args:
            args.append(_fmt_arg(arg))

        if params.vararg:
            args.append(_fmt_arg(params.vararg, prefix="*"))

        if params.kwonlyargs:
            if not params.vararg:
                args.append("*")
            for arg, default in zip(
                params.kwonlyargs, params.kw_defaults, strict=False
            ):
                default_repr = (
                    ast.unparse(default)
                    if default is not None
                    else None
                )
                formatted = _fmt_arg(arg)
                if default_repr:
                    formatted = f"{formatted}={default_repr}"
                args.append(formatted)

        if params.kwarg:
            args.append(_fmt_arg(params.kwarg, prefix="**"))

        return f"({', '.join(args)})"

    if isinstance(node, ast.ClassDef):
        bases = [ast.unparse(base) for base in node.bases]
        return f"({', '.join(bases)})" if bases else ""

    return ""


def _first_sentence(docstring: str) -> str:
    """Return the first sentence (or line) of a docstring."""

    if not docstring:
        return "Automatically generated description."
    first_line = docstring.strip().splitlines()[0].strip()
    return first_line or "Automatically generated description."


def _extract_public_symbols(tree: ast.Module) -> List[PublicSymbol]:
    """Collect public function and class definitions from an AST tree."""

    symbols: List[PublicSymbol] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("_"):
                continue
            summary = _first_sentence(ast.get_docstring(node) or "")
            symbols.append(
                PublicSymbol(
                    name=node.name,
                    kind="function",
                    signature=_normalise_signature(node),
                    summary=summary,
                )
            )
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            summary = _first_sentence(ast.get_docstring(node) or "")
            symbols.append(
                PublicSymbol(
                    name=node.name,
                    kind="class",
                    signature=_normalise_signature(node),
                    summary=summary,
                )
            )
    return symbols


def _module_import_path(module_path: Path, project_root: Path) -> str:
    """Convert a module path into a dotted import string."""

    rel = module_path.resolve().relative_to(project_root.resolve())
    parts = list(rel.parts)
    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _output_path_for_module(module_path: Path, output_dir: Path, project_root: Path) -> Path:
    """Return the documentation path for the supplied module."""

    rel = module_path.resolve().relative_to(project_root.resolve())
    rel_parts = list(rel.parts)
    if rel_parts[-1].endswith(".py"):
        rel_parts[-1] = rel_parts[-1][:-3]
    if rel_parts[-1] == "__init__":
        rel_parts = rel_parts[:-1]
    doc_rel = Path(*rel_parts).with_suffix(".md")
    return output_dir / doc_rel


def _build_usage_example(import_path: str, symbols: Sequence[PublicSymbol]) -> str:
    if not symbols:
        return textwrap.dedent(
            f"""```
            import {import_path}

            # Access helpers via {import_path}
            """
        ).strip() + "\n```"

    primary = symbols[0]
    if primary.kind == "class":
        example_body = [
            f"from {import_path} import {primary.name}",
            f"instance = {primary.name}(...)  # instantiate the helper",
        ]
    else:
        example_body = [
            f"from {import_path} import {primary.name}",
            f"result = {primary.name}(...)  # invoke with real arguments",
        ]

    return "```python\n" + "\n".join(example_body) + "\n```"


def _build_documentation(
    module_path: Path,
    *,
    project_root: Path,
    symbols: Sequence[PublicSymbol],
    timestamp: datetime,
    module_docstring: str,
) -> str:
    import_path = _module_import_path(module_path, project_root)
    header = textwrap.dedent(
        f"""
        {_DOC_MARKER}
        # {import_path}

        Generated on {timestamp.isoformat()}.
        """
    ).strip()

    summary_section = textwrap.dedent(
        f"""
        ## Summary

        {module_docstring.strip() or 'Auto-generated module summary.'}
        """
    ).strip()

    if symbols:
        lines = ["## Public API"]
        for symbol in symbols:
            signature = symbol.signature or ""
            signature_text = f"``{symbol.name}{signature}``" if signature else f"``{symbol.name}``"
            lines.append(f"- {signature_text} – {symbol.summary}")
        api_section = "\n".join(lines)
    else:
        api_section = "## Public API\n\n_No public symbols discovered._"

    usage_section = "## Usage Example\n\n" + _build_usage_example(import_path, symbols)

    docstring_content = (
        module_docstring.strip()
        or f"Auto-generated module summary for {import_path}."
    )
    generated_docstring = textwrap.dedent(
        "## Suggested Docstring\n\n"
        + f'"""{docstring_content}"""'
    ).strip()

    return "\n\n".join(
        section
        for section in (
            header,
            summary_section,
            api_section,
            usage_section,
            generated_docstring,
        )
    )


def generate_module_documentation(
    module_path: Path,
    *,
    output_dir: Path | None = None,
    project_root: Path | None = None,
    timestamp: datetime | None = None,
    append: bool = True,
) -> Path:
    """Generate documentation for ``module_path``.

    Parameters
    ----------
    module_path:
        Path to the Python module that should be documented.
    output_dir:
        Directory that will contain the generated Markdown file.  Defaults to
        ``docs/generated`` relative to the project root.
    project_root:
        Root of the repository for deriving dotted import paths.  Defaults to
        the repository root inferred from this file.
    timestamp:
        Optional timestamp used for deterministic testing.
    append:
        When ``True`` (the default) the generated section is appended to an
        existing document rather than replacing its contents.
    """

    module_path = Path(module_path)
    project_root = Path(project_root) if project_root else _PROJECT_ROOT
    output_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    timestamp = timestamp or datetime.utcnow()

    module_source = module_path.read_text(encoding="utf-8")
    tree = ast.parse(module_source)
    module_doc = ast.get_docstring(tree) or (
        f"Auto-generated module summary for {_module_import_path(module_path, project_root)}."
    )
    symbols = _extract_public_symbols(tree)
    documentation = _build_documentation(
        module_path,
        project_root=project_root,
        symbols=symbols,
        timestamp=timestamp,
        module_docstring=module_doc,
    )

    doc_path = _output_path_for_module(module_path, output_dir, project_root)
    doc_path.parent.mkdir(parents=True, exist_ok=True)

    if doc_path.exists() and append:
        existing = doc_path.read_text(encoding="utf-8")
        if existing.strip():
            documentation = existing.rstrip() + "\n\n" + documentation

    doc_path.write_text(documentation + "\n", encoding="utf-8")
    return doc_path


def _iter_module_paths(paths: Iterable[str]) -> Iterable[Path]:
    for item in paths:
        path = Path(item)
        if path.is_dir():
            yield from path.rglob("*.py")
        else:
            yield path


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate module documentation stubs")
    parser.add_argument(
        "modules",
        nargs="+",
        help="Module paths or packages to document",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Destination for generated Markdown files",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=_PROJECT_ROOT,
        help="Repository root for deriving dotted import paths",
    )
    parser.add_argument(
        "--no-append",
        action="store_true",
        help="Overwrite existing documentation instead of appending",
    )

    args = parser.parse_args(argv)

    exit_code = 0
    for module_path in _iter_module_paths(args.modules):
        if not module_path.exists():
            parser.error(f"Module path not found: {module_path}")
        try:
            generate_module_documentation(
                module_path,
                output_dir=args.output_dir,
                project_root=args.project_root,
                append=not args.no_append,
            )
        except Exception as exc:  # pragma: no cover - surface helpful message
            exit_code = 1
            print(f"Failed to document {module_path}: {exc}")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
