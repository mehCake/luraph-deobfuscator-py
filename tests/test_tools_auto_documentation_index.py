from __future__ import annotations

from pathlib import Path

import pytest

from src.tools.auto_documentation_index import (
    DocumentationIndex,
    generate_documentation_index,
    _BEGIN_MARKER,
    _END_MARKER,
)


@pytest.fixture()
def docs_tree(tmp_path: Path) -> Path:
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    (docs_dir / "IR.md").write_text("# IR Spec\n\nDetails", encoding="utf-8")
    (docs_dir / "USAGE.md").write_text("Usage guide", encoding="utf-8")
    examples = docs_dir / "examples"
    examples.mkdir()
    (examples / "sample.lua").write_text("print('demo')", encoding="utf-8")
    (examples / "README.md").write_text("# Example\ninfo", encoding="utf-8")
    return docs_dir


def read_index(path: Path) -> str:
    return (path / "index.md").read_text(encoding="utf-8")


def test_generate_index_creates_file(docs_tree: Path) -> None:
    index = generate_documentation_index(docs_tree)
    assert isinstance(index, DocumentationIndex)
    content = read_index(docs_tree)
    assert "IR Spec" in content
    assert "USAGE" in content  # fallback to file stem when no heading present
    assert "examples/sample.lua" in content


def test_update_preserves_manual_content(docs_tree: Path) -> None:
    index_path = docs_tree / "index.md"
    index_path.write_text(
        "Custom intro\n\n" + _BEGIN_MARKER + "\nold\n" + _END_MARKER + "\nTail", encoding="utf-8"
    )
    generate_documentation_index(docs_tree)
    updated = read_index(docs_tree)
    assert updated.startswith("Custom intro")
    assert updated.strip().endswith("Tail")
    assert "IR Spec" in updated


def test_dry_run_does_not_write(docs_tree: Path) -> None:
    generate_documentation_index(docs_tree, dry_run=True)
    assert not (docs_tree / "index.md").exists()
