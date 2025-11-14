from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path

from src.tools.auto_docstring import generate_module_documentation


def _write_module(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def test_generate_documentation_for_module_without_docstring(tmp_path: Path) -> None:
    module = _write_module(
        tmp_path / "src" / "pkg" / "sample.py",
        '''
        def greet(name):
            """Return a greeting."""

            return f"hi {name}"
        '''
    )

    doc_path = generate_module_documentation(
        module,
        output_dir=tmp_path / "docs",
        project_root=tmp_path,
        timestamp=datetime(2023, 1, 1, 0, 0, 0),
    )

    content = doc_path.read_text(encoding="utf-8")
    assert "pkg.sample" in content
    assert "greet" in content
    assert "Usage Example" in content
    assert "Return a greeting" in content


def test_appends_to_existing_document(tmp_path: Path) -> None:
    module = _write_module(
        tmp_path / "src" / "pkg" / "mod.py",
        '''
        """Existing documentation."""

        def run(task):
            return task()
        '''
    )

    output_dir = tmp_path / "docs"

    first = generate_module_documentation(
        module,
        output_dir=output_dir,
        project_root=tmp_path,
        timestamp=datetime(2023, 1, 1, 0, 0, 0),
    )
    first_content = first.read_text(encoding="utf-8")
    assert "Existing documentation" in first_content

    second = generate_module_documentation(
        module,
        output_dir=output_dir,
        project_root=tmp_path,
        timestamp=datetime(2023, 1, 2, 0, 0, 0),
    )
    second_content = second.read_text(encoding="utf-8")

    # Ensure we appended rather than overwrote the first run
    assert first_content in second_content
    assert "2023-01-02" in second_content

