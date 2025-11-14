from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.tools.emit_examples_for_documentation import (
    ExampleGenerationError,
    emit_documentation_examples,
    main as run_emit_examples_cli,
)


def test_emit_examples_sanitises_outputs(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    docs_dir = tmp_path / "docs"
    out_dir.mkdir()

    # Create a pipeline candidate file with a forbidden field and two entries.
    candidates = [
        {
            "operations": [
                {"type": "prga", "confidence": 0.9},
                {"type": "permute", "confidence": 0.8},
            ],
            "secret": "should_be_removed",
        },
        {"operations": [{"type": "xor"}]},
    ]
    (out_dir / "pipeline_candidates.json").write_text(
        json.dumps(candidates),
        encoding="utf-8",
    )

    # Final report excerpt containing a line with the word "key" which must be filtered.
    (out_dir / "final_report.md").write_text(
        "Session analysis\n" "Do not leak KEY material\n" "Next steps listed here\n",
        encoding="utf-8",
    )

    # Prettified Lua snippet.
    (out_dir / "deobfuscated_pretty.lua").write_text(
        "print('hello world')\nreturn true\n",
        encoding="utf-8",
    )

    summary = emit_documentation_examples(out_dir=out_dir, docs_dir=docs_dir)

    examples_dir = docs_dir / "examples"
    assert examples_dir.is_dir()

    example_files = {path.name: path for path in summary.generated}
    assert "pipeline_candidates_example.json" in example_files
    assert "final_report_excerpt.md" in example_files
    assert "prettified_snippet.lua" in example_files

    # The pipeline example should contain only the first candidate and no secret field.
    pipeline_data = json.loads(
        (examples_dir / "pipeline_candidates_example.json").read_text(encoding="utf-8")
    )
    assert isinstance(pipeline_data, list)
    assert len(pipeline_data) == 1
    assert "secret" not in pipeline_data[0]

    # Final report excerpt should have removed the line containing "key".
    final_excerpt = (examples_dir / "final_report_excerpt.md").read_text(encoding="utf-8")
    assert "KEY" not in final_excerpt
    assert "Session analysis" in final_excerpt

    # Ensure the missing optional artefact (opcode proposals) was noted as skipped.
    assert any("opcode_proposals.json" in str(path) for path, _ in summary.skipped)


def test_emit_examples_cli_handles_missing_sources(tmp_path: Path) -> None:
    out_dir = tmp_path / "missing-out"
    docs_dir = tmp_path / "docs"

    with pytest.raises(ExampleGenerationError):
        emit_documentation_examples(out_dir=out_dir, docs_dir=docs_dir)

    out_dir.mkdir()
    # Without any artefacts the CLI should still report failure (no examples generated).
    exit_code = run_emit_examples_cli([
        "--out-dir",
        str(out_dir),
        "--docs-dir",
        str(docs_dir),
        "--quiet",
    ])
    assert exit_code == 1
