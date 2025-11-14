import json
from pathlib import Path
from textwrap import dedent

from src.tools.parity_reporter import (
    build_suggestion_report,
    load_parity_report,
    main,
    write_suggestion_markdown,
)


def _write_sample_report(path: Path) -> None:
    content = dedent(
        """
        # PRGA Parity Report

        * **Sample:** `tests/parity/sample_lph.bin`
        * **Variant:** `initv4 default`
        * **Comparison limit:** 64 bytes
        * **Result:** FAILURE
        * **Matching prefix:** 12/64 bytes

        ## Details
        Parity mismatch detected during comparison.

        * **Mismatch index:** 7
        * **Python byte:** 0x78
        * **Lua byte:** 0x3c
        * **Python context:** `0011223344556677`
        * **Lua context:** `0033221144556677`

        ## Brute-force search
        Attempts executed: 10
        Best prefix observed: 20/64 bytes
        Best candidate key (length 3 bytes) achieved the prefix above.
        No brute-force candidate matched the requested prefix length within constraints.

        ## Recommendations
        * Check PRGA variant parameters (e.g. rotate/permute tables).
        """
    ).strip()
    path.write_text(content + "\n", encoding="utf-8")


def test_load_parity_report_parses_fields(tmp_path: Path) -> None:
    report_path = tmp_path / "parity_report.md"
    _write_sample_report(report_path)

    report = load_parity_report(report_path)
    assert report.success is False
    assert report.mismatch_index == 7
    assert report.python_byte == 0x78
    assert report.lua_byte == 0x3C
    assert report.brute_force_best_length == 3
    assert report.brute_force_best_prefix == 20
    assert report.matching_prefix == 12
    assert report.limit == 64


def test_build_suggestion_report_includes_rotate_and_mapping(tmp_path: Path) -> None:
    report_path = tmp_path / "parity_report.md"
    _write_sample_report(report_path)

    mapping_dir = tmp_path / "mappings"
    mapping_dir.mkdir()
    mapping_payload = {
        "name": "perm_candidate",
        "confidence": 0.82,
        "permutation_score": 0.93,
        "mapping": [0, 1, 2, 3],
        "inverse": {"0": 0, "1": 1, "2": 2, "3": 3},
        "stats": {"length": 4},
        "version_hint": "v14.4.2",
    }
    (mapping_dir / "000_perm_candidate.json").write_text(
        json.dumps(mapping_payload),
        encoding="utf-8",
    )

    suggestion_report = build_suggestion_report(report_path, mapping_dir=mapping_dir)
    suggestions = suggestion_report.suggestions
    assert any("rotate amount 1" in entry for entry in suggestions)
    assert any("Permutation invert candidate" in entry for entry in suggestions)

    output_path = tmp_path / "parity_suggestions.md"
    write_suggestion_markdown(suggestion_report, output_path)
    output = output_path.read_text(encoding="utf-8")
    assert "PRGA mismatch" in output
    assert "Permutation invert candidate" in output


def test_parity_reporter_cli_generates_markdown(tmp_path: Path) -> None:
    report_path = tmp_path / "parity_report.md"
    _write_sample_report(report_path)

    mapping_dir = tmp_path / "mappings"
    mapping_dir.mkdir()
    mapping_dir.joinpath("000_perm.json").write_text(
        json.dumps(
            {
                "name": "candidate",
                "confidence": 0.7,
                "permutation_score": 0.88,
                "mapping": [0, 1, 2],
                "inverse": {"0": 0, "1": 1, "2": 2},
                "stats": {"length": 3},
            }
        ),
        encoding="utf-8",
    )

    output_path = tmp_path / "cli_output.md"
    exit_code = main(
        [
            "--report",
            str(report_path),
            "--mapping-dir",
            str(mapping_dir),
            "--output",
            str(output_path),
            "--log-level",
            "DEBUG",
        ]
    )

    assert exit_code == 0
    content = output_path.read_text(encoding="utf-8")
    assert "Permutation invert candidate" in content
    assert "PRGA mismatch" in content
