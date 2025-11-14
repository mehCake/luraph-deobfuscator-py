from pathlib import Path

from src.tools.sanity_checks import main, run_sanity_checks


def test_run_sanity_checks_creates_report(tmp_path: Path) -> None:
    report = run_sanity_checks(output_dir=tmp_path, run_name="unit-test")
    assert report.name == "unit-test.md"
    content = report.read_text(encoding="utf-8")
    assert "Sanity Check Report" in content
    assert "Permutation round-trip" in content
    assert "LPH + PRGA parity" in content
    assert "Overall: PASS" in content


def test_sanity_checks_cli(tmp_path: Path) -> None:
    exit_code = main(["--output-dir", str(tmp_path), "--run-name", "cli-test"])
    assert exit_code == 0
    report = tmp_path / "sanity" / "cli-test.md"
    assert report.exists()
