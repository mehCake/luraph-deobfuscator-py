from pathlib import Path

from src.tools.replace_insecure_patterns import (
    PatternMatch,
    scan_paths,
    write_warning_report,
    main,
)


def test_scan_paths_detects_multiple_patterns(tmp_path: Path) -> None:
    sample = tmp_path / "payload.lua"
    sample.write_text(
        """
        local function dangerous()
            os.execute('rm -rf /')
            local handle = io.open('secret.txt', 'w')
            return handle
        end
        """,
        encoding="utf-8",
    )

    matches = scan_paths([sample])
    assert {match.pattern for match in matches} >= {"os.execute", "io.open"}
    assert all(isinstance(match, PatternMatch) for match in matches)
    assert all(match.path == sample for match in matches)


def test_write_warning_report_creates_file(tmp_path: Path) -> None:
    sample = tmp_path / "script.lua"
    sample.write_text("return os.execute('ls')", encoding="utf-8")

    matches = scan_paths([sample])
    destination = tmp_path / "out" / "warnings.txt"
    write_warning_report(destination, matches)

    report = destination.read_text(encoding="utf-8")
    assert "Suspicious Constructs Detected" in report
    assert "os.execute" in report
    assert str(sample) in report


def test_cli_generates_report(tmp_path: Path) -> None:
    sample = tmp_path / "script.lua"
    sample.write_text("local ok = syn.request({Url='http://example.com'})", encoding="utf-8")

    output = tmp_path / "warnings.txt"
    exit_code = main([str(sample), "--output", str(output)])

    assert exit_code == 1
    content = output.read_text(encoding="utf-8")
    assert "syn.request" in content


def test_cli_no_findings_returns_zero(tmp_path: Path) -> None:
    sample = tmp_path / "clean.lua"
    sample.write_text("return 42", encoding="utf-8")

    output = tmp_path / "warnings.txt"
    exit_code = main([str(sample), "--output", str(output)])

    assert exit_code == 0
    assert "No suspicious constructs" in output.read_text(encoding="utf-8")
