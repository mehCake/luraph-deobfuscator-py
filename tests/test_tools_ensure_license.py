from pathlib import Path

from src.tools.ensure_license import (
    DEFAULT_LICENSE_FILENAME,
    MIT_LICENSE_TEXT,
    ensure_license,
    ensure_license_file,
    ensure_license_headers,
    ensure_output_license,
    main as run_ensure_license,
)


def test_ensure_license_file_creates_and_reuses(tmp_path: Path) -> None:
    license_path, created = ensure_license_file(tmp_path)
    assert created is True
    assert license_path.name == DEFAULT_LICENSE_FILENAME
    assert license_path.read_text(encoding="utf-8").startswith("MIT License")

    license_path.write_text("custom", encoding="utf-8")
    second_path, created_again = ensure_license_file(tmp_path)
    assert second_path == license_path
    assert created_again is False
    assert license_path.read_text(encoding="utf-8") == "custom"


def test_output_license_copy(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    license_path = repo / DEFAULT_LICENSE_FILENAME
    license_path.write_text(MIT_LICENSE_TEXT, encoding="utf-8")

    output_dir = tmp_path / "out"
    copied = ensure_output_license(license_path, output_dir)
    assert copied.exists()
    assert copied.read_text(encoding="utf-8") == MIT_LICENSE_TEXT

    copied.write_text("modified", encoding="utf-8")
    ensure_output_license(license_path, output_dir)
    assert copied.read_text(encoding="utf-8") == "modified"


def test_license_headers_injected(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Report\n", encoding="utf-8")
    script = tmp_path / "script.lua"
    script.write_text("return true\n", encoding="utf-8")

    updated = ensure_license_headers([report, script])
    assert report in updated and script in updated
    assert report.read_text(encoding="utf-8").startswith("<!-- Licensed under the MIT License")
    assert script.read_text(encoding="utf-8").startswith("-- Licensed under the MIT License")

    # Running again should not duplicate headers.
    updated_again = ensure_license_headers([report, script])
    assert updated_again == []


def test_main_invocation(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    header_path = out_dir / "summary.md"
    header_path.write_text("Summary\n", encoding="utf-8")

    argv = [
        "--repo-root",
        str(repo),
        "--output-dir",
        str(out_dir),
        "--header",
        str(header_path),
    ]
    assert run_ensure_license(argv) == 0

    license_path = repo / DEFAULT_LICENSE_FILENAME
    assert license_path.exists()
    assert (out_dir / DEFAULT_LICENSE_FILENAME).exists()
    assert header_path.read_text(encoding="utf-8").startswith("<!-- Licensed under the MIT License")


def test_ensure_license_report_structure(tmp_path: Path) -> None:
    repo_root = tmp_path / "project"
    repo_root.mkdir()
    out_dir = repo_root / "out"
    out_dir.mkdir()
    target = out_dir / "report.md"
    target.write_text("Body", encoding="utf-8")

    report = ensure_license(
        repo_root,
        output_dirs=[out_dir],
        header_paths=[target],
    )

    assert report.license_path.exists()
    assert report.output_licenses == [out_dir / DEFAULT_LICENSE_FILENAME]
    assert report.header_updates == [target]
