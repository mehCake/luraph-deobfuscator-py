import zipfile
from datetime import datetime
from pathlib import Path

import pytest

from src.tools.export_for_reviewers import (
    DEFAULT_MAX_BLOB_SIZE,
    ExportForReviewersError,
    export_for_reviewers,
)


def write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def create_out_dir(base: Path) -> Path:
    out_dir = base / "out"
    write(out_dir / "deobfuscated_pretty.lua", b"print('hi')\n")
    write(out_dir / "final_report.md", b"## report\n")
    write(out_dir / "review_opmap.md", b"mnemonics\n")
    return out_dir


def test_export_for_reviewers_excludes_large_blobs(tmp_path: Path) -> None:
    out_dir = create_out_dir(tmp_path)
    write(out_dir / "intermediate" / "small.bin", b"data")
    big_blob = b"0" * (DEFAULT_MAX_BLOB_SIZE + 1)
    write(out_dir / "intermediate" / "big.bin", big_blob)

    summary = export_for_reviewers(
        out_dir=out_dir,
        dest_dir=tmp_path / "exports",
        include_blobs=False,
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
    )

    assert summary.archive_path.name == "review-20240101-000000.zip"
    included_names = {p.relative_to(out_dir).as_posix() for p in summary.included}
    assert "intermediate/small.bin" in included_names
    assert "intermediate/big.bin" not in included_names

    with zipfile.ZipFile(summary.archive_path) as zf:
        namelist = set(zf.namelist())
    assert "intermediate/big.bin" not in namelist


def test_export_for_reviewers_includes_large_blob_when_requested(tmp_path: Path) -> None:
    out_dir = create_out_dir(tmp_path)
    write(out_dir / "intermediate" / "big.bin", b"1" * (DEFAULT_MAX_BLOB_SIZE + 1))

    summary = export_for_reviewers(
        out_dir=out_dir,
        dest_dir=tmp_path / "exports",
        include_blobs=True,
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
    )

    included_names = {p.relative_to(out_dir).as_posix() for p in summary.included}
    assert "intermediate/big.bin" in included_names

    with zipfile.ZipFile(summary.archive_path) as zf:
        assert "intermediate/big.bin" in zf.namelist()


def test_export_for_reviewers_missing_required_file(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    write(out_dir / "deobfuscated_pretty.lua", b"print('hi')\n")

    with pytest.raises(ExportForReviewersError):
        export_for_reviewers(out_dir=out_dir, dest_dir=tmp_path / "exports")


def test_export_for_reviewers_skips_key_named_files(tmp_path: Path) -> None:
    out_dir = create_out_dir(tmp_path)
    write(out_dir / "intermediate" / "has_key.json", b'{"key": "secret"}')

    summary = export_for_reviewers(
        out_dir=out_dir,
        dest_dir=tmp_path / "exports",
        timestamp=datetime(2024, 1, 1, 0, 0, 0),
    )

    skipped = {path.relative_to(out_dir).as_posix() for path, _ in summary.skipped}
    assert "intermediate/has_key.json" in skipped
