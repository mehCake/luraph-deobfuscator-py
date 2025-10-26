from __future__ import annotations

import json
from pathlib import Path

from src.license_audit import collect_dependency_licenses, run_license_audit


def test_collect_dependency_licenses_handles_missing(tmp_path: Path) -> None:
    reqs = tmp_path / "reqs.txt"
    reqs.write_text("pytest\nnonexistent-pkg-license-check>=1.0\n", encoding="utf-8")

    records = collect_dependency_licenses(requirements_path=reqs)
    names = {record.name.lower() for record in records}
    assert "pytest" in names
    assert "nonexistent-pkg-license-check" in names
    missing = [record for record in records if not record.installed]
    assert any(record.name == "nonexistent-pkg-license-check" for record in missing)


def test_run_license_audit_writes_reports(tmp_path: Path) -> None:
    target = tmp_path / "sample.lua"
    target.write_text("return 1\n", encoding="utf-8")
    reqs = tmp_path / "reqs.txt"
    reqs.write_text("pytest\n", encoding="utf-8")

    result = run_license_audit(target, requirements_path=reqs)

    json_path = Path(result["report_path"])
    text_path = Path(result["text_report_path"])
    assert json_path.exists()
    assert text_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == len(payload["dependencies"])
    assert any(entry["name"].lower() == "pytest" for entry in payload["dependencies"])
