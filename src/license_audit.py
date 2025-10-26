"""Utilities for auditing third-party dependencies and their licenses."""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_REQUIREMENTS = _PROJECT_ROOT / "requirements.txt"

_COMPATIBLE_KEYWORDS = (
    "mit",
    "apache",
    "bsd",
    "isc",
    "zlib",
    "psf",
    "python software foundation",
    "lgpl",
)

_REVIEW_KEYWORDS = ("gpl", "proprietary", "unknown")

_REQ_SPLIT_RE = re.compile(r"[<>=!~\[]")


@dataclass(frozen=True)
class LicenseRecord:
    name: str
    version: Optional[str]
    license: str
    compatibility: str
    installed: bool
    summary: str

    def to_json(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "license": self.license,
            "compatibility": self.compatibility,
            "installed": self.installed,
            "summary": self.summary,
        }


def _parse_requirement_names(lines: Iterable[str]) -> List[str]:
    names: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            # Ignore nested requirements or pip directives in this lightweight parser.
            continue
        name = _REQ_SPLIT_RE.split(line, 1)[0].strip()
        if not name:
            continue
        names.append(name)
    return names


def _load_requirements(requirements_path: Optional[Path]) -> List[str]:
    if requirements_path is None:
        requirements_path = _DEFAULT_REQUIREMENTS
    try:
        text = requirements_path.read_text(encoding="utf-8")
    except OSError:
        return []
    return _parse_requirement_names(text.splitlines())


def _normalise_license(value: Optional[str]) -> str:
    if not value:
        return "UNKNOWN"
    return value.strip()


def _classify_license(license_text: str, installed: bool) -> str:
    if not installed:
        return "missing"
    lowered = license_text.lower()
    if any(keyword in lowered for keyword in _COMPATIBLE_KEYWORDS):
        return "compatible"
    if any(keyword in lowered for keyword in _REVIEW_KEYWORDS):
        return "review"
    return "needs_review"


def _extract_license_from_metadata(dist: metadata.Distribution) -> str:
    info = dist.metadata
    direct = info.get("License")
    if direct and direct.strip():
        return direct.strip()
    classifiers = info.get_all("Classifier", [])
    for classifier in classifiers:
        if classifier.lower().startswith("license ::"):
            parts = classifier.split("::")
            if parts:
                candidate = parts[-1].strip()
                if candidate:
                    return candidate
    return "UNKNOWN"


def collect_dependency_licenses(
    *, requirements_path: Optional[Path] = None
) -> List[LicenseRecord]:
    names = _load_requirements(requirements_path)
    seen = set()
    records: List[LicenseRecord] = []
    for name in names:
        canonical = name.lower()
        if canonical in seen:
            continue
        seen.add(canonical)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            records.append(
                LicenseRecord(
                    name=name,
                    version=None,
                    license="UNKNOWN",
                    compatibility="missing",
                    installed=False,
                    summary="not installed",
                )
            )
            continue
        license_text = _normalise_license(_extract_license_from_metadata(dist))
        compatibility = _classify_license(license_text, installed=True)
        version = dist.version
        summary = f"{license_text} ({compatibility})"
        records.append(
            LicenseRecord(
                name=dist.metadata.get("Name", name),
                version=version,
                license=license_text,
                compatibility=compatibility,
                installed=True,
                summary=summary,
            )
        )
    records.sort(key=lambda record: record.name.lower())
    return records


def _summarise(records: Sequence[LicenseRecord]) -> Dict[str, int]:
    summary: Dict[str, int] = {
        "total": len(records),
        "compatible": 0,
        "needs_review": 0,
        "review": 0,
        "missing": 0,
    }
    for record in records:
        kind = record.compatibility
        if kind in summary:
            summary[kind] += 1
        else:
            summary.setdefault(kind, 0)
            summary[kind] += 1
    return summary


def _format_text_report(payload: Dict[str, object]) -> str:
    summary = payload["summary"]  # type: ignore[assignment]
    assert isinstance(summary, dict)
    header = [
        "License audit report",
        f"Generated at: {payload['generated_at']}",
        f"Requirements file: {payload['requirements_path']}",
        "",
        "Summary:",
    ]
    for key in sorted(summary):
        header.append(f"  {key}: {summary[key]}")
    header.append("")
    header.append("Dependencies:")
    header.append("name,version,license,compatibility,installed")
    deps = payload["dependencies"]  # type: ignore[assignment]
    assert isinstance(deps, list)
    for entry in deps:
        if not isinstance(entry, dict):
            continue
        header.append(
            ",".join(
                [
                    str(entry.get("name", "")),
                    str(entry.get("version", "")),
                    str(entry.get("license", "")),
                    str(entry.get("compatibility", "")),
                    "yes" if entry.get("installed") else "no",
                ]
            )
        )
    return "\n".join(header) + "\n"


def run_license_audit(
    output_path: Path,
    *,
    requirements_path: Optional[Path] = None,
) -> Dict[str, object]:
    records = collect_dependency_licenses(requirements_path=requirements_path)
    summary = _summarise(records)
    timestamp = _dt.datetime.utcnow().isoformat() + "Z"
    req_path = (
        str(requirements_path)
        if requirements_path is not None
        else str(_DEFAULT_REQUIREMENTS)
    )
    payload: Dict[str, object] = {
        "generated_at": timestamp,
        "requirements_path": req_path,
        "summary": summary,
        "dependencies": [record.to_json() for record in records],
    }

    json_path = output_path.with_suffix(".license_audit.json")
    text_path = output_path.with_suffix(".license_audit.txt")
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    text_path.write_text(_format_text_report(payload), encoding="utf-8")

    return {
        "report_path": str(json_path),
        "text_report_path": str(text_path),
        "summary": summary,
        "dependencies": [record.to_json() for record in records],
        "requirements_path": req_path,
    }


def main() -> None:  # pragma: no cover - convenience entry point
    requirements_env = os.environ.get("LICENSE_AUDIT_REQUIREMENTS")
    requirements_path = Path(requirements_env) if requirements_env else None
    target = os.environ.get("LICENSE_AUDIT_OUTPUT", "reconstructed.lua")
    result = run_license_audit(Path(target), requirements_path=requirements_path)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":  # pragma: no cover - module entry point
    main()
