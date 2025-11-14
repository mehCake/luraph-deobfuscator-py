"""Ensure the repository and generated artefacts carry an explicit license."""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, Sequence

LOGGER = logging.getLogger(__name__)

MIT_LICENSE_TEXT = """MIT License

Copyright (c) 2024 Luraph Deobfuscator Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

DEFAULT_LICENSE_FILENAME = "LICENSE"
DEFAULT_HEADERS: Mapping[str, str] = {
    ".md": "<!-- Licensed under the MIT License. See LICENSE file in the repository root. -->\n",
    ".lua": "-- Licensed under the MIT License. See LICENSE file in the repository root.\n",
    ".py": "# Licensed under the MIT License. See LICENSE file in the repository root.\n",
    ".sh": "# Licensed under the MIT License. See LICENSE file in the repository root.\n",
    ".txt": "Licensed under the MIT License. See LICENSE file in the repository root.\n",
}

__all__ = [
    "DEFAULT_HEADERS",
    "DEFAULT_LICENSE_FILENAME",
    "LicenseReport",
    "MIT_LICENSE_TEXT",
    "ensure_license_file",
    "ensure_output_license",
    "ensure_license_headers",
    "ensure_license",
    "main",
]


@dataclass(slots=True)
class LicenseReport:
    """Summary of operations performed when ensuring license coverage."""

    license_path: Path
    created: bool
    output_licenses: List[Path]
    header_updates: List[Path]


def ensure_license_file(
    repo_root: Path,
    *,
    filename: str = DEFAULT_LICENSE_FILENAME,
    license_text: str = MIT_LICENSE_TEXT,
) -> tuple[Path, bool]:
    """Ensure a license file exists in ``repo_root``.

    Returns the resolved license path and whether it was created during this call.
    """

    license_path = repo_root / filename
    if license_path.exists():
        if not license_path.is_file():
            raise RuntimeError(f"Existing license path is not a file: {license_path}")
        return license_path, False

    license_path.write_text(license_text, encoding="utf-8")
    LOGGER.info("Created license file at %s", license_path)
    return license_path, True


def ensure_output_license(
    license_path: Path,
    output_dir: Path,
    *,
    filename: str = DEFAULT_LICENSE_FILENAME,
) -> Path:
    """Copy the repository license into ``output_dir`` if it is absent."""

    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / filename
    if destination.exists():
        return destination

    destination.write_text(license_path.read_text(encoding="utf-8"), encoding="utf-8")
    LOGGER.info("Copied license to %s", destination)
    return destination


def _apply_header(content: str, header: str) -> str | None:
    """Return updated content with the header applied, or ``None`` if unchanged."""

    if not header:
        return None

    bom = "\ufeff" if content.startswith("\ufeff") else ""
    body = content[len(bom) :]

    if body.startswith(header):
        return None

    separator = "" if body.startswith("\n") or not body else "\n"
    return bom + header + separator + body


def ensure_license_headers(
    paths: Iterable[Path],
    *,
    header_templates: Mapping[str, str] = DEFAULT_HEADERS,
) -> List[Path]:
    """Ensure each path begins with the appropriate license header."""

    updated: List[Path] = []
    for path in paths:
        if not path or not path.exists() or not path.is_file():
            continue
        template = header_templates.get(path.suffix.lower())
        if not template:
            continue
        original = path.read_text(encoding="utf-8")
        updated_content = _apply_header(original, template)
        if updated_content is None:
            continue
        path.write_text(updated_content, encoding="utf-8")
        updated.append(path)
        LOGGER.info("Inserted license header into %s", path)
    return updated


def ensure_license(
    repo_root: Path,
    *,
    output_dirs: Sequence[Path] | None = None,
    header_paths: Sequence[Path] | None = None,
    filename: str = DEFAULT_LICENSE_FILENAME,
    license_text: str = MIT_LICENSE_TEXT,
) -> LicenseReport:
    """Ensure the repository and selected artefacts reference the project license."""

    license_path, created = ensure_license_file(
        repo_root, filename=filename, license_text=license_text
    )

    output_licenses: List[Path] = []
    for directory in output_dirs or ():
        output_licenses.append(ensure_output_license(license_path, directory, filename=filename))

    header_updates = ensure_license_headers(header_paths or ())

    return LicenseReport(
        license_path=license_path,
        created=created,
        output_licenses=output_licenses,
        header_updates=header_updates,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Ensure the repository contains a license file and copy it into output "
            "artefact directories while injecting license headers into selected files."
        )
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path.cwd(),
        help="Repository root that should contain the LICENSE file (default: CWD)",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dirs",
        action="append",
        type=Path,
        default=[],
        help="Output directory that should receive a copy of the license (repeatable)",
    )
    parser.add_argument(
        "--header",
        dest="header_targets",
        action="append",
        type=Path,
        default=[],
        help="File that should be prefixed with a license header (repeatable)",
    )
    parser.add_argument(
        "--license-name",
        default=DEFAULT_LICENSE_FILENAME,
        help="Filename to use for the license (default: LICENSE)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    report = ensure_license(
        repo_root=args.repo_root,
        output_dirs=args.output_dirs,
        header_paths=args.header_targets,
        filename=args.license_name,
    )

    if report.created:
        LOGGER.info("License created at %s", report.license_path)
    else:
        LOGGER.info("License verified at %s", report.license_path)

    if report.output_licenses:
        for path in report.output_licenses:
            LOGGER.info("Output directory now contains license: %s", path)

    if report.header_updates:
        for path in report.header_updates:
            LOGGER.info("Injected license header into %s", path)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
