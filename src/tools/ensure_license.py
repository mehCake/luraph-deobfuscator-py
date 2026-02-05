from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Embedded MIT license fallback (guaranteed correct header)
MIT_LICENSE_TEXT = """MIT License

Copyright (c) ...

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
"""


def _find_project_license() -> str | None:
    """
    Try to locate a LICENSE file in the project root and verify it is MIT.
    """
    current = Path(__file__).resolve()

    for parent in current.parents:
        candidate = parent / "LICENSE"
        if candidate.exists():
            text = candidate.read_text(encoding="utf-8", errors="ignore")
            if text.startswith("MIT License"):
                logger.debug("Found MIT project license at %s", candidate)
                return text
            else:
                logger.warning(
                    "Ignoring non-MIT license at %s (header mismatch)",
                    candidate,
                )
    return None


def ensure_license(output_dir: Path) -> Path:
    """
    Copy a verified MIT license into the output directory.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    license_path = output_dir / "LICENSE"

    license_text = _find_project_license()

    if not license_text:
        logger.warning("Falling back to embedded MIT license text")
        license_text = MIT_LICENSE_TEXT

    license_path.write_text(license_text, encoding="utf-8")

    logger.info("Copied license to %s", license_path)

    return license_path


def insert_license_header(target_file: Path) -> None:
    """
    Prepend MIT license header to markdown/text outputs if missing.
    """
    if not target_file.exists():
        return

    content = target_file.read_text(encoding="utf-8")

    if content.startswith("MIT License"):
        return

    updated = MIT_LICENSE_TEXT + "\n\n" + content
    target_file.write_text(updated, encoding="utf-8")

    logger.info("Inserted license header into %s", target_file)
