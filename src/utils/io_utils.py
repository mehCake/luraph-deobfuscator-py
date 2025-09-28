"""Filesystem helpers for emitting human-readable artifacts."""

from __future__ import annotations

import base64
import json
import os
from typing import Iterable, List

__all__ = [
    "ensure_out",
    "write_text",
    "write_json",
    "write_b64_text",
    "chunk_lines",
]


def ensure_out(*paths: str) -> str:
    """Ensure that the output directory ``paths`` exists and return it."""

    path = os.path.join(*paths) if paths else "out"
    os.makedirs(path, exist_ok=True)
    return path


def write_text(path: str, content: str) -> None:
    """Write ``content`` to ``path`` using UTF-8 encoding."""

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def write_json(path: str, obj) -> None:
    """Serialise ``obj`` as pretty JSON at ``path``."""

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(obj, handle, ensure_ascii=False, indent=2)


def write_b64_text(path: str, raw: bytes) -> None:
    """Write base64-encoded ``raw`` bytes to ``path`` as text."""

    encoded = base64.b64encode(raw).decode("ascii") if raw else ""
    write_text(path, encoded)


def chunk_lines(text: str, max_lines: int) -> List[str]:
    """Return ``text`` split into chunks containing ``max_lines`` lines each."""

    if max_lines <= 0:
        return [text]
    lines = text.splitlines()
    chunks: List[str] = []
    for index in range(0, len(lines), max_lines):
        chunk = "\n".join(lines[index : index + max_lines])
        chunks.append(chunk)
    if not chunks:
        return [text]
    return chunks

