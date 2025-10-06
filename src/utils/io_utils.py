"""Filesystem helpers for emitting human-readable artifacts."""

from __future__ import annotations

import base64
import json
import os
import tempfile
from typing import List


def _as_fs_path(path: str | os.PathLike[str]) -> str:
    return os.fspath(path)


def _ensure_directory(path: str) -> str:
    directory = os.path.dirname(path)
    if not directory:
        directory = "."
    os.makedirs(directory, exist_ok=True)
    return directory


def _atomic_write_text(
    path: str | os.PathLike[str],
    writer,
    *,
    encoding: str = "utf-8",
) -> None:
    target = _as_fs_path(path)
    directory = _ensure_directory(target)
    fd, temp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".partial", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, target)
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise

__all__ = [
    "ensure_out",
    "write_text",
    "write_json",
    "write_b64_text",
    "chunk_lines",
]


def ensure_out(*paths: str | os.PathLike[str]) -> str:
    """Ensure that the output directory ``paths`` exists and return it."""

    if paths:
        fs_path = os.path.join(*(os.fspath(p) for p in paths))
    else:
        fs_path = "out"
    os.makedirs(fs_path, exist_ok=True)
    return fs_path


def write_text(
    path: str | os.PathLike[str],
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Write ``content`` to ``path`` using UTF-8 encoding."""

    def _writer(handle) -> None:
        handle.write(content)

    _atomic_write_text(path, _writer, encoding=encoding)


def write_json(
    path: str | os.PathLike[str],
    obj,
    *,
    encoding: str = "utf-8",
    sort_keys: bool = False,
) -> None:
    """Serialise ``obj`` as pretty JSON at ``path``."""

    def _writer(handle) -> None:
        json.dump(obj, handle, ensure_ascii=False, indent=2, sort_keys=sort_keys)

    _atomic_write_text(path, _writer, encoding=encoding)


def write_b64_text(path: str | os.PathLike[str], raw: bytes) -> None:
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

