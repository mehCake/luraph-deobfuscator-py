"""Logging helpers for configuring per-run debug outputs."""

from __future__ import annotations

import logging
from pathlib import Path

__all__ = [
    "configure_debug_file_logger",
    "close_debug_logger",
]


def configure_debug_file_logger(
    name: str,
    path: Path,
    *,
    level: int = logging.DEBUG,
    formatter: logging.Formatter | None = None,
) -> logging.Logger:
    """Return a logger writing debug traces to ``path``.

    Any previously configured debug handlers on ``name`` are removed so repeated
    invocations replace earlier traces instead of appending to them.  The file
    is opened in text mode with UTF-8 encoding.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        if getattr(handler, "_lifter_debug_dump", False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover - defensive
                pass

    handler = logging.FileHandler(path, mode="w", encoding="utf-8")
    handler._lifter_debug_dump = True  # type: ignore[attr-defined]
    if formatter is None:
        formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def close_debug_logger(logger: logging.Logger) -> None:
    """Tear down debug handlers installed by :func:`configure_debug_file_logger`."""

    for handler in list(logger.handlers):
        if getattr(handler, "_lifter_debug_dump", False):
            logger.removeHandler(handler)
            try:
                handler.close()
            except Exception:  # pragma: no cover - defensive
                pass
