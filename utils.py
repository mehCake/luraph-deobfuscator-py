"""Utility helpers used by the legacy CLI wrappers.

The top-level scripts (``run.py`` and ``luraph_deobfuscator.py``) pre-date the
new pass-based pipeline that lives in :mod:`src`.  They are still useful for
driving the tool in one-shot scenarios, therefore this module re-implements the
minimal plumbing they expect: logging configuration, safe file I/O helpers and
some light string utilities.  The implementations intentionally avoid side
effects (such as network access) so they can be reused in automated tests and
within sandboxed environments.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def setup_logging(log_level: int = logging.INFO) -> logging.Logger:
    """Return a logger configured for console output only.

    Historical versions of the project wrote logs to ``luraph_deobfuscator.log``
    which could easily clutter temporary directories and slow down repeated
    runs.  The helper now only configures a stream handler so invoking the
    legacy entry points remains side-effect free.  ``logging.basicConfig`` is
    used to keep the implementation simple while still respecting existing
    handlers if a caller configures logging separately.
    """

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("LuraphDeobfuscator")


def validate_file(filepath: str) -> bool:
    """Return ``True`` if *filepath* exists and is readable."""

    path = Path(filepath)
    try:
        return path.is_file() and os.access(path, os.R_OK)
    except OSError:
        return False


def validate_input(filepath: str) -> None:
    """Raise :class:`FileNotFoundError` if *filepath* is not a readable file."""

    if not validate_file(filepath):
        raise FileNotFoundError(filepath)


def create_output_path(input_path: str, suffix: str = "_deob.lua") -> str:
    """Create a deterministic output path next to ``input_path``.

    The helper mirrors :func:`src.utils.create_output_path` so the legacy entry
    points write files alongside their inputs while avoiding accidental
    overwrites of the original source.
    """

    path = Path(input_path)
    return str(path.with_name(path.stem + suffix))


def get_output_filename(input_path: str) -> str:
    """Return the default output filename for ``input_path``."""

    return create_output_path(input_path)


def read_file_content(filepath: str) -> str:
    """Return the content of *filepath* decoded as UTF-8.

    Errors are ignored so the deobfuscator can work with partially corrupted
    or mixed-encoding samples.
    """

    with open(filepath, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def save_output(content: str, output_path: str) -> None:
    """Persist *content* to ``output_path`` creating parent directories."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def print_banner() -> None:
    """Print a small banner used by the legacy CLI."""

    print("=== Luraph Deobfuscator ===")


def extract_nested_loadstrings(content: str) -> List[str]:
    """Return all string payloads passed to :func:`loadstring` calls.

    The extractor keeps the implementation intentionally simple: it only
    understands literal strings (single/double quoted or Lua long brackets) and
    ignores dynamic expressions.  This behaviour matches what the previous
    version of the tool supported while remaining deterministic.
    """

    pattern = re.compile(
        r"loadstring\s*\(\s*(?P<quote>['\"]).*?(?P=quote)\s*\)",
        re.DOTALL,
    )
    results: List[str] = []
    for match in pattern.finditer(content):
        snippet = match.group(0)
        literal_match = re.search(r"(['\"])(.*?)(?<!\\)\1", snippet, re.DOTALL)
        if literal_match:
            results.append(literal_match.group(2))
    bracket_pattern = re.compile(r"loadstring\s*\(\s*\[\[(.*?)\]\]\s*\)", re.DOTALL)
    results.extend(bracket_pattern.findall(content))
    return results


def normalize_whitespace(content: str) -> str:
    """Normalise newlines and collapse trailing whitespace."""

    content = content.replace("\r\n", "\n").replace("\r", "\n")
    content = re.sub(r"[ \t]+\n", "\n", content)
    return content.strip() + "\n"


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hexadecimal strings to bytes while ignoring separators."""

    hex_str = re.sub(r"[^0-9a-fA-F]", "", hex_str)
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        logging.getLogger("LuraphDeobfuscator").warning("invalid hex payload")
        return b""


def find_hex_patterns(text: str) -> List[str]:
    """Return candidate hex blobs embedded inside *text*."""

    return re.findall(r"(superflow_bytecode_ext\d+|[a-fA-F0-9]{16,})", text)


def safe_exec(code: str, globals_dict: Optional[Dict[str, Any]] = None) -> Any:
    """Execute ``code`` in a restricted global namespace.

    ``eval`` is only used for short expressions (e.g. constant folding helpers).
    Any exception results in ``None`` so callers can gracefully fall back to
    alternative strategies.
    """

    try:
        return eval(code, globals_dict or {})
    except Exception:
        logging.getLogger("LuraphDeobfuscator").debug("safe_exec failure", exc_info=True)
        return None


__all__ = [
    "create_output_path",
    "extract_nested_loadstrings",
    "find_hex_patterns",
    "get_output_filename",
    "hex_to_bytes",
    "normalize_whitespace",
    "print_banner",
    "read_file_content",
    "safe_exec",
    "save_output",
    "setup_logging",
    "validate_input",
    "validate_file",
]
