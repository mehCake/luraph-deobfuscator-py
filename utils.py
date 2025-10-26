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
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


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


@dataclass
class _BenchmarkStat:
    """Aggregate statistics for a benchmark category."""

    count: int = 0
    total: float = 0.0
    max_duration: float = 0.0
    last_event_id: int = 0
    events: deque[Tuple[int, float, Optional[Mapping[str, Any]]]] = field(
        default_factory=lambda: deque(maxlen=128)
    )


class BenchmarkRecorder:
    """Collects timing measurements for critical pipeline stages."""

    def __init__(self) -> None:
        self._stats: Dict[str, _BenchmarkStat] = defaultdict(_BenchmarkStat)
        self._lock = threading.Lock()

    @staticmethod
    def _coerce_metadata(metadata: Optional[Mapping[str, Any]] | Any) -> Optional[Dict[str, Any]]:
        if metadata is None:
            return None
        if isinstance(metadata, Mapping):
            result: Dict[str, Any] = {}
            for key, value in metadata.items():
                key_str = str(key)
                if isinstance(value, (str, int, float, bool)) or value is None:
                    result[key_str] = value
                else:
                    result[key_str] = str(value)
            return result
        return {"value": str(metadata)}

    def record(
        self,
        category: str,
        duration: float,
        metadata: Optional[Mapping[str, Any]] | Any = None,
    ) -> None:
        """Record a timing measurement for *category*."""

        if duration < 0:
            return
        meta = self._coerce_metadata(metadata)
        with self._lock:
            stat = self._stats[category]
            stat.count += 1
            stat.total += duration
            if duration > stat.max_duration:
                stat.max_duration = duration
            stat.last_event_id += 1
            stat.events.append((stat.last_event_id, duration, meta))

    def take_snapshot(self) -> Dict[str, Tuple[int, float, int]]:
        """Return a snapshot of the current aggregate counters."""

        with self._lock:
            return {
                category: (stat.count, stat.total, stat.last_event_id)
                for category, stat in self._stats.items()
            }

    def _iter_recent_events(
        self,
        stat: _BenchmarkStat,
        threshold: int,
    ) -> Iterable[Tuple[int, float, Optional[Mapping[str, Any]]]]:
        for event_id, duration, meta in stat.events:
            if event_id > threshold:
                yield event_id, duration, meta

    def summarize(
        self,
        snapshot: Optional[Dict[str, Tuple[int, float, int]]] = None,
        *,
        limit_samples: int = 3,
    ) -> List[Dict[str, Any]]:
        """Return aggregate statistics sorted by total runtime."""

        with self._lock:
            summaries: List[Dict[str, Any]] = []
            for category, stat in self._stats.items():
                prev_count = prev_total = prev_event = 0
                if snapshot:
                    prev_count, prev_total, prev_event = snapshot.get(
                        category, (0, 0.0, 0)
                    )
                count = stat.count - prev_count
                total = stat.total - prev_total
                recent_events = list(self._iter_recent_events(stat, prev_event))
                if snapshot and count <= 0:
                    count = len(recent_events)
                    total = sum(duration for _, duration, _ in recent_events)
                if count <= 0 or total <= 0:
                    continue
                max_duration = (
                    max((duration for _, duration, _ in recent_events), default=0.0)
                    if snapshot
                    else stat.max_duration
                )
                average = total / max(count, 1)
                samples: List[Dict[str, Any]] = []
                for _, duration, meta in recent_events[-limit_samples:]:
                    if meta is None:
                        continue
                    samples.append(
                        {
                            "duration": duration,
                            "metadata": meta,
                        }
                    )
                summaries.append(
                    {
                        "category": category,
                        "total": total,
                        "count": count,
                        "average": average,
                        "max": max_duration,
                        "samples": samples,
                    }
                )

        summaries.sort(key=lambda entry: entry["total"], reverse=True)
        return summaries

    def render_report(
        self,
        snapshot: Optional[Dict[str, Tuple[int, float, int]]] = None,
        *,
        limit_samples: int = 3,
    ) -> str:
        """Return a human-readable hotspot report."""

        summaries = self.summarize(snapshot, limit_samples=limit_samples)
        if not summaries:
            return "No benchmark data recorded."

        lines = ["Benchmark hotspots (sorted by total time):"]
        for entry in summaries:
            lines.append(
                "- {category}: {total:.6f}s over {count} events (avg {average:.6f}s, max {max:.6f}s)".format(
                    **entry
                )
            )
            for sample in entry.get("samples", []):
                metadata = sample.get("metadata") or {}
                if isinstance(metadata, dict):
                    meta_str = ", ".join(
                        f"{key}={value}" for key, value in sorted(metadata.items())
                    )
                else:
                    meta_str = str(metadata)
                lines.append(
                    f"    • {sample['duration']:.6f}s ({meta_str})"
                )
        return "\n".join(lines)


_BENCHMARK_RECORDER = BenchmarkRecorder()


def benchmark_recorder() -> BenchmarkRecorder:
    """Return the global :class:`BenchmarkRecorder` instance."""

    return _BENCHMARK_RECORDER


@contextmanager
def benchmark(category: str, metadata: Optional[Mapping[str, Any]] | Any = None):
    """Context manager that records execution time for ``category``."""

    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        benchmark_recorder().record(category, duration, metadata)


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


def byte_diff(
    a: bytes | bytearray | memoryview | None,
    b: bytes | bytearray | memoryview | None,
    *,
    context: int = 8,
) -> Dict[str, Any]:
    """Return structured information describing the first differing byte."""

    buf_a = bytes(a or b"")
    buf_b = bytes(b or b"")

    min_len = min(len(buf_a), len(buf_b))
    diff_index: int | None = None
    for index in range(min_len):
        if buf_a[index] != buf_b[index]:
            diff_index = index
            break
    else:
        if len(buf_a) != len(buf_b):
            diff_index = min_len

    if diff_index is None:
        return {
            "match": True,
            "index": None,
            "a_len": len(buf_a),
            "b_len": len(buf_b),
            "a_byte": None,
            "b_byte": None,
            "a_context": buf_a[-context:].hex() if buf_a else "",
            "b_context": buf_b[-context:].hex() if buf_b else "",
        }

    start = max(0, diff_index - context)
    end = min(max(len(buf_a), len(buf_b)), diff_index + context + 1)
    slice_a = buf_a[start:end]
    slice_b = buf_b[start:end]

    a_byte = buf_a[diff_index] if diff_index < len(buf_a) else None
    b_byte = buf_b[diff_index] if diff_index < len(buf_b) else None

    return {
        "match": False,
        "index": diff_index,
        "a_len": len(buf_a),
        "b_len": len(buf_b),
        "a_byte": a_byte,
        "b_byte": b_byte,
        "a_context": slice_a.hex(),
        "b_context": slice_b.hex(),
    }


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
    "byte_diff",
    "save_output",
    "setup_logging",
    "validate_input",
    "validate_file",
]
