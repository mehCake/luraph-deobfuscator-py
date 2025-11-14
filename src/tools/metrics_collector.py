"""Helpers for collecting runtime metrics during detection runs.

The metrics collector intentionally captures only high level diagnostic
information (timings, memory usage, step counts) so that no sensitive payload
data or session keys are persisted to disk.  Reports are written beneath
``out/metrics`` and keyed by the pipeline run identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
from pathlib import Path
import sys
import time
from typing import Any, Dict, Mapping, MutableMapping, Optional

LOGGER = logging.getLogger(__name__)

SENSITIVE_FIELD_NAMES = {"key", "secret", "token"}

__all__ = [
    "MetricsCollector",
    "MetricsReport",
    "collect_metrics",
]


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""

    return datetime.utcnow().isoformat(timespec="seconds")


def _max_rss_kb() -> Optional[int]:
    """Return the maximum resident set size in KiB if available."""

    try:  # ``resource`` is POSIX specific
        import resource  # type: ignore
    except Exception:  # pragma: no cover - unsupported platform
        return None

    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
    except Exception:  # pragma: no cover - defensive
        return None

    rss = getattr(usage, "ru_maxrss", None)
    if rss is None:
        return None

    # On macOS ``ru_maxrss`` is reported in bytes whereas Linux reports KiB.
    if sys.platform == "darwin":
        return int(rss / 1024)
    return int(rss)


def _is_sensitive_key(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in SENSITIVE_FIELD_NAMES)


def _sanitize_mapping(payload: Any) -> Any:
    """Return *payload* with any sensitive key entries removed."""

    if isinstance(payload, MutableMapping):
        cleaned: Dict[str, Any] = {}
        for key, value in payload.items():
            key_str = str(key)
            if _is_sensitive_key(key_str):
                LOGGER.debug("Dropping sensitive metric field '%s'", key_str)
                continue
            cleaned[key_str] = _sanitize_mapping(value)
        return cleaned
    if isinstance(payload, Mapping):  # pragma: no cover - defensive branch
        return {
            str(key): _sanitize_mapping(value)
            for key, value in payload.items()
            if not _is_sensitive_key(str(key))
        }
    if isinstance(payload, list):
        return [_sanitize_mapping(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(_sanitize_mapping(item) for item in payload)
    return payload


def _normalise_metric(value: Any) -> Any:
    """Normalise a metric value into a JSON serialisable representation."""

    if isinstance(value, (int, float)):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value
    if value is None:
        return None
    # Fallback to string representation for unexpected types.
    return str(value)


@dataclass(slots=True)
class MetricsReport:
    """Structured metrics for a detection run."""

    run_id: str
    created_at: str
    runtime_seconds: float
    max_rss_kib: Optional[int]
    step_counts: Dict[str, int] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "runtime_seconds": round(self.runtime_seconds, 6),
            "max_rss_kib": self.max_rss_kib,
            "step_counts": self.step_counts,
            "metrics": self.metrics,
            "extra": self.extra,
        }


class MetricsCollector:
    """Collect simple runtime metrics for a detection pipeline run."""

    def __init__(self) -> None:
        self._start_time = time.perf_counter()
        self._step_counts: Dict[str, int] = {}
        self._metrics: Dict[str, Any] = {}
        self._notes: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Step counting helpers
    # ------------------------------------------------------------------
    def record_count(self, name: str, value: int) -> None:
        """Record the absolute *value* for the named step."""

        if not name:
            return
        try:
            count = int(value)
        except (TypeError, ValueError):
            LOGGER.debug("Ignoring non-numeric count for %s: %r", name, value)
            return
        self._step_counts[name] = max(0, count)

    def increment(self, name: str, amount: int = 1) -> None:
        """Increment the named step count by *amount*."""

        if not name:
            return
        try:
            increment = int(amount)
        except (TypeError, ValueError):
            LOGGER.debug("Ignoring non-numeric increment for %s: %r", name, amount)
            return
        self._step_counts[name] = self._step_counts.get(name, 0) + increment

    # ------------------------------------------------------------------
    # Metric helpers
    # ------------------------------------------------------------------
    def observe(self, name: str, value: Any) -> None:
        """Record an arbitrary metric (converted to a JSON safe value)."""

        if not name:
            return
        self._metrics[name] = _normalise_metric(value)

    def note(self, name: str, value: Any) -> None:
        """Record auxiliary metadata about the run."""

        if not name:
            return
        self._notes[name] = _normalise_metric(value)

    # ------------------------------------------------------------------
    def build_report(
        self,
        *,
        run_id: str,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> MetricsReport:
        """Assemble a :class:`MetricsReport` without writing it to disk."""

        duration = max(0.0, time.perf_counter() - self._start_time)
        extra_payload = dict(self._notes)
        if extra:
            extra_payload.update({str(k): _normalise_metric(v) for k, v in extra.items()})
        cleaned_extra = _sanitize_mapping(extra_payload)

        return MetricsReport(
            run_id=run_id,
            created_at=_now_iso(),
            runtime_seconds=duration,
            max_rss_kib=_max_rss_kb(),
            step_counts=dict(sorted(self._step_counts.items())),
            metrics=dict(sorted(self._metrics.items())),
            extra=cleaned_extra,
        )

    def write_report(
        self,
        *,
        output_dir: Path,
        run_id: str,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Path:
        """Write a metrics report beneath *output_dir* and return the path."""

        report = self.build_report(run_id=run_id, extra=extra)
        path = output_dir / f"{run_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
        LOGGER.info("Wrote metrics report %s", path)
        return path


def collect_metrics(
    *,
    output_dir: Path,
    run_id: str,
    step_counts: Mapping[str, int],
    metrics: Mapping[str, Any],
    extra: Optional[Mapping[str, Any]] = None,
) -> Path:
    """Convenience wrapper to write a metrics report from raw mappings."""

    collector = MetricsCollector()
    for name, value in step_counts.items():
        collector.record_count(name, value)
    for name, value in metrics.items():
        collector.observe(name, value)
    return collector.write_report(output_dir=output_dir, run_id=run_id, extra=extra)
