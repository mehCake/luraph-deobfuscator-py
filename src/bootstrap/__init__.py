"""Bootstrap-specific helpers."""

from importlib import import_module
from typing import Any

__all__ = [
    "BootstrapChunk",
    "BootstrapCandidate",
    "extract_bootstrap_chunks",
    "identify_bootstrap_candidates",
    "LPHBlock",
    "scan_lph_blocks",
]


def __getattr__(name: str) -> Any:  # pragma: no cover - trivial delegator
    if name in {"BootstrapChunk", "BootstrapCandidate", "extract_bootstrap_chunks", "identify_bootstrap_candidates"}:
        module = import_module(".extract_bootstrap", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    if name in {"LPHBlock", "scan_lph_blocks"}:
        module = import_module(".lph_scan", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
