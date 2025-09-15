from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

_CONFIG_PATH = Path(__file__).with_name("config.json")
_DATA = json.loads(_CONFIG_PATH.read_text())
_VERSIONS: Dict[str, Dict[str, Any]] = _DATA.get("versions", {})


def get_handler(version: str) -> Any:
    """Return the module implementing *version*.

    The mapping between version strings and module names is stored in
    ``config.json`` next to this file.  ``KeyError`` is raised when an unknown
    version is requested.
    """

    descriptor = _VERSIONS.get(version)
    if descriptor is None:
        raise KeyError(version)
    modname = descriptor.get("module")
    if not isinstance(modname, str):  # pragma: no cover - defensive programming
        raise KeyError(version)
    return import_module(f"{__name__}.{modname}")


def iter_descriptors() -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Yield ``(version, descriptor)`` pairs from the configuration."""

    return _VERSIONS.items()


def get_descriptor(version: str) -> Dict[str, Any]:
    """Return a shallow copy of the descriptor for *version*."""

    descriptor = _VERSIONS.get(version)
    if descriptor is None:
        raise KeyError(version)
    return dict(descriptor)


__all__ = ["get_handler", "get_descriptor", "iter_descriptors"]
