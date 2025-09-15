from __future__ import annotations

import json
from importlib import import_module
from pathlib import Path
from typing import Any

_CONFIG_PATH = Path(__file__).with_name("config.json")
_CONFIG = json.loads(_CONFIG_PATH.read_text())


def get_handler(version: str) -> Any:
    """Return the module implementing *version*.

    The mapping between version strings and module names is stored in
    ``config.json`` next to this file.  ``KeyError`` is raised when an unknown
    version is requested.
    """

    modname = _CONFIG.get(version)
    if modname is None:
        raise KeyError(version)
    return import_module(f"{__name__}.{modname}")


__all__ = ["get_handler"]
