"""I/O helpers for Luraph deobfuscator."""

from importlib import import_module
from typing import Any

__all__ = ["load_lua_file", "extract_large_strings"]


def __getattr__(name: str) -> Any:  # pragma: no cover - trivial delegator
    if name in __all__:
        module = import_module(".loader", __name__)
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
