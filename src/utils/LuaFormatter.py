"""Compatibility shim exposing :class:`LuaFormatter` under the legacy module path."""

from __future__ import annotations

try:
    from .. import utils as _legacy_utils
except Exception:  # pragma: no cover - optional dependency
    _legacy_utils = None


if _legacy_utils is not None and hasattr(_legacy_utils, "LuaFormatter"):
    LuaFormatter = _legacy_utils.LuaFormatter
else:
    class LuaFormatter:  # pragma: no cover - fallback shim
        """Minimal formatter used when the legacy helpers are unavailable."""

        def format(self, source: str) -> str:
            return source

__all__ = ["LuaFormatter"]
