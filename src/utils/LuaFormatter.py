"""Compatibility shim exposing :class:`LuaFormatter` under the legacy module path."""

from __future__ import annotations

from .. import utils as _legacy_utils

LuaFormatter = _legacy_utils.LuaFormatter

__all__ = ["LuaFormatter"]
