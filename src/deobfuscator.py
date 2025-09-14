"""Core Lua deobfuscation routines.

This module provides a small wrapper around the helper functions in
``src.utils`` to make it easy to decode the bundled example scripts or any
user provided file.  Heavy lifting such as beautifying, variable renaming or
pattern analysis live in their own modules; this file focuses purely on
turning obfuscated Lua text into something readable.
"""

from __future__ import annotations

import logging
from . import utils

logger = logging.getLogger(__name__)


class LuaDeobfuscator:
    """High level interface for decoding obfuscated Lua code."""

    def __init__(self) -> None:
        self.logger = logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def deobfuscate_content(self, content: str) -> str:
        """Return a best‑effort decoded version of ``content``."""
        # Some scripts wrap JSON payloads in Lua strings.  Extract such content
        # and decode it recursively before attempting any other format
        # detection.
        embedded = utils.extract_embedded_json(content)
        if embedded:
            return self.deobfuscate_content(embedded)

        # Try specialised formats next
        for decoder in (
            utils.decode_json_format,
            utils.decode_superflow,
            utils.decode_virtual_machine,
        ):
            result = decoder(content)
            if result:
                content = result
                break
        # Fallback to generic string/array decoding
        return utils.decode_simple_obfuscations(content)

    def deobfuscate_file(self, path: str) -> str:
        """Load ``path`` and return its decoded contents."""
        content = utils.safe_read_file(path)
        if content is None:
            raise FileNotFoundError(path)
        return self.deobfuscate_content(content)


__all__ = ["LuaDeobfuscator"]

