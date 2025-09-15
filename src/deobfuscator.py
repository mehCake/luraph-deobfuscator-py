"""Core Lua deobfuscation routines.

This module provides a small wrapper around the helper functions in
``src.utils`` to make it easy to decode the bundled example scripts or any
user provided file.  Heavy lifting such as beautifying, variable renaming or
pattern analysis live in their own modules; this file focuses purely on
turning obfuscated Lua text into something readable.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

from . import utils
from . import versions

logger = logging.getLogger(__name__)


class LuaDeobfuscator:
    """High level interface for decoding obfuscated Lua code."""

    def __init__(self) -> None:
        self.logger = logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def detect_version(self, content: str) -> str:
        """Best effort detection of the Luraph VM version used in *content*."""

        match = re.search(r"Luraph v(\d+\.\d+)", content)
        if match:
            v = match.group(1)
            if v.startswith("14.2"):
                return "v14.2"
            if v.startswith("14.1"):
                return "v14.1"
            if v.startswith("14.0"):
                return "v14.0.2"
        if "pcall" in content and "2611" in content:
            return "v14.2"
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "bytecode" in data:
                count = len(data["bytecode"])
                if count > 1000:
                    return "v14.2"
                if count > 500:
                    return "v14.1"
                return "v14.0.2"
        except Exception:
            pass
        return "unknown"

    def deobfuscate_content(self, content: str) -> str:
        """Return a best‑effort decoded version of ``content``."""
        # Some scripts wrap JSON payloads in Lua strings.  Extract such content
        # and decode it recursively before attempting any other format
        # detection.
        embedded = utils.extract_embedded_json(content)
        if embedded:
            return self.deobfuscate_content(embedded)

        version = self.detect_version(content)
        handler: Optional[object] = None
        if version != "unknown":
            try:
                handler = versions.get_handler(version)
            except KeyError:
                handler = None

        for decoder in (
            utils.decode_json_format,
            utils.decode_superflow,
            lambda c: utils.decode_virtual_machine(c, handler=handler),
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

