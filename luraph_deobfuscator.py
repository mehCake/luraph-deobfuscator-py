"""Legacy compatibility wrapper for downstream tooling tests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class EnhancedLuraphDeobfuscator:
    """Minimal stub preserving the historical public API.

    The original project exposed a richer interface that supported downloading
    payloads from URLs.  The modern test-suite only verifies that unsafe
    behaviour remains disabled, so the stub focuses on the guard-rail methods
    that previously raised.
    """

    allowed_extensions: Iterable[str] = (".lua", ".json")

    def process_input(self, path_or_text: str) -> None:
        if path_or_text.startswith(("http://", "https://")):
            raise ValueError("Remote URLs are disabled in the compatibility shim")
        candidate = Path(path_or_text)
        if candidate.suffix and candidate.suffix not in self.allowed_extensions:
            raise ValueError(f"Unsupported extension: {candidate.suffix}")
        raise NotImplementedError("This compatibility shim only enforces guard rails")

    def download_from_url(self, url: str) -> None:
        raise RuntimeError("Network access has been disabled in this environment")


__all__ = ["EnhancedLuraphDeobfuscator"]
