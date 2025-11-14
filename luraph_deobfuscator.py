"""Legacy compatibility wrapper for downstream tooling tests."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from version_detector import VersionDetector, VersionFeature, VersionInfo
from src.detect_protections import scan_lua


logger = logging.getLogger("LuraphDeobfuscator")


@dataclass
class EnhancedLuraphDeobfuscator:
    """Minimal stub preserving the historical public API.

    The original project exposed a richer interface that supported downloading
    payloads from URLs.  The modern test-suite only verifies that unsafe
    behaviour remains disabled, so the stub focuses on the guard-rail methods
    that previously raised.
    """

    allowed_extensions: Iterable[str] = (".lua", ".json")
    _detector: VersionDetector = field(default_factory=VersionDetector, init=False, repr=False)

    def process_input(self, path_or_text: str) -> None:
        if path_or_text.startswith(("http://", "https://")):
            raise ValueError("Remote URLs are disabled in the compatibility shim")
        candidate = Path(path_or_text)
        if candidate.suffix and candidate.suffix not in self.allowed_extensions:
            raise ValueError(f"Unsupported extension: {candidate.suffix}")
        raise NotImplementedError("This compatibility shim only enforces guard rails")

    def download_from_url(self, url: str) -> None:
        raise RuntimeError("Network access has been disabled in this environment")

    def summarise_detection(self, text: str, *, filename: str = "<memory>") -> str:
        """Log and return a concise detection summary for *text*."""

        version = self._detector.detect_version(text)
        version_label = self._format_version_label(version)

        report = scan_lua(text, filename=filename)
        profile = report.get("profile") if isinstance(report.get("profile"), dict) else {}
        descriptors = self._collect_descriptors(version, profile)

        summary = version_label
        if descriptors:
            summary = f"{version_label} ({', '.join(descriptors)})"
        logger.info(summary)
        return summary

    def _collect_descriptors(self, version: VersionInfo, profile: dict) -> list[str]:
        descriptors: list[str] = []
        if VersionFeature.LURAPH_V14_3_VM.value in version.features:
            descriptors.append("VM")

        real_life_label = self._classify_real_life(profile.get("real_life_score"))
        if real_life_label:
            descriptors.append(f"Real Life {real_life_label}")

        if profile.get("string_encryption") is True:
            descriptors.append("strings encrypted")

        double_packed = profile.get("double_packed_constants")
        if double_packed is None:
            double_packed = bool(version.profile.get("double_packed_constants"))
        if double_packed:
            descriptors.append("double-packed constants")

        return descriptors

    def _format_version_label(self, version: VersionInfo) -> str:
        if version.major:
            if version.minor:
                return f"Luraph v{version.major}.{version.minor}"
            return f"Luraph v{version.major}"
        if version.name and version.name != "unknown":
            return version.name.replace("_", " ")
        return "Luraph (unknown version)"

    def _classify_real_life(self, score: float | None) -> str | None:
        if score is None:
            return None
        if score >= 12.0:
            return "HIGH"
        if score >= 6.0:
            return "MEDIUM"
        return "LOW"


__all__ = ["EnhancedLuraphDeobfuscator"]
