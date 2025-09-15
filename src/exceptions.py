"""Custom exception hierarchy for the deobfuscator."""

from __future__ import annotations


class DeobfuscationError(Exception):
    """Base class for all deobfuscation related errors."""


class VMEmulationError(DeobfuscationError):
    """Raised when the virtual machine encounters an unrecoverable issue."""


__all__ = ["DeobfuscationError", "VMEmulationError"]
