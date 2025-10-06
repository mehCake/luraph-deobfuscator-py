"""Decoders for bootstrap payload artefacts."""

from .lph85 import decode_lph85, strip_lph_prefix

__all__ = ["decode_lph85", "strip_lph_prefix"]
