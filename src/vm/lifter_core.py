"""Compatibility wrapper exposing the new lifter implementation."""

from __future__ import annotations

from src.lifter.lifter import LiftOutput, lift_program

__all__ = ["LiftOutput", "lift_program"]
