"""Helpers for writing lifter debug artifacts to disk."""

from __future__ import annotations

import logging
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Optional, Sequence

from .. import utils
from ..logging_config import close_debug_logger, configure_debug_file_logger
from ..utils import ensure_directory, write_json

__all__ = ["LifterDebugDump"]


class LifterDebugDump:
    """Manage debug artifacts for a single lifter execution."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        ensure_directory(base_dir)
        self._trace_logger: Optional[logging.Logger] = None

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def dump_raw_instructions(self, instructions: Sequence[Any]) -> None:
        """Write ``raw_instructions.json`` based on *instructions*."""

        serialised = []
        for entry in instructions:
            payload = self._coerce_instruction(entry)
            serialised.append(utils.serialise_metadata(payload))
        write_json(self.base_dir / "raw_instructions.json", serialised, sort_keys=False)

    def dump_opcode_table(self, opcode_table: Mapping[int, Mapping[str, Any] | Any]) -> None:
        """Write ``opcode_table_used.json`` summarising *opcode_table*."""

        payload: MutableMapping[str, Any] = {}
        for opcode, data in opcode_table.items():
            key = str(int(opcode) & 0x3F)
            payload[key] = utils.serialise_metadata(self._coerce_entry(data))
        write_json(self.base_dir / "opcode_table_used.json", payload, sort_keys=True)

    def dump_handler_snippets(self, opcode_table: Mapping[int, Mapping[str, Any] | Any]) -> None:
        """Write ``handler_snippets.json`` with source snippets per opcode."""

        snippets: MutableMapping[str, str] = {}
        for opcode, data in opcode_table.items():
            entry = self._coerce_entry(data)
            snippet = entry.get("source_snippet")
            if isinstance(snippet, str) and snippet.strip():
                snippets[str(int(opcode) & 0x3F)] = snippet
        write_json(self.base_dir / "handler_snippets.json", snippets, sort_keys=True)

    # ------------------------------------------------------------------
    # Trace logging
    # ------------------------------------------------------------------

    def trace_logger(self) -> logging.Logger:
        """Return a logger writing verbose traces to ``lift_trace.log``."""

        if self._trace_logger is None:
            log_path = self.base_dir / "lift_trace.log"
            self._trace_logger = configure_debug_file_logger("lifter.trace", log_path)
        return self._trace_logger

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close any loggers owned by this dump."""

        if self._trace_logger is not None:
            close_debug_logger(self._trace_logger)
            self._trace_logger = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_entry(value: Mapping[str, Any] | Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if is_dataclass(value):
            return asdict(value)
        if isinstance(value, Mapping):
            return {str(key): val for key, val in value.items()}
        if value is None:
            return {}
        return {"mnemonic": str(value)}

    @staticmethod
    def _coerce_instruction(entry: Any) -> Any:
        """Return a JSON-serialisable payload for *entry*."""

        if isinstance(entry, Mapping):
            raw = entry.get("raw")
            if raw is not None:
                return raw
            return dict(entry)

        if is_dataclass(entry) and not isinstance(entry, type):
            data = asdict(entry)
            raw = data.get("raw")
            if raw is not None:
                return raw
            return data

        asdict_method = getattr(entry, "_asdict", None)
        if callable(asdict_method):
            data = dict(asdict_method())
            raw = data.get("raw")
            if raw is not None:
                return raw
            return data

        if hasattr(entry, "__dict__"):
            data = {key: getattr(entry, key) for key in vars(entry)}
            raw = data.get("raw")
            if raw is not None:
                return raw
            return data

        return entry


