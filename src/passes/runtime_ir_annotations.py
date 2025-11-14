"""Runtime IR annotation helpers for analysis tooling."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from opcode_lifter import BootstrapIR


@dataclass
class RuntimeIRAnnotations:
    """Summary of labels attached by :class:`RuntimeIRAnnotationPass`."""

    control_state_machine: Optional[str] = None
    constant_cache_label: Optional[str] = None
    primitive_table_label: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class RuntimeIRAnnotationPass:
    """Attach descriptive metadata to runtime IR structures."""

    def __init__(self) -> None:
        self._external_annotations: Dict[int, Dict[str, Any]] = {}
        self._last_annotations: Optional[RuntimeIRAnnotations] = None

    def run(
        self, bootstrap_ir: Optional[BootstrapIR], vm_entry: Any
    ) -> RuntimeIRAnnotations:
        """Annotate the supplied IR objects and return a summary."""

        summary = RuntimeIRAnnotations()

        if bootstrap_ir is not None:
            bootstrap_annotations = self._ensure_annotation_map(bootstrap_ir)
            runtime_bucket = bootstrap_annotations.setdefault("runtime", {})

            runtime_bucket["constant_cache"] = {
                "label": "constant cache",
                "slot_count": len(bootstrap_ir.cache_slots),
            }
            summary.constant_cache_label = "constant cache"

            if bootstrap_ir.c3_primitives is not None:
                entry_count = None
                if isinstance(bootstrap_ir.c3_primitives, dict):
                    raw_count = bootstrap_ir.c3_primitives.get("count")
                    if isinstance(raw_count, int):
                        entry_count = raw_count

                runtime_bucket["primitive_operations"] = {
                    "label": "primitive operations table",
                    "entry_count": entry_count,
                }
                summary.primitive_table_label = "primitive operations table"

        if vm_entry is not None:
            entry_annotations = self._ensure_annotation_map(vm_entry)
            runtime_bucket = entry_annotations.setdefault("runtime", {})

            control_var = self._extract_control_variable(vm_entry)
            if control_var:
                runtime_bucket["control_state_machine"] = {
                    "label": "control state machine",
                    "variable": control_var,
                }
                summary.control_state_machine = control_var

            cache_name = getattr(vm_entry, "constant_cache_name", None)
            if cache_name and "constant_cache" not in runtime_bucket:
                runtime_bucket["constant_cache"] = {
                    "label": "constant cache",
                    "name": cache_name,
                }

            primitive_name = getattr(vm_entry, "primitive_table_name", None)
            if primitive_name and "primitive_operations" not in runtime_bucket:
                runtime_bucket["primitive_operations"] = {
                    "label": "primitive operations table",
                    "name": primitive_name,
                }

        summary.extra = {
            "bootstrap_annotations": self._snapshot_external(bootstrap_ir),
            "vm_entry_annotations": self._snapshot_external(vm_entry),
        }
        self._last_annotations = summary
        return summary

    # ------------------------------------------------------------------
    def _ensure_annotation_map(self, target: Any) -> Dict[str, Any]:
        if target is None:
            return {}

        existing = getattr(target, "annotations", None)
        if isinstance(existing, dict):
            return existing

        annotations: Dict[str, Any] = {}
        try:
            setattr(target, "annotations", annotations)
            return annotations
        except Exception:
            self._external_annotations[id(target)] = annotations
            return annotations

    def _snapshot_external(self, target: Any) -> Optional[Dict[str, Any]]:
        if target is None:
            return None
        external = self._external_annotations.get(id(target))
        if external is None:
            return None
        return dict(external)

    def _extract_control_variable(self, vm_entry: Any) -> Optional[str]:
        for attr in (
            "control_variable",
            "state_variable",
            "dispatcher_variable",
            "loop_variable",
        ):
            value = getattr(vm_entry, attr, None)
            if isinstance(value, str) and value.strip():
                return value

        captures = getattr(vm_entry, "captures", None)
        if isinstance(captures, dict):
            for key, value in captures.items():
                if not isinstance(value, str):
                    continue
                lowered = str(key).lower()
                if any(marker in lowered for marker in ("control", "state", "dispatcher")):
                    if value.strip():
                        return value
        return None


__all__ = ["RuntimeIRAnnotations", "RuntimeIRAnnotationPass"]

