"""
runtime_ir_annotations.py

Light-weight runtime IR annotations and a small symbolic evaluation engine
for cache / F3-style slots.

This module does NOT modify the original Lua code. It only attaches
metadata to cache slots so later analysis and devirtualisation passes can
reason about them more easily.

The key ideas are:

* Represent each slot assignment as a tiny expression tree built from:
    - literals (int/float),
    - references to other slots,
    - simple binary operators (+, -, *, //, /, %, ^, &, |, <<, >>).

* Track, for each slot, both:
    - the raw expression tree, and
    - a simplified numeric result when all dependencies are known.

* Iterate until a fixed point so that slots which depend only on already
  resolved slots become concrete numbers.

It is deliberately conservative: if an expression touches anything that
is not a literal or a known slot value, the evaluator just leaves it as
metadata and does NOT guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, Dict, Iterable, Optional, Set, Tuple, Union, List, Mapping

import re
from collections import Counter, defaultdict

Number = Union[int, float]


# ---------------------------------------------------------------------------
# Expression model
# ---------------------------------------------------------------------------

@dataclass
class LiteralExpr:
    """A literal numeric value, such as 123 or 0xFF."""
    value: Number

    def __repr__(self) -> str:
        return f"LiteralExpr({self.value!r})"


@dataclass
class SlotRefExpr:
    """
    Reference to another cache slot by index.

    The meaning of 'index' is left to the caller. In a typical F3 cache,
    this would be the numeric slot index used by the VM / bootstrap.
    """
    slot_index: int

    def __repr__(self) -> str:
        return f"SlotRefExpr(slot={self.slot_index})"


@dataclass
class BinaryOpExpr:
    """
    Binary operation over two expressions.

    `op` is a small string such as '+', '-', '*', '//', '/', '%', '^',
    '&', '|', '<<', '>>'.
    """
    op: str
    left: "Expression"
    right: "Expression"

    def __repr__(self) -> str:
        return f"BinaryOpExpr({self.op!r}, {self.left!r}, {self.right!r})"


Expression = Union[LiteralExpr, SlotRefExpr, BinaryOpExpr]


# ---------------------------------------------------------------------------
# Cache slot description (per-slot metadata container)
# ---------------------------------------------------------------------------

@dataclass
class CacheSlotInfo:
    """
    Description and analysis metadata for a single cache/F3 slot.

    Fields:
        index:
            Numeric slot index (as used by the VM/bootstrap).

        raw_expr:
            Symbolic representation of the expression used to assign the
            slot, in terms of LiteralExpr / SlotRefExpr / BinaryOpExpr.
            May be None for "unknown" or non-numeric initialisation.

        simplified_value:
            Concrete numeric value if we were able to fully evaluate
            `raw_expr` using already-known slot values. Otherwise None.

        dependencies:
            Set of slot indices that this slot reads from. Used to drive
            the fixed-point solver.

        notes:
            Free-form string for higher-level passes to attach context
            (e.g. "part of constant cache F3", "derived from header", etc.).
    """

    index: int
    raw_expr: Optional[Expression] = None
    simplified_value: Optional[Number] = None
    dependencies: Set[int] = field(default_factory=set)
    notes: str = ""
    used_in_string_decoder: bool = False
    used_in_serialized_data: bool = False
    used_in_vm_core: bool = False
    rarely_referenced: bool = False
    reference_contexts: Dict[str, int] = field(default_factory=dict)

    def record_expression(self, expr: Expression) -> None:
        """
        Attach an expression and recompute the dependencies set.
        Does not perform any evaluation; that is handled by the
        symbolic engine below.
        """
        self.raw_expr = expr
        self.dependencies = collect_dependencies(expr)

    def to_debug_dict(self) -> Dict[str, Any]:
        """
        Small JSON-serialisable view for dumping / debugging.
        """
        return {
            "index": self.index,
            "raw_expr": expr_to_debug_repr(self.raw_expr)
            if self.raw_expr is not None
            else None,
            "simplified_value": self.simplified_value,
            "dependencies": sorted(self.dependencies),
            "notes": self.notes,
            "used_in_string_decoder": self.used_in_string_decoder,
            "used_in_serialized_data": self.used_in_serialized_data,
            "used_in_vm_core": self.used_in_vm_core,
            "rarely_referenced": self.rarely_referenced,
            "reference_contexts": dict(self.reference_contexts),
        }


# ---------------------------------------------------------------------------
# Utilities over expressions
# ---------------------------------------------------------------------------

def collect_dependencies(expr: Expression) -> Set[int]:
    """
    Walk an expression tree and collect all slot indices that it refers to.

    This is used to compute CacheSlotInfo.dependencies.
    """
    deps: Set[int] = set()

    def _walk(e: Expression) -> None:
        if isinstance(e, SlotRefExpr):
            deps.add(e.slot_index)
        elif isinstance(e, BinaryOpExpr):
            _walk(e.left)
            _walk(e.right)
        # LiteralExpr has no dependencies

    _walk(expr)
    return deps


def expr_to_debug_repr(expr: Optional[Expression]) -> Any:
    """
    Return a JSON-friendly representation of an expression tree.

    This is intended for logging / diagnostics; callers should not rely
    on the exact structure beyond it being 'reasonably readable'.
    """
    if expr is None:
        return None
    if isinstance(expr, LiteralExpr):
        return {"kind": "literal", "value": expr.value}
    if isinstance(expr, SlotRefExpr):
        return {"kind": "slot_ref", "slot": expr.slot_index}
    if isinstance(expr, BinaryOpExpr):
        return {
            "kind": "binop",
            "op": expr.op,
            "left": expr_to_debug_repr(expr.left),
            "right": expr_to_debug_repr(expr.right),
        }
    # Fallback – should not normally happen
    return repr(expr)


# ---------------------------------------------------------------------------
# Symbolic evaluation
# ---------------------------------------------------------------------------

_SUPPORTED_OPS = {
    "+",
    "-",
    "*",
    "/",
    "//",
    "%",
    "^",
    "&",
    "|",
    "<<",
    ">>",
}


def _apply_op(op: str, left: Number, right: Number) -> Number:
    """
    Apply a simple arithmetic or bitwise operator to two concrete numbers.

    The semantics are intentionally boring and Python-like:
      * '/' always performs float division
      * '//' always performs floor division
    """
    if op == "+":
        return left + right
    if op == "-":
        return left - right
    if op == "*":
        return left * right
    if op == "/":
        return left / right
    if op == "//":
        return left // right
    if op == "%":
        return left % right
    if op == "^":
        # Lua uses ^ for exponent; Python uses **, so we bridge that here.
        return left ** right
    if op == "&":
        return int(left) & int(right)
    if op == "|":
        return int(left) | int(right)
    if op == "<<":
        return int(left) << int(right)
    if op == ">>":
        return int(left) >> int(right)

    raise ValueError(f"Unsupported operator in symbolic evaluator: {op!r}")


def try_evaluate_expression(
    expr: Expression,
    known_slots: Dict[int, Number],
) -> Tuple[Optional[Number], Expression]:
    """
    Try to evaluate `expr` to a concrete numeric value.

    Parameters
    ----------
    expr:
        Expression tree built from LiteralExpr / SlotRefExpr / BinaryOpExpr.

    known_slots:
        Mapping from slot index -> concrete numeric value. Typically this is
        derived from:

            { info.index: info.simplified_value
              for info in cache_slots.values()
              if info.simplified_value is not None }

    Returns
    -------
    (value, simplified_expr)

        * If evaluation succeeds entirely:
            - value is a concrete number
            - simplified_expr is a LiteralExpr(value)

        * If evaluation cannot complete (because some slots are unknown or
          because an unsupported operator / type was encountered):
            - value is None
            - simplified_expr is a partially simplified Expression which
              may still be useful for further passes.
    """

    # Literal: always known.
    if isinstance(expr, LiteralExpr):
        return expr.value, expr

    # Slot reference: only known when slot is present in known_slots.
    if isinstance(expr, SlotRefExpr):
        if expr.slot_index in known_slots:
            value = known_slots[expr.slot_index]
            return value, LiteralExpr(value)
        # Slot not yet known → keep as-is.
        return None, expr

    # Binary operation: recursively try to evaluate both sides.
    if isinstance(expr, BinaryOpExpr):
        if expr.op not in _SUPPORTED_OPS:
            # Unknown operator, give up but still try to simplify children.
            _, left_simplified = try_evaluate_expression(expr.left, known_slots)
            _, right_simplified = try_evaluate_expression(expr.right, known_slots)
            return None, BinaryOpExpr(expr.op, left_simplified, right_simplified)

        left_val, left_simplified = try_evaluate_expression(expr.left, known_slots)
        right_val, right_simplified = try_evaluate_expression(expr.right, known_slots)

        if left_val is not None and right_val is not None:
            try:
                value = _apply_op(expr.op, left_val, right_val)
            except Exception:
                # Overflow / ZeroDivision / etc.: treat as unknown.
                return None, BinaryOpExpr(expr.op, left_simplified, right_simplified)
            return value, LiteralExpr(value)

        # Cannot fully resolve; keep partially simplified tree.
        return None, BinaryOpExpr(expr.op, left_simplified, right_simplified)

    # Fallback: unknown expression type – do not crash, just leave it.
    return None, expr


# ---------------------------------------------------------------------------
# Fixed-point solver over a group of slots
# ---------------------------------------------------------------------------

def simplify_cache_slots(
    slots: Dict[int, CacheSlotInfo],
    max_passes: int = 8,
) -> None:
    """
    Given a mapping of slot index -> CacheSlotInfo, iteratively try to
    simplify each slot's expression using already-known slots.

    This function mutates the CacheSlotInfo objects in place:

        * .simplified_value is filled when an expression resolves.
        * .raw_expr is replaced with a more compact expression tree when
          partial simplification was possible (e.g. sub-expressions that
          folded into literals).

    The algorithm is intentionally simple:

        1. Build an initial map of known slot values.
        2. Loop up to `max_passes` times:
            - For each slot which has a raw_expr but no simplified_value:
                - Try to evaluate its expression.
                - If we obtained a concrete value, record it and add to the
                  known map.
                - Always store the simplified expression tree, even when
                  no concrete value is found.
        3. Stop early if a full pass did not resolve any new slots.

    This keeps behaviour predictable, and avoids infinite loops on cyclic
    dependencies.
    """

    # Initialise with any slots that already have a concrete value.
    known: Dict[int, Number] = {
        info.index: info.simplified_value
        for info in slots.values()
        if info.simplified_value is not None
    }

    if not slots:
        return

    for _round in range(max_passes):
        progress_made = False

        for idx, info in slots.items():
            if info.raw_expr is None:
                continue  # nothing to simplify
            if info.simplified_value is not None:
                continue  # already resolved

            value, simplified_expr = try_evaluate_expression(info.raw_expr, known)
            info.raw_expr = simplified_expr

            if value is not None:
                info.simplified_value = value
                known[idx] = value
                progress_made = True

        if not progress_made:
            break  # reached a fixed point


# ---------------------------------------------------------------------------
# Convenience helpers for callers
# ---------------------------------------------------------------------------

def build_slot_info_from_assignments(
    assignments: Iterable[Tuple[int, Expression]],
    *,
    existing: Optional[Dict[int, CacheSlotInfo]] = None,
    notes: str = "",
) -> Dict[int, CacheSlotInfo]:
    """
    Convenience to construct / update a cache slot mapping from a set
    of (slot_index, expression) pairs.

    Parameters
    ----------
    assignments:
        Iterable of (index, expr) pairs describing the expression used to
        assign each cache slot. The index here is whatever the caller uses
        to identify F3/cache slots.

    existing:
        Optional pre-existing mapping of slots. If provided, this function
        updates those CacheSlotInfo objects in place rather than creating
        new ones.

    notes:
        Optional notes string attached to any new CacheSlotInfo object.
        Existing entries are not overwritten.

    Returns
    -------
    Dict[int, CacheSlotInfo]
        The updated mapping (either the `existing` one or a new dict).
    """
    if existing is None:
        slots: Dict[int, CacheSlotInfo] = {}
    else:
        slots = existing

    for index, expr in assignments:
        info = slots.get(index)
        if info is None:
            info = CacheSlotInfo(index=index, notes=notes)
            slots[index] = info
        info.record_expression(expr)

    return slots


# ---------------------------------------------------------------------------
# Runtime annotation pass
# ---------------------------------------------------------------------------


@dataclass
class RuntimeIRAnnotationSummary:
    """Summary information produced by :class:`RuntimeIRAnnotationPass`."""

    constant_cache_label: Optional[str]
    constant_cache_slot_count: int
    primitive_table_label: Optional[str]
    primitive_table_entry_count: Optional[int]
    control_state_machine: Optional[str]
    slot_usage: Dict[int, Dict[str, Any]]


class RuntimeIRAnnotationPass:
    """Annotate runtime structures discovered during bootstrap lifting."""

    _DEFAULT_CACHE_NAME = "F3"
    _RARE_KEYWORDS = {
        "fallback",
        "rare",
        "panic",
        "error",
        "guard",
        "debug",
        "unused",
        "telemetry",
        "assert",
        "fail",
        "trap",
    }

    def run(self, bootstrap: Any, vm_entry: Any) -> RuntimeIRAnnotationSummary:
        runtime_annotations = self._ensure_runtime_container(bootstrap)
        constant_cache_info = self._annotate_constant_cache(runtime_annotations, bootstrap, vm_entry)
        primitive_info = self._annotate_primitive_table(runtime_annotations, bootstrap)
        control_variable = self._annotate_control_state(runtime_annotations, vm_entry)

        slot_usage = constant_cache_info.get("slot_usage", {})
        summary_slot_usage = {
            index: {
                "notes": info.notes,
                "used_in_string_decoder": info.used_in_string_decoder,
                "used_in_serialized_data": info.used_in_serialized_data,
                "used_in_vm_core": info.used_in_vm_core,
                "rarely_referenced": info.rarely_referenced,
                "reference_contexts": dict(info.reference_contexts),
            }
            for index, info in slot_usage.items()
        }

        return RuntimeIRAnnotationSummary(
            constant_cache_label=constant_cache_info.get("label"),
            constant_cache_slot_count=constant_cache_info.get("slot_count", 0),
            primitive_table_label=primitive_info.get("label"),
            primitive_table_entry_count=primitive_info.get("entry_count"),
            control_state_machine=control_variable,
            slot_usage=summary_slot_usage,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_runtime_container(self, bootstrap: Any) -> Dict[str, Any]:
        annotations = getattr(bootstrap, "annotations", None)
        if not isinstance(annotations, dict):
            annotations = {}
            setattr(bootstrap, "annotations", annotations)
        runtime = annotations.setdefault("runtime", {})
        return runtime

    def _annotate_constant_cache(
        self,
        runtime_annotations: Dict[str, Any],
        bootstrap: Any,
        vm_entry: Any,
    ) -> Dict[str, Any]:
        slots_info = self._analyse_slot_usage(bootstrap, vm_entry)
        slot_usage_payload = {
            str(index): info.to_debug_dict()
            for index, info in sorted(slots_info.items())
        }

        slot_count = len(getattr(bootstrap, "cache_slots", []) or [])
        payload = {
            "label": "constant cache",
            "slot_count": slot_count,
            "slot_usage": slots_info,
            "slot_usage_payload": slot_usage_payload,
            "rare_slots": [index for index, info in slots_info.items() if info.rarely_referenced],
        }

        runtime_annotations["constant_cache"] = {
            "label": payload["label"],
            "slot_count": payload["slot_count"],
            "slot_usage": slot_usage_payload,
            "rare_slots": payload["rare_slots"],
        }

        return payload

    def _annotate_primitive_table(
        self, runtime_annotations: Dict[str, Any], bootstrap: Any
    ) -> Dict[str, Any]:
        primitives = getattr(bootstrap, "c3_primitives", None)
        entry_count: Optional[int]
        if isinstance(primitives, Mapping):
            entry_count = primitives.get("count")
            if entry_count is None:
                entries = primitives.get("entries")
                if isinstance(entries, (list, tuple, set)):
                    entry_count = len(entries)
        else:
            entry_count = None

        payload = {
            "label": "primitive operations table",
            "entry_count": entry_count,
        }

        runtime_annotations["primitive_operations"] = {
            "label": payload["label"],
            "entry_count": payload["entry_count"],
        }
        return payload

    def _annotate_control_state(self, runtime_annotations: Dict[str, Any], vm_entry: Any) -> Optional[str]:
        entry_annotations = getattr(vm_entry, "annotations", None)
        if not isinstance(entry_annotations, dict):
            entry_annotations = {}
            setattr(vm_entry, "annotations", entry_annotations)
        runtime_entry = entry_annotations.setdefault("runtime", {})

        control_var = self._extract_control_variable(vm_entry)
        runtime_entry["control_state_machine"] = {"variable": control_var}
        return control_var

    def _extract_control_variable(self, vm_entry: Any) -> Optional[str]:
        if isinstance(getattr(vm_entry, "control_variable", None), str):
            return vm_entry.control_variable

        captures = getattr(vm_entry, "captures", None)
        if isinstance(captures, Mapping):
            for key in ("state", "control", "dispatcher", "state_machine"):
                value = captures.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    def _analyse_slot_usage(self, bootstrap: Any, vm_entry: Any) -> Dict[int, CacheSlotInfo]:
        cache_name = getattr(vm_entry, "constant_cache_name", self._DEFAULT_CACHE_NAME)
        if not isinstance(cache_name, str) or not cache_name:
            cache_name = self._DEFAULT_CACHE_NAME

        slots: Dict[int, CacheSlotInfo] = {}
        for slot in getattr(bootstrap, "cache_slots", []) or []:
            index = self._normalise_slot_index(slot)
            if index is None:
                continue
            notes = getattr(slot, "semantic_role", "")
            info = CacheSlotInfo(index=index, notes=notes)
            slots[index] = info

        context_fragments = self._collect_reference_fragments(bootstrap, vm_entry)
        pattern = self._build_reference_pattern(cache_name)
        context_counters: Dict[int, Counter] = defaultdict(Counter)

        for context_name, fragments in context_fragments.items():
            for fragment in fragments:
                for index in self._find_referenced_slots(fragment, pattern):
                    if index not in slots:
                        slots[index] = CacheSlotInfo(index=index, notes="inferred reference")
                    context_counters[index][context_name] += 1

        for index, info in slots.items():
            counters = context_counters.get(index, Counter())
            info.reference_contexts = dict(counters)
            info.used_in_string_decoder = counters.get("string_decoder", 0) > 0
            info.used_in_serialized_data = counters.get("serialized_data", 0) > 0
            info.used_in_vm_core = counters.get("vm_core", 0) > 0

            context_names = {name for name, count in counters.items() if count}
            total_hits = sum(counters.values())
            if context_names and context_names <= {"rare_branch"}:
                info.rarely_referenced = True
            elif total_hits <= 1 and not (
                info.used_in_string_decoder
                or info.used_in_serialized_data
                or info.used_in_vm_core
            ):
                info.rarely_referenced = True
            else:
                info.rarely_referenced = False

        return slots

    def _normalise_slot_index(self, slot: Any) -> Optional[int]:
        index = getattr(slot, "index_value", None)
        if isinstance(index, int):
            return index

        literal = getattr(slot, "index_literal", None)
        if isinstance(literal, str) and literal:
            parsed = self._parse_numeric_token(literal)
            if parsed is not None:
                return parsed
        return None

    def _collect_reference_fragments(self, bootstrap: Any, vm_entry: Any) -> Dict[str, List[str]]:
        fragments: Dict[str, List[str]] = {
            "string_decoder": [],
            "serialized_data": [],
            "vm_core": [],
            "rare_branch": [],
        }

        string_decoder = getattr(bootstrap, "string_decoder", None)
        if string_decoder is not None:
            fragments["string_decoder"].extend(self._flatten_to_strings(string_decoder))

        serialized = getattr(bootstrap, "serialized_chunk", None)
        if serialized is not None:
            fragments["serialized_data"].extend(self._flatten_to_strings(serialized))

        captures = getattr(vm_entry, "captures", None)
        if isinstance(captures, Mapping):
            for name, value in captures.items():
                target = "rare_branch" if self._is_rare_context(name, value) else "vm_core"
                fragments[target].extend(self._flatten_to_strings(value))

        handlers = getattr(vm_entry, "handlers", None)
        if handlers is not None:
            fragments["vm_core"].extend(self._flatten_to_strings(handlers))

        operations = getattr(vm_entry, "operations", None)
        if operations is not None:
            fragments["vm_core"].extend(self._flatten_to_strings(operations))

        return fragments

    def _flatten_to_strings(self, value: Any) -> List[str]:
        strings: List[str] = []
        visited: Set[int] = set()

        def _walk(obj: Any) -> None:
            if isinstance(obj, str):
                strings.append(obj)
                return

            obj_id = id(obj)
            if obj_id in visited:
                return
            visited.add(obj_id)

            if obj is None:
                return

            if isinstance(obj, Mapping):
                for key, val in obj.items():
                    _walk(key)
                    _walk(val)
                return

            if isinstance(obj, (list, tuple, set, frozenset)):
                for item in obj:
                    _walk(item)
                return

            if is_dataclass(obj):
                for field_info in fields(obj):
                    _walk(getattr(obj, field_info.name))
                return

            if hasattr(obj, "__dict__"):
                _walk(vars(obj))
                return

            strings.append(str(obj))

        _walk(value)
        return strings

    def _is_rare_context(self, name: Any, value: Any) -> bool:
        text_components = []
        if isinstance(name, str):
            text_components.append(name)
        if isinstance(value, str):
            text_components.append(value)
        elif isinstance(value, Mapping):
            text_components.extend(str(key) for key in value.keys())

        combined = " ".join(component.lower() for component in text_components)
        return any(keyword in combined for keyword in self._RARE_KEYWORDS)

    def _build_reference_pattern(self, cache_name: str) -> re.Pattern[str]:
        pattern = rf"\b{re.escape(cache_name)}\s*\[\s*(0x[0-9a-fA-F_]+|\d+)\s*\]"
        return re.compile(pattern)

    def _find_referenced_slots(self, text: str, pattern: re.Pattern[str]) -> List[int]:
        matches: List[int] = []
        for match in pattern.finditer(text):
            token = match.group(1)
            value = self._parse_numeric_token(token)
            if value is not None:
                matches.append(value)
        return matches

    def _parse_numeric_token(self, token: str) -> Optional[int]:
        cleaned = token.replace("_", "").strip()
        if not cleaned:
            return None
        base = 10
        if cleaned.lower().startswith("0x"):
            base = 16
        try:
            return int(cleaned, base)
        except ValueError:
            return None
