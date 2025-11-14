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

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional, Set, Tuple, Union

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
