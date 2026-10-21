"""Does an exported guard or range fact bound the destination of its sink? (``guard-bounds-destination/1``)

Design rule R3 (``evidence-admissibility/3``): a dominating guard or a bounded range only *qualifies*
``missing_or_ineffective_guard`` by default. It may contradict the predicate only when the application can show,
from the facts the graph export recorded, that it bounds the destination. These are pure, deterministic functions of
a ``guard_fact`` or ``range_fact`` result; no model output, prose or retrieval enters them. The evidence mapping
(``review.evidence``) and the scoring factor (``review.scoring.factors``) share them.

A guard bounds the destination iff all of the following hold:

1. ``guard_state`` is ``dominating`` and the guard is a comparison with a known operator and both operands;
2. ``constrains_sink_operand`` is ``true`` (``unknown`` and ``false`` never bound);
3. ``destination.object_bytes`` is known: the destination is a fixed-size object;
4. exactly one operand is a compile-time integer (kind ``constant``, or ``sizeof`` with an integer value) ``K``; the
   other operand is ``n``, the sink's size operand. Orienting the comparison as ``n REL K`` (flip when ``n`` is the
   right operand, negate when the sink runs on the false branch) yields an upper bound on ``n`` (``<``, ``<=``,
   ``==``) with ``K <= object_bytes`` (``<=`` and ``==``) or ``K <= object_bytes + 1`` (``<``).

Anything missing or outside the closed vocabulary does not bound, and the reason names it. The lower bound of ``n``
(a signed ``n`` can be negative) is not examined: the rule is about the upper bound against the destination.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

BOUNDS_RULE = "guard-bounds-destination/1"

_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}
_NEGATE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}
_UPPER = frozenset({"<", "<=", "=="})
_CONSTANT_KINDS = frozenset({"constant", "sizeof"})


@dataclass(frozen=True, slots=True)
class GuardBound:
    """Whether a fact bounds its sink's destination, and the reason either way."""

    bounds: bool
    reason: str


def _no(reason: str) -> GuardBound:
    return GuardBound(False, reason)


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _constant(operand: Any) -> int | None:
    if isinstance(operand, Mapping) and operand.get("kind") in _CONSTANT_KINDS and _integer(operand.get("value")):
        return int(operand["value"])
    return None


def destination_bytes(result: Mapping[str, Any]) -> int | None:
    """The destination object size a ``guard_fact`` result records, else ``None``."""
    destination = result.get("destination") if isinstance(result, Mapping) else None
    value = destination.get("object_bytes") if isinstance(destination, Mapping) else None
    return int(value) if _integer(value) and value > 0 else None


def sink_destination_bytes(guard_results: Iterable[Mapping[str, Any]]) -> int | None:
    """The one destination size the guard facts of a sink agree on; ``None`` when none or they disagree."""
    sizes = {destination_bytes(result) for result in guard_results}
    sizes.discard(None)
    return next(iter(sizes)) if len(sizes) == 1 else None


def guard_bounds_destination(result: Mapping[str, Any] | None) -> GuardBound:
    """Whether the ``guard_fact`` ``result`` shows its dominating comparison bounds the destination."""
    if not isinstance(result, Mapping):
        return _no("guard result is missing")
    state = result.get("guard_state")
    if state != "dominating":
        return _no(f"guard_state is {state or 'missing'}, not dominating")
    constrains = result.get("constrains_sink_operand")
    if constrains is not True:
        return _no("the comparison is not shown to involve the sink size operand"
                   f" (constrains_sink_operand={'unknown' if constrains in (None, 'unknown') else constrains})")
    capacity = destination_bytes(result)
    if capacity is None:
        return _no("destination object size is unknown")
    comparison = result.get("comparison")
    if not isinstance(comparison, Mapping):
        return _no("the guard is not a recorded comparison")
    operator = comparison.get("operator")
    if operator not in _FLIP:
        return _no(f"comparison operator {operator!r} is missing or not recognized")
    operands = comparison.get("operands")
    by_role = {item.get("role"): item for item in operands if isinstance(item, Mapping)} \
        if isinstance(operands, list) else {}
    if set(by_role) != {"lhs", "rhs"}:
        return _no("the compared operands are not both recorded")
    polarity = result.get("polarity")
    if polarity not in {"true_branch", "false_branch"}:
        return _no(f"polarity {polarity!r} is missing or not recognized")
    constants = {role: _constant(item) for role, item in by_role.items()}
    known = [role for role, value in constants.items() if value is not None]
    if len(known) == 2:
        return _no("both operands are constants, so the sink operand is not identified")
    if not known:
        return _no("the other operand is not a compile-time constant")
    bound_role = known[0]
    limit = constants[bound_role]
    relation = operator if bound_role == "rhs" else _FLIP[operator]     # n REL K
    if polarity == "false_branch":
        relation = _NEGATE[relation]
    if relation not in _UPPER:
        return _no(f"the comparison does not give an upper bound on the sink operand (n {relation} {limit})")
    allowed = capacity + 1 if relation == "<" else capacity
    if limit > allowed:
        return _no(f"bound n {relation} {limit} exceeds the {capacity}-byte destination")
    return GuardBound(True, f"n {relation} {limit} within the {capacity}-byte destination")


def range_bounds_destination(result: Mapping[str, Any] | None, destination_object_bytes: int | None) -> GuardBound:
    """Whether the ``range_fact`` ``result`` has a known upper bound within ``destination_object_bytes``.

    The range payload does not record the destination, so the caller passes the size its sink's guard facts agree on
    (:func:`sink_destination_bytes`); ``None`` never bounds and no number is invented.
    """
    if not isinstance(result, Mapping):
        return _no("range result is missing")
    interval = result.get("interval")
    if not isinstance(interval, Mapping):
        return _no("no interval was computed")
    if result.get("sign_change"):
        return _no("the conversion chain includes a sign change")
    upper = interval.get("upper")
    if not _integer(upper):
        return _no("the range has no known upper bound")
    if not _integer(destination_object_bytes) or destination_object_bytes <= 0:
        return _no("destination object size is unknown")
    if upper > destination_object_bytes:
        return _no(f"upper bound {upper} exceeds the {destination_object_bytes}-byte destination")
    return GuardBound(True, f"upper bound {upper} within the {destination_object_bytes}-byte destination")


def fact_bounds_destination(family: str, result: Mapping[str, Any] | None,
                            sink_destination: int | None = None) -> GuardBound:
    """Dispatch on the graph family (``guard_fact`` or ``range_fact``); any other family never bounds."""
    if family == "guard_fact":
        return guard_bounds_destination(result)
    if family == "range_fact":
        return range_bounds_destination(result, sink_destination)
    return _no(f"{family} facts do not bound a destination")


__all__ = ["BOUNDS_RULE", "GuardBound", "destination_bytes", "fact_bounds_destination", "guard_bounds_destination",
           "range_bounds_destination", "sink_destination_bytes"]
