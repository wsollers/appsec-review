"""``graph.bounds``: when an exported guard or range fact shows it bounds the destination of its sink."""
from __future__ import annotations

from typing import Any

import pytest

from appsec_review.graph.bounds import (
    GuardBound, destination_bytes, guard_bounds_destination, range_bounds_destination, sink_destination_bytes,
)


def operand(role: str, kind: str, value: Any = None, text: str | None = None) -> dict[str, Any]:
    return {"role": role, "kind": kind, "value": value, "text": text, "location": None}


def const(role: str, value: int) -> dict[str, Any]:
    return operand(role, "constant", value, str(value))


def sized(role: str, value: int | None, text: str = "sizeof(out.name)") -> dict[str, Any]:
    return operand(role, "sizeof", value, text)


def var(role: str, text: str = "n") -> dict[str, Any]:
    return operand(role, "variable", None, text)


def guard(operator: str | None, lhs: dict, rhs: dict, *, polarity: str = "false_branch", state: str = "dominating",
          constrains: Any = True, capacity: int | None = 16) -> dict[str, Any]:
    comparison = None if operator is None else {"operator": operator, "bound_display": "x", "operands": [lhs, rhs]}
    return {"sink": {"sink_site": "asr:sink_site:" + "1" * 64}, "guard_state": state, "polarity": polarity,
            "condition": None, "constrains_sink_operand": constrains, "comparison": comparison,
            "destination": {"object_bytes": capacity}}


# (operator as written, sink operand n on the left?, K, polarity, capacity, bounds)
# A false branch negates the written relation; a constant on the left flips it. The result must be n REL K with
# REL in {<, <=, ==}, K <= capacity (K <= capacity + 1 for <).
CASES = [
    (">", True, 16, "false_branch", 16, True),       # if (n > 16) return;       -> n <= 16
    (">", True, 64, "false_branch", 16, False),      # if (n > 64) return;       -> n <= 64, over capacity
    (">=", True, 16, "false_branch", 16, True),      # if (n >= sizeof) return;  -> n < 16
    (">", True, 15, "false_branch", 16, True),
    (">", True, 17, "false_branch", 16, False),
    (">=", True, 17, "false_branch", 16, True),      # n < 17 is within capacity + 1
    (">=", True, 18, "false_branch", 16, False),
    ("<", True, 16, "false_branch", 16, False),      # sink runs when n >= 16: only a lower bound
    ("<=", True, 16, "false_branch", 16, False),
    ("==", True, 16, "false_branch", 16, False),     # sink runs when n != 16
    ("!=", True, 16, "false_branch", 16, True),      # sink runs when n == 16
    ("<", True, 16, "true_branch", 16, True),
    ("<", True, 17, "true_branch", 16, True),
    ("<", True, 18, "true_branch", 16, False),
    ("<=", True, 16, "true_branch", 16, True),
    ("<=", True, 17, "true_branch", 16, False),
    ("==", True, 16, "true_branch", 16, True),
    ("==", True, 17, "true_branch", 16, False),
    (">", True, 4, "true_branch", 16, False),        # lower bounds only
    (">=", True, 4, "true_branch", 16, False),
    ("!=", True, 16, "true_branch", 16, False),
    ("<", False, 16, "false_branch", 16, True),      # if (16 < n) return;       -> n <= 16
    ("<", False, 17, "false_branch", 16, False),
    ("<=", False, 17, "false_branch", 16, True),     # if (17 <= n) return;      -> n < 17
    (">", False, 16, "true_branch", 16, True),       # 16 > n                    -> n < 16
    (">", False, 17, "true_branch", 16, True),
    (">", False, 18, "true_branch", 16, False),
    (">=", False, 16, "true_branch", 16, True),      # 16 >= n                   -> n <= 16
    (">=", False, 17, "true_branch", 16, False),
    ("==", False, 16, "true_branch", 16, True),
    ("<", False, 16, "true_branch", 16, False),      # 16 < n                    -> lower bound
]


@pytest.mark.parametrize("operator, n_left, limit, polarity, capacity, expected", CASES)
@pytest.mark.parametrize("constant_kind", ["constant", "sizeof"])
def test_comparison_orientation_polarity_and_capacity(operator, n_left, limit, polarity, capacity, expected,
                                                      constant_kind) -> None:
    k_role, n_role = ("rhs", "lhs") if n_left else ("lhs", "rhs")
    k = const(k_role, limit) if constant_kind == "constant" else sized(k_role, limit)
    operands = [var(n_role), k] if n_left else [k, var(n_role)]
    result = guard_bounds_destination(guard(operator, *operands, polarity=polarity, capacity=capacity))
    assert isinstance(result, GuardBound) and result.bounds is expected and result.reason


def bounding(**changes: Any) -> dict[str, Any]:
    return {**guard(">", var("lhs"), const("rhs", 16)), **changes}


@pytest.mark.parametrize("changes, fragment", [
    ({"guard_state": "non_dominating"}, "not dominating"),
    ({"guard_state": "none"}, "not dominating"),
    ({"guard_state": "post_dominating_only"}, "not dominating"),
    ({"guard_state": None}, "not dominating"),
    ({"constrains_sink_operand": "unknown"}, "constrains_sink_operand"),
    ({"constrains_sink_operand": False}, "constrains_sink_operand"),
    ({"constrains_sink_operand": None}, "constrains_sink_operand"),
    ({"destination": {"object_bytes": None}}, "destination object size is unknown"),
    ({"destination": None}, "destination object size is unknown"),
    ({"destination": {"object_bytes": 0}}, "destination object size is unknown"),
    ({"comparison": None}, "not a recorded comparison"),
    ({"polarity": "unknown"}, "polarity"),
    ({"polarity": None}, "polarity"),
])
def test_missing_or_unrecognized_inputs_never_bound(changes, fragment) -> None:
    result = guard_bounds_destination(bounding(**changes))
    assert not result.bounds and fragment in result.reason
    assert guard_bounds_destination(bounding()).bounds        # the unmodified fixture does bound


def comparison(operator: Any, operands: Any) -> dict[str, Any]:
    return {"operator": operator, "bound_display": "x", "operands": operands}


@pytest.mark.parametrize("value, fragment", [
    (comparison("<=>", [var("lhs"), const("rhs", 16)]), "operator"),
    (comparison(None, [var("lhs"), const("rhs", 16)]), "operator"),
    (comparison(">", [var("lhs")]), "operands"),
    (comparison(">", None), "operands"),
    (comparison(">", [var("lhs"), var("rhs", "m")]), "not a compile-time constant"),
    (comparison(">", [const("lhs", 4), const("rhs", 16)]), "both operands"),
    (comparison(">", [var("lhs"), sized("rhs", None)]), "not a compile-time"),
    (comparison(">", [var("lhs"), operand("rhs", "other", 16, "16u")]), "not a compile-time"),
    (comparison(">", [var("lhs"), operand("rhs", "call", None, "f()")]), "not a compile-time"),
    (comparison(">", [var("lhs"), operand("rhs", "field", 16, "o.k")]), "not a compile-time"),
    (comparison(">", [var("lhs"), operand("rhs", "quantum", 16, "q")]), "not a compile-time"),
    (comparison(">", [var("lhs"), operand("rhs", "constant", True, "true")]), "not a compile-time"),
])
def test_unusable_comparisons_never_bound(value, fragment) -> None:
    result = guard_bounds_destination(bounding(comparison=value))
    assert not result.bounds and fragment in result.reason


def test_a_non_mapping_result_never_bounds() -> None:
    assert not guard_bounds_destination(None).bounds
    assert not guard_bounds_destination("x").bounds  # type: ignore[arg-type]


def test_packet_cpp_line_13_and_line_8_guards_do_not_bound() -> None:
    """Live-verified rows of the cpp-multivuln corpus (src/packet.cpp) into ``char name[16]``."""
    line_13 = guard("<", var("lhs", "size"), operand("rhs", "other", None, "4u + out.length"),
                    polarity="false_branch", constrains="unknown")
    line_8 = guard("<", var("lhs", "size"), const("rhs", 4), polarity="false_branch", constrains=False)
    assert not guard_bounds_destination(line_13).bounds and not guard_bounds_destination(line_8).bounds
    # Even with the sink operand identified, line 13's other operand is not a compile-time constant.
    assert "compile-time constant" in guard_bounds_destination({**line_13, "constrains_sink_operand": True}).reason


def test_destination_size_helpers() -> None:
    sixteen = guard(">", var("lhs"), const("rhs", 1))
    unknown = guard(None, var("lhs"), var("rhs"), capacity=None)
    assert destination_bytes(sixteen) == 16
    assert destination_bytes({"destination": {"object_bytes": None}}) is None and destination_bytes({}) is None
    assert sink_destination_bytes([sixteen, unknown]) == 16
    assert sink_destination_bytes([sixteen, guard(None, var("lhs"), var("rhs"), capacity=32)]) is None
    assert sink_destination_bytes([unknown]) is None and sink_destination_bytes([]) is None


def ranged(upper: Any, *, interval: bool = True, sign_change: bool = False) -> dict[str, Any]:
    return {"sink": {"sink_site": "asr:sink_site:" + "1" * 64}, "operand_index": 2, "applicability": "integral",
            "interval": {"lower": 0, "upper": upper} if interval else None, "sign_change": sign_change}


@pytest.mark.parametrize("result, capacity, expected", [
    (ranged(16), 16, True), (ranged(15), 16, True), (ranged(17), 16, False),
    (ranged(65535), 16, False),                                  # uint16_t into a 16-byte object
    (ranged("unknown"), 16, False), (ranged(None), 16, False), (ranged(16.0), 16, False),
    (ranged(16), None, False), (ranged(16), 0, False),
    (ranged(8, interval=False), 16, False), (ranged(8, sign_change=True), 16, False),
])
def test_range_bounds_only_with_a_known_upper_bound_within_the_destination(result, capacity, expected) -> None:
    outcome = range_bounds_destination(result, capacity)
    assert outcome.bounds is expected and outcome.reason


def test_range_without_a_result_never_bounds() -> None:
    assert not range_bounds_destination(None, 16).bounds
