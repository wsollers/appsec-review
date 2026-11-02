"""The numeric-reasoning guardrail contract: detection, tool-fact citation and the numeric weakness table."""
from __future__ import annotations

import pytest

from appsec_review.review import numeric_reasoning as nr


@pytest.mark.parametrize(("text", "categories"), [
    ("Subtraction cannot underflow after the header check.", (nr.ARITHMETIC_WRAP,)),
    ("The length is bounded to 0..65535 so the copy stays in range.", (nr.RANGE_BOUND,)),
    ("size * count can overflow before the allocation", (nr.ARITHMETIC_WRAP,)),
    ("integer overflow in the size calculation", (nr.ARITHMETIC_WRAP,)),
    ("the index is less than the buffer length", (nr.RANGE_BOUND,)),
    ("the value fits in a 16-bit field", (nr.RANGE_BOUND,)),
    ("len is never above SIZE_MAX", (nr.RANGE_BOUND,)),
    ("an off-by-one in the terminator write", (nr.ARITHMETIC_WRAP,)),
    ("the loop always terminates because i grows", (nr.LOOP_ITERATION,)),
    ("the loop bound is attacker controlled", (nr.LOOP_ITERATION,)),
    ("the parser runs at most 4 times per frame", (nr.LOOP_ITERATION,)),
    ("the invariant holds at the fixpoint after widening", (nr.LOOP_ITERATION,)),
    ("upper bound unchecked; the counter can wrap", (nr.RANGE_BOUND, nr.ARITHMETIC_WRAP)),
])
def test_detect_reports_numeric_categories(text: str, categories: tuple[str, ...]) -> None:
    assert nr.detect(text) == categories


@pytest.mark.parametrize("text", [
    None,
    "",
    "Command injection: request parameter reaches os.system without escaping.",
    "Buffer overflow reported by the scanner rule for strcpy into a stack array.",
    "Hard-coded credential in the deployment configuration.",
    "The excerpt is truncated; context is insufficient.",
    "A bounded question about the cited lines.",
    "Return one result per finding.",
])
def test_detect_ignores_non_numeric_text(text: str | None) -> None:
    assert nr.detect(text) == ()


@pytest.mark.parametrize(("text", "cites"), [
    ("R1 bounds the decoded length to 0..65535", True),
    ("G2 shows the header check", True),
    ("the CodeQL range fact for the sink", True),
    ("an AddressSanitizer report confirms the write", True),
    ("query_code_graph returned the guard", True),
    ("the length looks small enough", False),
    ("RFC 7230 limits the header", False),
    (None, False),
])
def test_cites_tool_fact(text: str | None, cites: bool) -> None:
    assert nr.cites_tool_fact(text) is cites


@pytest.mark.parametrize(("cwe", "normal"), [
    ("CWE-190", "CWE-190"), ("cwe 190", "CWE-190"), ("CWE-0190", "CWE-190"), (190, "CWE-190"),
    ("CWE:787", "CWE-787"), ("not-a-cwe", None), (None, None), (True, None),
])
def test_normalize_cwe(cwe: object, normal: str | None) -> None:
    assert nr.normalize_cwe(cwe) == normal  # type: ignore[arg-type]


def test_numeric_weakness_table() -> None:
    assert nr.NUMERIC_CWE_TABLE_VERSION == "numeric-weakness-cwes/1"
    for cwe in ("CWE-190", "CWE-191", "CWE-193", "CWE-129", "CWE-131", "CWE-369", "CWE-835", "CWE-787",
                "CWE-125", "CWE-119"):
        assert nr.is_numeric_weakness(cwe)
    for cwe in ("CWE-78", "CWE-79", "CWE-89", "CWE-798", "CWE-416", None):
        assert not nr.is_numeric_weakness(cwe)
    assert all(nr.normalize_cwe(cwe) == cwe for cwe in nr.NUMERIC_WEAKNESS_CWES)


def test_gap_and_rule_identities() -> None:
    assert nr.RULE == "numeric-reasoning-guardrail/1"
    assert nr.TRIAGE_GAP == "triage_unresolved:uncited_numeric_reasoning"
    assert nr.RULE in nr.SCORING_MISSING_REASON
