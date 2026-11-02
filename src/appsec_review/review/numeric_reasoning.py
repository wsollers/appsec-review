"""Numeric-reasoning guardrail (``numeric-reasoning-guardrail/1``): numeric facts come from tools, not prose.

Language models often reach a correct conclusion through unsound reasoning about value ranges, bounds, integer
wrap, loop trip counts, termination, invariants and fixpoints (Mitchell et al., arXiv:2503.12686). Those facts must
come from a deterministic tool artifact: a graph range or guard fact, a CodeQL, Infer, SVF or Clang Static
Analyzer result, a sanitizer report, or the scanner observation itself. Model prose that states them without such
a citation is judgment, never evidence; consumers record a named gap instead of accepting it.

This module is the shared contract. It is pure and deterministic:

- ``detect`` reports which numeric-reasoning categories a text uses (a conservative vocabulary: a false positive
  costs a named gap or a lint finding, never an acceptance);
- ``cites_tool_fact`` reports whether a text cites a package fact label (``R1``, ``G2``, ``P1``, ``M1``, ``C1``) or
  names a tool artifact;
- ``NUMERIC_WEAKNESS_CWES`` (``numeric-weakness-cwes/1``) lists the weaknesses whose guard is a numeric fact.
"""
from __future__ import annotations

import re

RULE = "numeric-reasoning-guardrail/1"
NUMERIC_CWE_TABLE_VERSION = "numeric-weakness-cwes/1"

RANGE_BOUND = "range_bound"
ARITHMETIC_WRAP = "arithmetic_wrap"
LOOP_ITERATION = "loop_iteration"
CATEGORIES = (RANGE_BOUND, ARITHMETIC_WRAP, LOOP_ITERATION)

TRIAGE_GAP = "triage_unresolved:uncited_numeric_reasoning"
TRIAGE_GAP_REASON = ("the triage reason relies on numeric reasoning (ranges, bounds, wrap or loops) without citing "
                     "a supplied tool fact")
SCORING_MISSING_REASON = ("numeric weakness: support that the guard is missing or ineffective rests only on "
                          "code_evidence; ranges, bounds and overflow must come from a graph or tool fact "
                          f"({RULE})")

# Package-view labels of tool-produced facts: R ranges, G guards, P flows, M memory, C corroboration.
TOOL_FACT_LABEL_PREFIXES = ("R", "G", "P", "M", "C")
_TOOL_FACT_LABEL = re.compile(r"\b[" + "".join(TOOL_FACT_LABEL_PREFIXES) + r"]\d+\b")
TOOL_ARTIFACT_NAMES = re.compile(
    r"\b(?:range|guard|graph|tool|memory)[ _-]facts?\b"
    r"|\bcodeql\b|\binfer\b|\bsvf\b|\bclang static analyzer\b|\bscan-build\b"
    r"|\b(?:address|undefined[- ]behavior|memory|thread)?\s*sanitizers?\b|\b[amtu]san\b|\bubsan\b"
    r"|\bquery_code_graph\b|\btool_fact\b|\bscanner observation\b",
    re.IGNORECASE)

_INT_CONSTANT = r"(?:U?(?:INT|LONG|LLONG|SHRT|CHAR)|SIZE|SSIZE|U?INT\d+|PTRDIFF)_(?:MAX|MIN)"
_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    RANGE_BOUND: (
        re.compile(r"\b(?:upper|lower)[- ]bounds?\b", re.IGNORECASE),
        re.compile(r"\bbounds?[- ]check(?:s|ed|ing)?\b", re.IGNORECASE),
        re.compile(r"\b(?:in|within)\s+(?:range|bounds)\b|\bout\s+of\s+range\b", re.IGNORECASE),
        re.compile(r"\b(?:value|numeric|integer|index|length|size|offset)\s+ranges?\b", re.IGNORECASE),
        re.compile(r"-?\b\d+\s*\.\.\.?\s*-?\w+"),
        re.compile(r"\b(?:less|greater|smaller|larger|fewer)\s+than\s+(?:or\s+equal\s+to\s+)?"
                   r"(?:\d|" + _INT_CONSTANT + r"\b|the\s+(?:buffer|length|size|capacity|limit|maximum|minimum)\b)",
                   re.IGNORECASE),
        re.compile(r"\b" + _INT_CONSTANT + r"\b|\b(?:MAX|MIN)_VALUE\b"),
        re.compile(r"\bfits?\s+(?:in|into|within)\s+(?:an?\s+|the\s+)?"
                   r"(?:\d+[- ]bits?|bytes?|int(?:eger)?|short|u?int\d+(?:_t)?|size_t)\b", re.IGNORECASE),
        re.compile(r"\b(?:clamp|saturat)(?:e|es|ed|ing|s|ion)?\b", re.IGNORECASE),
    ),
    ARITHMETIC_WRAP: (
        re.compile(r"\b(?:integer|arithmetic|numeric|signed|unsigned|size|length|counter|multiplication|addition"
                   r"|subtraction)\s+(?:overflow|underflow|wrap)", re.IGNORECASE),
        re.compile(r"\b(?:can(?:not)?|can't|could(?:\s+not)?|may(?:\s+not)?|might|will|would|does(?:\s+not)?"
                   r"|doesn't|never|must\s+not)\s+(?:overflow|underflow|wrap)\b", re.IGNORECASE),
        re.compile(r"\bunderflow(?:s|ed|ing)?\b|\bwrap[- ]?around\b|\bwraps\b", re.IGNORECASE),
        re.compile(r"\b(?:integer|numeric|value|narrowing|sign)\s+(?:truncation|conversion)\b", re.IGNORECASE),
        re.compile(r"\btruncat\w*\s+to\s+(?:an?\s+)?(?:\d+[- ]bits?|u?int\d*(?:_t)?|short|char|byte)\b",
                   re.IGNORECASE),
        re.compile(r"\bsign[- ]extension\b|\boff[- ]by[- ]one\b|\bdivi(?:de|sion)[- ]by[- ]zero\b", re.IGNORECASE),
    ),
    LOOP_ITERATION: (
        re.compile(r"\bloop\s+(?:bounds?|counter|condition|invariants?|termination|exit|guard)\b", re.IGNORECASE),
        re.compile(r"\b(?:trip|iteration)\s+counts?\b|\b\d+\s+iterations?\b", re.IGNORECASE),
        re.compile(r"\bnon[- ]?terminat\w*|\b(?:always|never|eventually)\s+terminates?\b", re.IGNORECASE),
        re.compile(r"\b(?:infinite|unbounded|endless)\s+(?:loop|recursion|iteration)s?\b", re.IGNORECASE),
        re.compile(r"\b(?:inductive|loop)\s+invariants?\b|\bfix(?:ed)?[- ]?points?\b|\bwidening\b", re.IGNORECASE),
        re.compile(r"\b(?:iterates?|runs?|executes?|loops?)\s+(?:at\s+most|at\s+least|exactly|up\s+to)\s+\S+\s+times\b",
                   re.IGNORECASE),
    ),
}

_NUMERIC_CWE_NUMBERS = (
    # integer overflow, wrap, truncation and conversion
    190, 191, 192, 194, 195, 196, 197, 128, 681, 682,
    # off-by-one, index validation, buffer-size calculation, divide by zero
    193, 129, 131, 680, 369,
    # loops and iteration
    835, 834, 606,
    # bounds-based buffer reads and writes
    119, 120, 121, 122, 125, 787, 805, 806,
)
NUMERIC_WEAKNESS_CWES = frozenset(f"CWE-{number}" for number in _NUMERIC_CWE_NUMBERS)
_CWE = re.compile(r"^\s*(?:cwe)?[\s:_-]*0*(\d+)\s*$", re.IGNORECASE)


def detect(text: str | None) -> tuple[str, ...]:
    """The numeric-reasoning categories ``text`` uses, in ``CATEGORIES`` order; empty when it uses none."""
    if not text:
        return ()
    return tuple(category for category in CATEGORIES if any(pattern.search(text) for pattern in _PATTERNS[category]))


def cites_tool_fact(text: str | None) -> bool:
    """Whether ``text`` cites a tool-fact package label or names a tool artifact."""
    if not text:
        return False
    return bool(_TOOL_FACT_LABEL.search(text) or TOOL_ARTIFACT_NAMES.search(text))


def normalize_cwe(cwe: str | int | None) -> str | None:
    """``CWE-<n>`` for ``190``, ``"cwe 190"``, ``"CWE-0190"``; ``None`` for anything else."""
    if cwe is None or isinstance(cwe, bool):
        return None
    match = _CWE.match(str(cwe))
    return f"CWE-{int(match.group(1))}" if match else None


def is_numeric_weakness(cwe: str | int | None) -> bool:
    """Whether ``cwe`` is listed in ``numeric-weakness-cwes/1``."""
    return normalize_cwe(cwe) in NUMERIC_WEAKNESS_CWES
