#!/usr/bin/env python3
"""Sentence-scoped, negation-aware guard against verification wording in model prose.

A cell whose output is unvalidated (an attack chain, a PoC, a proposed fix) must not say that it is
verified. :func:`pattern` builds the assertion regex for a subject set and a state set; :func:`errors`
returns one repair message per sentence that asserts it. A sentence that negates the state before the
match ("not verified", "never confirmed", "unproven") passes.
"""
from __future__ import annotations

import re

NEGATION_RE = re.compile(r"\b(?:not|no|never|cannot|can't|isn't|wasn't|un(?:verified|confirmed|proven))\b",
                         re.IGNORECASE)
_SENTENCE = re.compile(r"(?<=[.;!?])\s+")


def pattern(subjects: str, states: str) -> re.Pattern[str]:
    """``<subject> ... is|was|has been [fully] <state>`` or ``<state> [attack] <subject>``."""
    return re.compile(
        rf"\b(?:{subjects})\b[^.;!?]{{0,60}}?\b(?:is|was|are|were|has been|have been)\s+(?:fully\s+)?(?:{states})\b"
        rf"|\b(?:{states})\s+(?:attack\s+)?(?:{subjects})\b",
        re.IGNORECASE)


def errors(text: str | None, where: str, assertion: re.Pattern[str], advice: str) -> list[str]:
    """One message per sentence of ``text`` that asserts ``assertion`` without a negation before it."""
    found = []
    for sentence in _SENTENCE.split(text or ""):
        match = assertion.search(sentence)
        if match and not NEGATION_RE.search(sentence[:match.end()]):
            found.append(f"{where}: {match.group(0)!r} asserts verification; {advice}")
    return found
