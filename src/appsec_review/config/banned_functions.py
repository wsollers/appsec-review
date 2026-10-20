"""Banned and unsafe C/C++ function names, reported as review leads.

The ``[banned_functions]`` table lists function names, in three tiers, that are unsafe to call or
easy to misuse, plus a ``review`` tier of ordinary memory, string, comparison and format calls
(``malloc``, ``memcpy``, ``strcmp``, ``printf`` ...) that are not banned but are where size, bounds,
termination, null-check and format-string mistakes happen. ``review`` tier calls are reported at ``INFO``. A call to a listed name in C or C++ source is reported by Semgrep and Opengrep as a
review lead: ``high`` tier calls at ``ERROR`` (reported as high severity), ``warning`` tier calls at
``WARNING``. The default list is Microsoft's Security Development Lifecycle ``banned.h``; the tiers are
ours (unbounded or unsafe contracts are ``high``; bounded-but-error-prone, pedantic and path APIs are
``warning``). Add or move names here; nothing else needs to change but regenerating the rule file::

    python -m appsec_review.rulepacks.banned_functions --write

``rules/semgrep/banned-functions.yml`` is a generated view of this table. It is never hand-edited, a
test fails when it drifts, and the evidence job refuses to run it when it does not match the table.

A match is a lead, never a finding: a name can be called safely, and a call can be unsafe without
being on any list (``memcpy`` is not on Microsoft's list; ``rules/semgrep/review-signals.yml`` covers
an unbounded copy length separately).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import re
from typing import Any

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
TIERS = ("high", "warning", "review")
_TEXT_KEYS = ("source", "reference", "retrieved", "licence")
_KEYS = frozenset({*TIERS, *_TEXT_KEYS})


@dataclass(frozen=True, slots=True)
class BannedFunctions:
    high: tuple[str, ...] = ()
    warning: tuple[str, ...] = ()
    review: tuple[str, ...] = ()
    source: str = ""
    reference: str = ""
    retrieved: str = ""
    licence: str = ""

    def names(self, tier: str) -> tuple[str, ...]:
        return getattr(self, tier)

    def as_record(self) -> dict[str, Any]:
        return {"high": list(self.high), "warning": list(self.warning), "review": list(self.review), "source": self.source,
                "reference": self.reference, "retrieved": self.retrieved, "licence": self.licence}


def parse_banned_functions(value: object) -> BannedFunctions:
    """Validate the optional ``[banned_functions]`` table (absent means no rules)."""

    if value is None:
        return BannedFunctions()
    if not isinstance(value, Mapping):
        raise ValueError("[banned_functions] must be a table")
    unknown = set(value) - _KEYS
    if unknown:
        raise ValueError("banned_functions has unknown settings: " + ", ".join(sorted(unknown)))
    parsed: dict[str, Any] = {}
    for tier in TIERS:
        names = value.get(tier, [])
        if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
            raise ValueError(f"banned_functions.{tier} must be a list of function names")
        bad = [item for item in names if not NAME.fullmatch(item)]
        if bad:
            raise ValueError(f"banned_functions.{tier} holds names that are not C identifiers: "
                             + ", ".join(sorted(bad)[:5]))
        if len(set(names)) != len(names):
            repeated = sorted({item for item in names if names.count(item) > 1})
            raise ValueError(f"banned_functions.{tier} repeats names: " + ", ".join(repeated[:5]))
        parsed[tier] = tuple(names)
    seen: set[str] = set()
    overlapping: set[str] = set()
    for tier in TIERS:
        overlapping |= seen & set(parsed[tier])
        seen |= set(parsed[tier])
    overlap = sorted(overlapping)
    if overlap:
        raise ValueError("banned_functions lists names in both tiers: " + ", ".join(overlap[:5]))
    for key in _TEXT_KEYS:
        text = value.get(key, "")
        if not isinstance(text, str):
            raise ValueError(f"banned_functions.{key} must be a string")
        parsed[key] = text
    return BannedFunctions(**parsed)
