"""Revision-independent finding identity (finding-metrics.md section 4.1, T-060).

A finding is one root cause. Its fingerprint hashes the weakness family, the enclosing functions,
the source and sink symbols and the normalized code context of the affected constructs. It never
includes a commit, a line number, a severity, a confidence or prose, so the same defect at two
revisions has the same identity.

Two keys are produced:

* ``exact`` adds the normalized paths: the same finding in the same place.
* ``relocated`` omits them: the same finding after a move or rename. It is only distinct from
  ``exact`` when the finding carries a function or code context; a finding known only by its path
  cannot be recognised after a move.

``basis`` names what the identity rests on, strongest first: ``function_and_code``, ``code``,
``function``, ``path_only``. Anything weaker than a ``relocated`` match is not a match.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import re
from typing import Any

from .contracts import FINGERPRINT_VERSION, MatchTier, digest, weakness_family

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"(?m)(?://|#(?!\s*(?:include|define|if|ifdef|ifndef|else|elif|endif|pragma)\b)).*$")
_SPACE = re.compile(r"\s+")


def normalize_code(code: str | None) -> str | None:
    """Code with comments removed and whitespace collapsed; ``None`` when nothing remains.

    The normalization is deliberately lexical and language-agnostic: C-style block comments, ``//``
    and ``#`` line comments (preprocessor directives are kept) and all runs of whitespace. A change
    that survives it is treated as a change to the construct.
    """
    if code is None:
        return None
    text = _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub(" ", code))
    text = _SPACE.sub(" ", text).strip()
    return text or None


def fingerprint(finding: Mapping[str, Any]) -> dict[str, str]:
    """``{"version", "exact", "relocated", "basis"}`` for a normalized finding record."""
    locations = finding["locations"]
    functions = sorted({item["function"] for item in locations if item.get("function")})
    code = sorted({text for text in (normalize_code(item.get("code")) for item in locations) if text})
    paths = sorted({item["path"] for item in locations})
    basis = ("function_and_code" if functions and code else "code" if code
             else "function" if functions else "path_only")
    stable = {"version": FINGERPRINT_VERSION, "family": weakness_family(finding.get("weakness_cwe")),
              "predicate": finding.get("security_predicate"), "functions": functions, "code": code,
              "source_symbol": finding.get("source_symbol"), "sink_symbol": finding.get("sink_symbol")}
    exact = digest({**stable, "paths": paths})
    relocated = exact if basis == "path_only" else digest(stable)
    return {"version": FINGERPRINT_VERSION, "exact": exact, "relocated": relocated, "basis": basis}


def match_tier(prior: Mapping[str, Any], current: Mapping[str, Any]) -> MatchTier | None:
    """The tier at which two fingerprints name the same finding, or ``None``."""
    if prior.get("version") != FINGERPRINT_VERSION or current.get("version") != FINGERPRINT_VERSION:
        raise ValueError("fingerprints of different versions are not comparable")
    if prior["exact"] == current["exact"]:
        return MatchTier.EXACT
    if prior["relocated"] == current["relocated"] and prior.get("basis") != "path_only":
        return MatchTier.RELOCATED
    return None


def match_findings(prior: Iterable[Mapping[str, Any]], current: Iterable[Mapping[str, Any]]
                   ) -> dict[str, tuple[str, MatchTier]]:
    """``prior finding_id -> (current finding_id, tier)``; each current finding matches at most once.

    Exact matches are assigned first, then relocated ones, both in ``finding_id`` order, so the
    result is deterministic and a moved finding cannot steal an unmoved finding's match.
    """
    prior = sorted(prior, key=lambda item: item["finding_id"])
    current = sorted(current, key=lambda item: item["finding_id"])
    matches: dict[str, tuple[str, MatchTier]] = {}
    taken: set[str] = set()
    for tier in (MatchTier.EXACT, MatchTier.RELOCATED):
        for old in prior:
            if old["finding_id"] in matches:
                continue
            for new in current:
                if new["finding_id"] not in taken and match_tier(old["fingerprint"], new["fingerprint"]) is tier:
                    matches[old["finding_id"]] = (new["finding_id"], tier)
                    taken.add(new["finding_id"])
                    break
    return matches


__all__ = ["fingerprint", "match_findings", "match_tier", "normalize_code"]
