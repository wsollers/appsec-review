"""Review coverage by security dimension.

The closed ``security_predicate`` vocabulary (:class:`appsec_review.review.models.SecurityPredicate`) is
grouped into readable axes, and the accepted packages are counted per axis. The executive PDF (radar
chart and table) and ``final-report.md`` (table) both take their numbers from :func:`dimension_counts`,
so the two renderings agree. Counting is a pure function of ``final-report.json`` and the bound dossier
documents: a package's predicate is the one its gate-bound dossier states or, when no dossier is bound
for it, the leading token of its pipeline title ``<predicate> (<CWE>)``; a package that names no
vocabulary member is counted as unclassified, never guessed. A short axis means little was found or
examined there, never that the dimension is clean; an axis with no claims is uncovered.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .text import clean


@dataclass(frozen=True, slots=True)
class Dimension:
    key: str                           # short code at the rim of the radar chart and in the tables
    label: str
    predicates: tuple[str, ...]        # members of the closed vocabulary that count here
    counts: str                        # what counts here, for the key


DIMENSIONS: tuple[Dimension, ...] = (
    Dimension("M", "Memory safety", ("memory_corruption", "out_of_bounds_read", "use_after_free"),
              "buffer overflows and other memory corruption, out-of-bounds reads, use after free"),
    Dimension("N", "Numeric handling", ("integer_error",),
              "integer overflow and wraparound, sign and conversion errors, division errors"),
    Dimension("C", "Control and injection", ("injection", "command_injection", "code_injection", "sql_injection",
                                             "path_traversal", "ssrf"),
              "command, code, SQL and other injection, path traversal, server-side request forgery"),
    Dimension("P", "Parsing and data", ("deserialization",), "unsafe deserialization of untrusted data"),
    Dimension("A", "Access control", ("authn_bypass", "authz_bypass"), "authentication and authorization bypass"),
    Dimension("S", "Secrets and crypto", ("crypto_weakness", "info_disclosure"),
              "weak or misused cryptography, disclosure of data meant to stay private"),
    Dimension("R", "Concurrency", ("race_condition",), "race conditions and unsafe interleavings"),
    Dimension("X", "Resource exhaustion", ("resource_exhaustion",),
              "uncontrolled memory, CPU, disk or connection use"),
    Dimension("K", "Configuration and supply chain", ("insecure_configuration", "supply_chain_compromise"),
              "insecure settings, compromised dependencies or build inputs"),
)
DIMENSION_OF_PREDICATE: dict[str, str] = {predicate: dimension.key
                                          for dimension in DIMENSIONS for predicate in dimension.predicates}


@dataclass(frozen=True, slots=True)
class DimensionCounts:
    key: str
    label: str
    findings: int                      # confirmed finding packages
    claims: int                        # claims examined: confirmed, verification backlog and withheld packages


def predicate_of(item: Mapping[str, Any], dossier: Mapping[str, Any] | None = None) -> str | None:
    """The package's predicate: the bound dossier's, else the leading token of its ``<predicate> (<CWE>)`` title.

    ``None`` when neither names a member of the closed vocabulary (``other`` included).
    """
    candidates = [clean((dossier or {}).get("security_predicate")),
                  clean(item.get("title")).split(" (", 1)[0].strip()]
    return next((candidate for candidate in candidates if candidate in DIMENSION_OF_PREDICATE), None)


def dimension_counts(report: Mapping[str, Any],
                     dossiers_by_claim: Mapping[str, Mapping[str, Any]] | None = None,
                     ) -> tuple[tuple[DimensionCounts, ...], int]:
    """Per-axis counts over the report's three package buckets, and the number of unclassified packages."""
    dossiers_by_claim = dossiers_by_claim or {}
    findings = {dimension.key: 0 for dimension in DIMENSIONS}
    claims = {dimension.key: 0 for dimension in DIMENSIONS}
    unclassified = 0
    for bucket in ("findings", "verification_backlog", "withheld"):
        for item in report.get(bucket) or ():
            predicate = predicate_of(item, dossiers_by_claim.get(item.get("claim_id")))
            if predicate is None:
                unclassified += 1
                continue
            key = DIMENSION_OF_PREDICATE[predicate]
            claims[key] += 1
            if bucket == "findings":
                findings[key] += 1
    return (tuple(DimensionCounts(dimension.key, dimension.label, findings[dimension.key], claims[dimension.key])
                  for dimension in DIMENSIONS), unclassified)


__all__ = ["DIMENSIONS", "DIMENSION_OF_PREDICATE", "Dimension", "DimensionCounts", "dimension_counts", "predicate_of"]
