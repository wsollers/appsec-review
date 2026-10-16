"""Clang-Tidy / Clang Static Analyzer diagnostics as ``sink_site`` evidence (rule ``graph-analyzer-sinks/1``).

docs/architecture/seeded-neighborhoods.md section 9 and docs/architecture/code-graph-precomputation.md 4.1.
Pure functions over already-built :class:`GraphFact` values and accepted ``clang-static`` observation rows
read through ``indexing.store.ShardSet``; nothing here runs an analyzer or reads a target tree.

A diagnostic names a *check*, not a sink class. Only checks in :data:`CHECK_SINK_CLASS` (an explicit,
reviewed table; a check is never classified from its message text) map to a :class:`SinkClass`. For each
mapped diagnostic at a located point:

* a CodeQL ``sink_site`` of the same file whose exact span contains the diagnostic line and has the same
  sink class is *corroborated*: the analyzer is recorded as an agreeing ``clang-static`` cross-check
  producer on that fact. An analyzer can only confirm a CodeQL sink, never contradict it, and a fact it
  does not mention stays ``not_covered`` (absence is never evidence);
* otherwise the diagnostic becomes an *analyzer-only* ``sink_site`` fact. It is inexact (the location is
  the diagnostic point, not the sink expression), its coverage is partial, its cross-check state is
  ``partial`` and it is therefore never direct-eligible. ``argument_index`` is ``-1``: an analyzer names no argument.

A diagnostic whose check is not in the table stays only in the ``diagnostics`` rows of the producer
neighborhood; the count per check is a named gap, never silently dropped and never guessed.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from appsec_review.graph.contract import (
    AUTHORITY, CROSS_CHECK_RULE, GRAPH_FACT_SCHEMA, Coverage, CrossCheckState, Family, GraphFact, Producer, SinkClass,
    admissibility, fact_identity,
)
from appsec_review.retrieval.model import SourceLocation, canonical_json

ANALYZER_SINK_RULE = "graph-analyzer-sinks/1"
METHOD_DIAGNOSTIC_LINE = "analyzer-diagnostic-in-sink-lines"
METHOD_DIAGNOSTIC_POINT = "analyzer-diagnostic-point"
SCANNERS = frozenset({"clang-tidy", "clang-static-analyzer"})
MAX_ANALYZER_SINKS = 500
NO_ARGUMENT = -1

# Clang Static Analyzer checker names. clang-tidy reports an analyzer checker as ``clang-analyzer-<checker>``;
# the prefix is removed before the lookup. Alpha checkers are deliberately absent.
CHECK_SINK_CLASS: Mapping[str, SinkClass] = {
    # Unbounded or unchecked buffer writes.
    "security.insecureAPI.strcpy": SinkClass.MEMORY_WRITE,
    "security.insecureAPI.gets": SinkClass.MEMORY_WRITE,
    "security.insecureAPI.DeprecatedOrUnsafeBufferHandling": SinkClass.MEMORY_WRITE,
    "unix.cstring.BufferOverlap": SinkClass.MEMORY_WRITE,
    "unix.cstring.OutOfBounds": SinkClass.MEMORY_WRITE,
    "unix.cstring.UninitializedRead": SinkClass.MEMORY_READ,
    "core.uninitialized.ArraySubscript": SinkClass.MEMORY_READ,
    "bugprone-not-null-terminated-result": SinkClass.MEMORY_WRITE,
    # Allocation sizes.
    "unix.MallocSizeof": SinkClass.ALLOCATION_SIZE,
    "optin.taint.TaintedAlloc": SinkClass.ALLOCATION_SIZE,
    # Commands and paths.
    "cert-env33-c": SinkClass.COMMAND_EXECUTION,
    "security.insecureAPI.mktemp": SinkClass.PATH_ACCESS,
    "security.insecureAPI.mkstemp": SinkClass.PATH_ACCESS,
    # Integer conversion.
    "bugprone-implicit-widening-of-multiplication-result": SinkClass.INTEGER_CONVERSION,
    "bugprone-misplaced-widening-cast": SinkClass.INTEGER_CONVERSION,
    "bugprone-narrowing-conversions": SinkClass.INTEGER_CONVERSION,
    "cppcoreguidelines-narrowing-conversions": SinkClass.INTEGER_CONVERSION,
    "bugprone-signed-char-misuse": SinkClass.INTEGER_CONVERSION,
    "cert-err34-c": SinkClass.INTEGER_CONVERSION,
    # Randomness and key material.
    "security.insecureAPI.rand": SinkClass.CRYPTO_MISUSE,
    "security.insecureAPI.random": SinkClass.CRYPTO_MISUSE,
}
CLANG_ANALYZER_PREFIX = "clang-analyzer-"


def sink_class_of(check: str) -> SinkClass | None:
    """The sink class a check maps to, or ``None`` when the table does not classify it."""
    name = check.removeprefix(CLANG_ANALYZER_PREFIX)
    return CHECK_SINK_CLASS.get(name) or CHECK_SINK_CLASS.get(check)


@dataclass(frozen=True, slots=True)
class AnalyzerSinks:
    facts: tuple[GraphFact, ...]
    summary: Mapping[str, Any] = field(default_factory=dict)


def _unique(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(value) for value in {canonical_json(item): item for item in items}.values()]


def _point(row: Mapping[str, Any]) -> dict[str, Any] | None:
    location = row.get("location")
    if not isinstance(location, Mapping) or location.get("path") is None:
        return None
    try:
        return {"path": str(location["path"]), "sha256": str(location["file_sha256"]),
                "offset": int(location["start_byte"]), "line": int(location["start_line"]),
                "column": int(location["start_column"])}
    except (KeyError, TypeError, ValueError):
        return None


def apply_analyzer_sinks(facts: Sequence[GraphFact], rows: Sequence[Mapping[str, Any]],
                         upstream: Sequence[Mapping[str, str]], *, target_snapshot: str, scope: Mapping[str, Any],
                         tool_version: str = "unknown") -> AnalyzerSinks:
    """Corroborate CodeQL sinks with, and add analyzer-only sinks from, Clang diagnostics.

    ``rows`` are ``tool_observation`` rows of accepted ``clang-static`` shards (``ShardSet.entities`` shape);
    ``upstream`` is the ``{index, shard_id, sha256}`` of every shard they came from. Returns every input fact
    (corroborated ones with a recomputed ``cross_check``) plus the analyzer-only facts, sorted by identity.
    """
    if not str(scope.get("scope_id") or ""):
        raise ValueError("analyzer sink scope requires a scope_id")
    diagnostics = sorted((row for row in rows if (row.get("payload") or {}).get("scanner") in SCANNERS),
                         key=lambda row: str(row["identity"]))
    sinks: dict[str, list[GraphFact]] = {}
    for fact in facts:
        location = fact.location
        if (fact.family is Family.SINK_SITE and fact.payload.get("exact") is True and location is not None
                and not location.ambiguous):
            sinks.setdefault(location.path, []).append(fact)
    corroborated: dict[str, list[dict[str, Any]]] = {}
    pending: dict[tuple[str, int, str], dict[str, Any]] = {}
    unmapped: dict[str, int] = {}
    unlocated = 0
    for row in diagnostics:
        payload = row.get("payload") or {}
        check = str(payload.get("native_rule_id") or row.get("name") or "")
        klass = sink_class_of(check)
        if klass is None:
            unmapped[check or "(unnamed)"] = unmapped.get(check or "(unnamed)", 0) + 1
            continue
        point = _point(row)
        if point is None:
            unlocated += 1
            continue
        entry = {"check": check, "scanner": str(payload.get("scanner")), "line": point["line"], "column": point["column"],
                 "evidence": str(row["identity"])}
        matched = [fact for fact in sinks.get(point["path"], ())
                   if fact.payload["result"].get("sink_class") == klass.value and fact.location is not None
                   and fact.location.start_line <= point["line"] <= fact.location.end_line]
        if matched:
            for fact in matched:
                corroborated.setdefault(fact.identity.value, []).append(entry)
            continue
        key = (point["path"], point["offset"], klass.value)
        group = pending.setdefault(key, {"point": point, "class": klass, "diagnostics": []})
        group["diagnostics"].append(entry)

    gaps: list[str] = []
    updated: list[GraphFact] = []
    for fact in facts:
        entries = corroborated.get(fact.identity.value)
        if not entries:
            updated.append(fact)
            continue
        payload = dict(fact.payload)
        cross = dict(payload["cross_check"])
        producers = [item for item in cross.get("producers", ()) if item.get("name") != Producer.CLANG_STATIC.value]
        first = min(entries, key=lambda item: (item["check"], item["line"], item["evidence"]))
        producers.append({"name": Producer.CLANG_STATIC.value, "state": CrossCheckState.AGREE.value,
                          "method": METHOD_DIAGNOSTIC_LINE,
                          "detail": f"{first['scanner']} {first['check']} at line {first['line']}"
                                    + (f" (+{len(entries) - 1} more)" if len(entries) > 1 else "")})
        producers.sort(key=lambda item: item["name"])
        states = [CrossCheckState(item["state"]) for item in producers]
        # Analyzer corroboration never worsens another producer's verdict and never hides a disagreement.
        state = (CrossCheckState.DISAGREE if CrossCheckState.DISAGREE in states else
                 CrossCheckState.PARTIAL if CrossCheckState.PARTIAL in states else CrossCheckState.AGREE)
        payload["cross_check"] = {"rule": CROSS_CHECK_RULE, "state": state.value, "producers": producers}
        merged = _unique([*payload.get("upstream", ()), *upstream])
        payload["upstream"] = sorted(merged, key=canonical_json)
        payload["admissibility"] = admissibility(payload)
        updated.append(replace(fact, payload=payload))

    added: list[GraphFact] = []
    for key in sorted(pending)[:MAX_ANALYZER_SINKS]:
        group = pending[key]
        point, klass = group["point"], group["class"]
        entries = sorted(_unique(group["diagnostics"]), key=lambda item: (item["check"], item["evidence"]))
        identity = fact_identity(Family.SINK_SITE, target_snapshot, {
            "scope_id": scope["scope_id"], "path": point["path"], "start_byte": point["offset"],
            "end_byte": point["offset"], "sink_class": klass.value, "argument_index": NO_ARGUMENT})
        location = SourceLocation(
            target_snapshot, point["path"], point["sha256"], point["offset"], point["offset"], point["line"],
            point["line"], point["column"], point["column"],
            {"producer": Producer.CLANG_STATIC.value, "line": point["line"], "column": point["column"]},
            METHOD_DIAGNOSTIC_POINT, 0.5, True)
        checks = sorted({item["check"] for item in entries})
        result = {
            "sink_class": klass.value, "cwe_family": None,
            "api": {"display": checks[0], "declared_in": None}, "argument_index": None, "display": checks[0],
            "operand": {"location": None, "exact": False},
            "enclosing_function": {"symbol": None, "display": None},
            "dominating_sanitizer_count": None, "catalog_rule": ANALYZER_SINK_RULE, "model": "analyzer-diagnostic",
            "models": ["analyzer-diagnostic"], "checks": checks, "diagnostics": entries[:10],
        }
        payload = {
            "schema": GRAPH_FACT_SCHEMA, "family": Family.SINK_SITE.value,
            "producer": {"name": Producer.CLANG_STATIC.value, "tool_version": tool_version,
                         "export_pack_sha256": None, "catalog_version": None, "rule_version": ANALYZER_SINK_RULE},
            "scope": {name: scope.get(name) for name in ("scope_id", "language", "build_unit_id", "component_id")},
            "exact": False, "coverage_status": Coverage.PARTIAL.value,
            "gaps": ["analyzer_only: no CodeQL sink_site of this class covers this diagnostic line; this is missing "
                     "CodeQL coverage, not a CodeQL negative",
                     "location is the diagnostic point, not the sink expression; the enclosing function and the "
                     "argument are not identified"],
            "cross_check": {"rule": CROSS_CHECK_RULE, "state": CrossCheckState.PARTIAL.value, "producers": [
                {"name": Producer.CLANG_STATIC.value, "state": CrossCheckState.AGREE.value,
                 "method": METHOD_DIAGNOSTIC_POINT}]},
            "result": result, "upstream": sorted(_unique(upstream), key=canonical_json), "authority": AUTHORITY,
        }
        payload["admissibility"] = admissibility(payload)
        added.append(GraphFact(identity, f"{checks[0]} [{klass.value}]"[:256], payload, location))
    if len(pending) > MAX_ANALYZER_SINKS:
        gaps.append(f"analyzer_sinks_limit: {MAX_ANALYZER_SINKS} of {len(pending)} analyzer-only sink_site facts are published")
    if unmapped:
        gaps.append(f"analyzer_checks_unmapped: {sum(unmapped.values())} diagnostic(s) of {len(unmapped)} check(s) name no "
                    f"sink class in {ANALYZER_SINK_RULE}; they remain only in the diagnostics rows")
    if unlocated:
        gaps.append(f"analyzer_diagnostics_unlocated: {unlocated} mapped diagnostic(s) carry no source location")
    all_facts = sorted([*updated, *added], key=lambda item: item.identity.value)
    if len({item.identity.value for item in all_facts}) != len(all_facts):
        raise ValueError("analyzer sinks produced duplicate fact identities")
    summary = {"rule": ANALYZER_SINK_RULE, "diagnostics": len(diagnostics),
               "corroborated": len(corroborated), "analyzer_only": len(added),
               "unmapped_checks": dict(sorted(unmapped.items())), "gaps": gaps}
    return AnalyzerSinks(tuple(all_facts), summary)
