"""The per-run graph quality scorecard (T-5016), ``appsec-review/graph-quality-scorecard/1``.

``job_code_graph_index`` publishes one scorecard per attempt
(``graph-quality-scorecard.json`` beside ``code-graph-summary.json``, with a one-screen text rendering
in ``graph-quality-scorecard.txt``). It answers, per CodeQL scope and per first-party function, what the
graph knows and who vouches for it:

* call edges by producer with their cross-check agreement (``agree``, ``disagree``, ``partial``,
  ``not_covered`` = CodeQL only, ``secondary_only`` = a secondary producer without a CodeQL counterpart);
* every dataflow path with its endpoints, classes, direct eligibility and SARIF correlation state
  (``bridged``, ``partial``, ``broken``, or ``uncorrelated`` when no code flow was correlated onto it);
* sink classification coverage, the cross-check producers attached to the scope, and the per-family
  first-party exclusion counts the normalizer recorded.

The scorecard is computed from the scope's published facts, symbols, relations and coverage rows only. It
is a measurement of the graph, never evidence about the target: a function with no agreeing producer is
unverified, not wrong, and an excluded vendored fact is a recorded count, not a gap. The document validates
against ``docs/schemas/graph-quality-scorecard.schema.json`` (closed) before it is written.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from appsec_review.application_paths import application_asset
from appsec_review.graph.contract import CrossCheckState, Family, GraphFact, Producer
from appsec_review.graph.correlate import CORRELATION_RULE, CorrelationState
from appsec_review.graph.normalize import CoverageRow
from appsec_review.retrieval.model import EntityKind, EntityRecord, RelationKind, RelationRecord
from appsec_review.review.dispositions import DISPOSITION_RULE, FIRST_PARTY, SourceDispositions

SCORECARD_SCHEMA = "appsec-review/graph-quality-scorecard/1"
SCHEMA_PATH = "docs/schemas/graph-quality-scorecard.schema.json"
UNCORRELATED = "uncorrelated"
# Bounds that keep the document independent of the target's size; the omitted counts are recorded.
MAX_FUNCTIONS = 5000
MAX_PATHS = 1000
MAX_UNCLASSIFIED_APIS = 50
_STATES = tuple(state.value for state in CrossCheckState) + ("secondary_only",)
_RENDER_FUNCTIONS = 12
_RENDER_PATHS = 10


class ScorecardError(ValueError):
    """The scorecard violates its closed schema."""


def _schema() -> Mapping[str, Any]:
    return json.loads(application_asset(SCHEMA_PATH).read_text(encoding="utf-8"))


def validate_scorecard(document: Mapping[str, Any]) -> None:
    """Check a scorecard against ``docs/schemas/graph-quality-scorecard.schema.json``."""
    errors = sorted(Draft202012Validator(_schema()).iter_errors(document), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        where = "/".join(str(part) for part in first.path) or "<root>"
        raise ScorecardError(f"graph quality scorecard violates its schema at {where}: {first.message}")


def _location(location: Any) -> dict[str, Any] | None:
    if location is None:
        return None
    get = location.get if isinstance(location, Mapping) else (lambda name, default=None: getattr(location, name, default))
    path = get("path")
    if not path:
        return None
    return {"path": str(path), "line": int(get("start_line") or 0)}


def _step_location(result: Mapping[str, Any], index: int) -> dict[str, Any] | None:
    steps = result.get("steps") or []
    if not steps or not isinstance(steps[index], Mapping):
        return None
    return _location(steps[index].get("location"))


def scope_scorecard(*, scope: Mapping[str, Any], facts: Sequence[GraphFact], symbols: Sequence[EntityRecord],
                    relations: Sequence[RelationRecord], coverage: Sequence[CoverageRow],
                    dispositions: SourceDispositions | None = None,
                    cross_check: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The scorecard section of one CodeQL scope, from its published facts (see the module docstring)."""
    classify = (dispositions or SourceDispositions()).classify
    calls = [fact for fact in facts if fact.family is Family.CALL_SITE]
    paths = sorted((fact for fact in facts if fact.family is Family.DATAFLOW_PATH), key=lambda item: item.identity.value)
    sinks = [fact for fact in facts if fact.family is Family.SINK_SITE]

    # -- functions: every first-party function symbol exactly once, with its call edges by verdict ----------
    functions: dict[str, dict[str, Any]] = {}
    for symbol in sorted(symbols, key=lambda item: item.identity.value):
        payload = symbol.payload or {}
        if symbol.identity.kind is not EntityKind.SYMBOL or payload.get("kind", "function") != "function":
            continue
        location = _location(symbol.location)
        disposition = classify(location["path"] if location else None)
        if disposition != FIRST_PARTY:
            continue
        functions[symbol.identity.value] = {
            "symbol": symbol.identity.value, "name": str(symbol.name)[:256],
            "path": location["path"] if location else None, "line": location["line"] if location else None,
            "calls": {state: 0 for state in _STATES} | {"total": 0}, "producers": {}}
    unattributed = Counter()
    for fact in calls:
        result = fact.payload.get("result") or {}
        caller = str((result.get("caller") or {}).get("symbol") or "")
        dispatch = str((result.get("callee") or {}).get("dispatch") or "")
        state = "secondary_only" if dispatch == "secondary_only" else str(fact.payload["cross_check"]["state"])
        entry = functions.get(caller)
        if entry is None:
            unattributed[state] += 1
            continue
        entry["calls"]["total"] += 1
        entry["calls"][state] += 1
        for producer in fact.payload["cross_check"].get("producers", ()):
            if producer.get("state") == CrossCheckState.AGREE.value:
                entry["producers"][str(producer["name"])] = entry["producers"].get(str(producer["name"]), 0) + 1
    ordered_functions = sorted(functions.values(), key=lambda item: (item["path"] or "", item["line"] or 0, item["name"]))
    for entry in ordered_functions:
        entry["producers"] = dict(sorted(entry["producers"].items()))

    # -- paths with their correlation state ------------------------------------------------------------------
    correlation_by_path: dict[str, str] = {}
    for relation in relations:
        payload = relation.payload or {}
        if relation.kind is RelationKind.DERIVED_FROM and payload.get("rule") == CORRELATION_RULE \
                and payload.get("state") in {state.value for state in CorrelationState}:
            current = correlation_by_path.get(relation.source_id)
            rank = {CorrelationState.BRIDGED.value: 0, CorrelationState.PARTIAL.value: 1, CorrelationState.BROKEN.value: 2}
            if current is None or rank[str(payload["state"])] < rank[current]:
                correlation_by_path[relation.source_id] = str(payload["state"])
    path_rows = []
    correlation = Counter()
    for fact in paths:
        result = fact.payload.get("result") or {}
        source, sink = result.get("source") or {}, result.get("sink") or {}
        state = correlation_by_path.get(fact.identity.value, UNCORRELATED)
        correlation[state] += 1
        producers = [str(fact.payload["producer"]["name"])] + sorted(
            {str(item["name"]) for item in fact.payload["cross_check"].get("producers", ())})
        source_location = _step_location(result, 0)
        path_rows.append({
            "identity": fact.identity.value, "name": str(fact.name)[:256],
            "source": {"display": str((result.get("steps") or [{}])[0].get("display") or "")[:120]
                       if result.get("steps") else "", "source_class": str(source.get("source_class") or "unclassified"),
                       "path": source_location["path"] if source_location else None,
                       "line": source_location["line"] if source_location else None},
            "sink": {"display": str(fact.name).rsplit("->", 1)[-1].strip()[:120],
                     "sink_class": str(sink.get("sink_class") or "unclassified"),
                     "path": fact.location.path if fact.location is not None else None,
                     "line": int(fact.location.start_line) if fact.location is not None else None},
            "hop_count": int(result.get("hop_count") or 0), "producers": producers,
            "direct_eligible": bool(fact.payload["admissibility"]["direct_eligible"]),
            "ineligibility_reasons": [str(item) for item in fact.payload["admissibility"]["ineligibility_reasons"]],
            "correlation": state})

    # -- sinks, cross-check states, exclusions ---------------------------------------------------------------
    by_class = Counter(str((fact.payload.get("result") or {}).get("sink_class") or "unclassified") for fact in sinks)
    unclassified_apis = Counter(
        str(((fact.payload.get("result") or {}).get("api") or {}).get("display") or fact.name)
        for fact in sinks if (fact.payload.get("result") or {}).get("sink_class") == "unclassified")
    states = Counter(str(fact.payload["cross_check"]["state"]) for fact in calls)
    secondary_only = sum(1 for fact in calls
                         if ((fact.payload.get("result") or {}).get("callee") or {}).get("dispatch") == "secondary_only")
    exclusions: dict[str, dict[str, int]] = {}
    coverage_rows: dict[str, str] = {}
    for row in coverage:
        coverage_rows[row.family.value] = row.status.value
        for key, value in row.counts.items():
            if key.startswith("excluded_") and value:
                exclusions.setdefault(row.family.value, {})[key.removeprefix("excluded_")] = int(value)
    attached = sorted((cross_check or {}).get("producers", {}).keys()) if cross_check else []
    return {
        "scope_id": str(scope["scope_id"]), "language": str(scope.get("language") or ""),
        "build_unit_id": str(scope.get("build_unit_id") or "") or None,
        "export_status": str(scope.get("export_status") or ""),
        "functions": ordered_functions[:MAX_FUNCTIONS], "functions_omitted": max(0, len(ordered_functions) - MAX_FUNCTIONS),
        "call_sites": {"total": len(calls), **{state: int(states.get(state, 0)) for state in
                                                (s.value for s in CrossCheckState)},
                       "secondary_only": secondary_only, "unattributed": dict(sorted(unattributed.items()))},
        "paths": path_rows[:MAX_PATHS], "paths_omitted": max(0, len(path_rows) - MAX_PATHS),
        "correlation": {"bridged": correlation.get("bridged", 0), "partial": correlation.get("partial", 0),
                        "broken": correlation.get("broken", 0), "uncorrelated": correlation.get(UNCORRELATED, 0)},
        "sinks": {"total": len(sinks), "classified": len(sinks) - by_class.get("unclassified", 0),
                  "unclassified": by_class.get("unclassified", 0), "by_class": dict(sorted(by_class.items())),
                  "unclassified_apis": dict(sorted(unclassified_apis.most_common(MAX_UNCLASSIFIED_APIS)))},
        "cross_check_producers": attached, "exclusions": {key: dict(sorted(value.items()))
                                                           for key, value in sorted(exclusions.items())},
        "coverage": dict(sorted(coverage_rows.items())),
    }


def assemble_scorecard(*, run_id: str, target_snapshot: str, scopes: Sequence[Mapping[str, Any]],
                       catalog: Mapping[str, Any], dispositions: SourceDispositions | None = None) -> dict[str, Any]:
    """The run scorecard over every scope section; validated against the closed schema."""
    sections = sorted((dict(item) for item in scopes), key=lambda item: item["scope_id"])
    totals = {
        "scopes": len(sections), "first_party_functions": sum(len(item["functions"]) for item in sections),
        "call_sites": sum(item["call_sites"]["total"] for item in sections),
        "call_sites_agreed": sum(item["call_sites"]["agree"] for item in sections),
        "call_sites_codeql_only": sum(item["call_sites"]["not_covered"] for item in sections),
        "paths": sum(len(item["paths"]) + item["paths_omitted"] for item in sections),
        "paths_eligible": sum(1 for item in sections for path in item["paths"] if path["direct_eligible"]),
        "sinks_unclassified": sum(item["sinks"]["unclassified"] for item in sections),
        "excluded_facts": sum(count for item in sections for family in item["exclusions"].values()
                              for count in family.values()),
    }
    document = {
        "schema": SCORECARD_SCHEMA, "run_id": str(run_id), "target_snapshot": str(target_snapshot),
        "catalog": {"version": str(catalog.get("version") or ""), "revision": int(catalog.get("revision") or 0),
                    "release_id": str(catalog.get("release_id") or "undeclared")},
        "dispositions": {"rule": DISPOSITION_RULE, "configured": bool(dispositions is not None and dispositions.configured)},
        "authority": "a measurement of the published code graph; never evidence about the target",
        "totals": totals, "scopes": sections,
    }
    validate_scorecard(document)
    return document


def render_scorecard(document: Mapping[str, Any]) -> str:
    """A one-screen text rendering for the report's coverage section (bounded lines and widths)."""
    totals = document["totals"]
    lines = [f"Code-graph quality scorecard ({document['schema']}) run {document['run_id']}",
             f"catalog {document['catalog']['version']} rev {document['catalog']['revision']}; first-party "
             f"dispositions {'configured' if document['dispositions']['configured'] else 'not configured'}",
             f"scopes {totals['scopes']}; first-party functions {totals['first_party_functions']}; call sites "
             f"{totals['call_sites']} (agreed {totals['call_sites_agreed']}, CodeQL-only {totals['call_sites_codeql_only']}); "
             f"paths {totals['paths']} (eligible {totals['paths_eligible']}); unclassified sinks "
             f"{totals['sinks_unclassified']}; excluded non-first-party facts {totals['excluded_facts']}"]
    for scope in document["scopes"]:
        calls = scope["call_sites"]
        lines.append(f"- scope {scope['scope_id']} [{scope['language']}] export {scope['export_status']}; producers "
                     f"{', '.join(scope['cross_check_producers']) or 'none attached'}")
        lines.append(f"  call sites {calls['total']}: agree {calls['agree']}, disagree {calls['disagree']}, partial "
                     f"{calls['partial']}, codeql-only {calls['not_covered']}, secondary-only {calls['secondary_only']}")
        correlation = scope["correlation"]
        lines.append(f"  paths {len(scope['paths']) + scope['paths_omitted']}: bridged {correlation['bridged']}, partial "
                     f"{correlation['partial']}, broken {correlation['broken']}, uncorrelated {correlation['uncorrelated']}; "
                     f"sinks {scope['sinks']['total']} classified {scope['sinks']['classified']} unclassified "
                     f"{scope['sinks']['unclassified']}"
                     + (f" ({', '.join(f'{api} {n}' for api, n in scope['sinks']['unclassified_apis'].items())})"
                        if scope["sinks"]["unclassified_apis"] else ""))
        if scope["exclusions"]:
            lines.append("  excluded: " + "; ".join(
                f"{family} " + ", ".join(f"{kind} {count}" for kind, count in counts.items())
                for family, counts in scope["exclusions"].items()))
        functions = sorted(scope["functions"], key=lambda item: (-item["calls"]["total"], item["path"] or "", item["name"]))
        for entry in functions[:_RENDER_FUNCTIONS]:
            calls = entry["calls"]
            vouch = ", ".join(f"{name} {count}" for name, count in entry["producers"].items()) or "no agreeing producer"
            lines.append(f"  fn {entry['name'][:48]} {entry['path']}:{entry['line']} calls {calls['total']} "
                         f"(agree {calls['agree']}, codeql-only {calls['not_covered']}, secondary-only "
                         f"{calls['secondary_only']}); {vouch}")
        if len(functions) > _RENDER_FUNCTIONS:
            lines.append(f"  ... {len(functions) - _RENDER_FUNCTIONS} more first-party functions in the JSON scorecard")
        for path in scope["paths"][:_RENDER_PATHS]:
            lines.append(f"  path {path['source']['source_class']} -> {path['sink']['sink_class']} "
                         f"{path['sink']['path']}:{path['sink']['line']} hops {path['hop_count']} "
                         f"{'eligible' if path['direct_eligible'] else 'ineligible: ' + ','.join(path['ineligibility_reasons'])} "
                         f"{path['correlation']} by {','.join(path['producers'])}")
        if len(scope["paths"]) > _RENDER_PATHS:
            lines.append(f"  ... {len(scope['paths']) - _RENDER_PATHS} more paths in the JSON scorecard")
    return "\n".join(line[:200] for line in lines) + "\n"


__all__ = ["MAX_FUNCTIONS", "MAX_PATHS", "SCHEMA_PATH", "SCORECARD_SCHEMA", "UNCORRELATED", "ScorecardError",
           "assemble_scorecard", "render_scorecard", "scope_scorecard", "validate_scorecard"]
