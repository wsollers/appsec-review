"""Versioned lead-family normalization over accepted shards (lane A intake).

Every accepted lead family has one versioned rule that maps an accepted record to a normalized
*reported* severity. Reported severity orders review work; it is never an adjudicated severity, and
an unmapped label stays ``unknown`` rather than low. A family whose accepted producer shard is
absent yields a coverage gap, never an empty (clean) lead list.

Families: source SAST and CodeQL reuse ``retrieval.observations`` normalization and the accepted
``scanner_correlation`` lead facts of ``indexing/sast.py``; artifact scanners; dependency
advisories (the advisory's own CVSS or severity); CI rules; post-build hardening checks; OWASP
control failures.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
import math
import re
from typing import Any

from appsec_review.indexing.products_base import AcceptedShards
from appsec_review.indexing.sast import (
    RULE_VERSION as CORRELATION_RULE, LeadAuditError, build_scanner_correlation,
)
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.retrieval.observations import (
    SEVERITY_ORDER, SEVERITY_RULE, classify, normalize_reported_severity, rule_of, scanner_of,
)
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import AcceptedScope, ScopeGap, sorted_gaps


FAMILIES = ("source_sast", "codeql", "artifact_scanner", "dependency_advisory", "ci_rule",
            "post_build_hardening", "owasp_control")
FAMILY_RULES = {family: f"appsec-review/lead-family/{family}/1" for family in FAMILIES}
# Producer whose accepted shard must exist for the family to have coverage.
FAMILY_PRODUCERS = {
    "source_sast": ("source_sast",), "codeql": ("codeql",), "artifact_scanner": ("artifact_scanner",),
    "dependency_advisory": ("dependency_scanner", "artifact_scanner"), "ci_rule": ("ci_configuration",),
    "post_build_hardening": ("post_build_hardening",), "owasp_control": ("control_evidence",),
}
# Producers whose partial or stale coverage qualifies a family without deciding its availability.
FAMILY_CONTEXT_PRODUCERS = {
    "source_sast": ("scanner_correlation",), "codeql": ("scanner_correlation",),
    "dependency_advisory": ("dependency_advisories", "reference_intelligence"),
}
ARTIFACT_KINDS = frozenset({
    EntityKind.EXECUTABLE.value, EntityKind.LIBRARY.value, EntityKind.OBJECT_FILE.value,
    EntityKind.BUILD_ARTIFACT.value, EntityKind.PACKAGE.value, EntityKind.ARCHIVE_MEMBER.value,
    EntityKind.BYTECODE_MODULE.value, EntityKind.MANAGED_ASSEMBLY.value, EntityKind.WASM_MODULE.value,
    EntityKind.EVIDENCE_ARTIFACT.value,
})
_CWE = re.compile(r"(?i)\bcwe[-_/ ]?0*(\d{1,5})\b")
_MESSAGE_BOUND = 1024


@dataclass(frozen=True, slots=True)
class Lead:
    """One accepted, normalized lead. Identity is the accepted record's logical identity."""

    observation_id: str
    family: str
    scanner: str
    rule_id: str
    native_severity: str | None
    reported_severity: str
    severity_basis: str
    message: str | None
    rule_cwe: tuple[str, ...]
    path: str | None
    start_line: int | None
    location_exact: bool
    shard_name: str
    shard_id: str
    shard_sha256: str
    suppression_status: str = "unknown"
    duplicate_of: str | None = None
    flow_ids: tuple[str, ...] = ()
    related: tuple[tuple[str, str], ...] = ()     # (identity, role) from accepted relations
    component_hint: str | None = None

    @property
    def severity_rule(self) -> str:
        return FAMILY_RULES[self.family]

    @property
    def shard_label(self) -> str:
        return f"{self.shard_name}/{self.shard_id}"


@dataclass(frozen=True, slots=True)
class LeadCollection:
    leads: tuple[Lead, ...]
    gaps: tuple[ScopeGap, ...]
    available: Mapping[str, bool]
    correlation_audit: Mapping[str, Any] | None
    correlation_shards: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    non_lead_counts: Mapping[str, int] = field(default_factory=dict)

    def counts(self) -> dict[str, dict[str, int]]:
        found: dict[str, Counter[str]] = {family: Counter() for family in FAMILIES}
        for lead in self.leads:
            found[lead.family][lead.reported_severity] += 1
        return {family: {severity: found[family][severity] for severity in SEVERITY_ORDER} for family in FAMILIES}


def _band(number: float) -> str:
    return ("critical" if number >= 9.0 else "high" if number >= 7.0 else "medium" if number >= 4.0
            else "low" if number > 0.0 else "info")


def _score(value: Any) -> float | None:
    if isinstance(value, Mapping):
        for key in ("base_score", "baseScore", "score"):
            if key in value:
                return _score(value[key])
        return None
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and 0.0 <= number <= 10.0 else None


def _label(value: Any) -> dict[str, str]:
    return normalize_reported_severity({"native_severity": value} if value not in (None, "") else {})


def _first(payload: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if payload.get(key) not in (None, ""):
            return payload[key]
    return None


def severity_for(family: str, payload: Mapping[str, Any]) -> tuple[str, str | None, str]:
    """Return ``(reported, native, basis)`` under the family's versioned rule."""
    if family in {"source_sast", "codeql", "ci_rule"}:
        value = normalize_reported_severity(payload)
        return value["value"], value["native"], value["basis"]
    if family in {"dependency_advisory", "artifact_scanner"}:
        nested = payload.get("observation") if isinstance(payload.get("observation"), Mapping) else {}
        for source in (payload, nested):
            score = _score(_first(source, ("cvss_score", "cvss_base_score", "cvss", "security_severity")))
            if score is not None:
                return _band(score), str(_first(source, ("cvss_score", "cvss_base_score", "cvss",
                                                         "security_severity"))), "advisory-cvss-band"
        for source in (payload, nested):
            native = _first(source, ("advisory_severity", "native_severity", "severity", "level"))
            if native is not None:
                value = _label(native)
                return value["value"], str(native)[:128], value["basis"]
        return "unknown", None, "unmapped-native-severity"
    # post-build hardening checks and OWASP control failures carry no scanner severity by default
    native = _first(payload, ("severity", "risk"))
    if native is None:
        return "unknown", None, "no-native-severity"
    value = _label(native)
    return value["value"], str(native)[:128], value["basis"]


def _message(payload: Mapping[str, Any]) -> str | None:
    value = _first(payload, ("message", "rationale", "summary", "description"))
    return str(value)[:_MESSAGE_BOUND] if value is not None else None


def _cwes(payload: Mapping[str, Any]) -> tuple[str, ...]:
    found: set[str] = set()

    def visit(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, str):
            found.update(f"CWE-{int(match)}" for match in _CWE.findall(value))
        elif isinstance(value, Mapping):
            for key, child in value.items():
                if "cwe" in str(key).lower():
                    visit(child, depth + 1)
                    if isinstance(child, int) and not isinstance(child, bool):
                        found.add(f"CWE-{child}")
        elif isinstance(value, (list, tuple)):
            for child in value[:32]:
                visit(child, depth + 1)
    visit({key: value for key, value in payload.items() if "cwe" in str(key).lower()})
    mapping = payload.get("rule_mapping")
    if isinstance(mapping, Mapping):
        visit({key: value for key, value in mapping.items() if "cwe" in str(key).lower()})
    return tuple(sorted(found, key=lambda item: int(item[4:])))


def observation_family(row: Mapping[str, Any], shard: Mapping[str, Any]) -> str | None:
    """Family of one accepted ``tool_observation`` row, or ``None`` when it is not a lead."""
    from appsec_review.review.scope import PRODUCERS
    payload = row["payload"]
    if scanner_of(payload) == "codeql" or PRODUCERS["codeql"](shard):
        return "codeql"
    if PRODUCERS["ci_configuration"](shard):
        return "ci_rule"
    observation_class = classify(payload)
    if observation_class == "dependency" or payload.get("capability") == "grype":
        return "dependency_advisory"
    if PRODUCERS["artifact_scanner"](shard):
        return "artifact_scanner"
    if observation_class == "source_sast":
        return "source_sast"
    return None


def _relations(scope: AcceptedScope, shards: Iterable[Mapping[str, Any]]) -> dict[str, list[tuple[str, str]]]:
    found: dict[str, list[tuple[str, str]]] = {}
    for relation in scope.store.relations(shards, kinds=("OBSERVED_AT", "DERIVED_FROM")):
        kind = LogicalIdentity.parse(relation["target_id"]).kind.value
        role = "source" if kind == EntityKind.SOURCE_FILE.value else "artifact" if kind in ARTIFACT_KINDS else None
        if role is not None:
            found.setdefault(relation["source_id"], []).append((relation["target_id"], role))
    return found


def _location(row: Mapping[str, Any]) -> tuple[str | None, int | None, bool]:
    location = row["location"]
    if location is None:
        return None, None, False
    return str(location["path"]), int(location["start_line"]), not bool(location["ambiguous"])


def _correlation_leads(scope: AcceptedScope, gaps: list[ScopeGap]
                       ) -> tuple[dict[str, Mapping[str, Any]], Mapping[str, Any] | None, tuple[Mapping[str, Any], ...]]:
    """Lead states from the accepted scanner_correlation shard, else recomputed without suppressions."""
    coverage = scope.producer("scanner_correlation")
    states: dict[str, Mapping[str, Any]] = {}
    audit: Mapping[str, Any] | None = None
    if coverage.shards:
        for row in scope.store.entities(coverage.shards, kinds=("precomputed_fact",)):
            payload = row["payload"]
            result = payload.get("result") or {}
            if payload.get("fact_type") == "lead" and isinstance(result.get("observation_id"), str):
                if result["observation_id"] in states:
                    raise IntegrityError(f"accepted scanner_correlation repeats lead {result['observation_id']}")
                states[result["observation_id"]] = result
            elif payload.get("fact_type") == "audit":
                if result.get("status") != "passed":
                    raise IntegrityError("accepted scanner_correlation membership audit did not pass")
                audit = result
        if audit is None:
            raise IntegrityError("accepted scanner_correlation shard has no membership audit")
        return states, audit, coverage.shards
    gaps.append(ScopeGap("scanner_correlation", "run", "partial",
                         "accepted scanner_correlation is unavailable: duplicate state recomputed by "
                         f"{CORRELATION_RULE}; suppression state is unknown"))
    shards = AcceptedShards(scope.run_root, scope.shards, scope.target_snapshot)
    try:
        product = build_scanner_correlation(shards, None, [], {"menu_partition_size": 1_000_000})
    except LeadAuditError as exc:
        raise IntegrityError(str(exc)) from exc
    for item in product.facts:
        if item.fact_type == "lead":
            states[str(item.result["observation_id"])] = item.result
    return states, None, ()


def _compare_correlation_audit(audit: Mapping[str, Any], sast: Mapping[str, str]) -> None:
    """Per-severity counts must equal the accepted scanner_correlation membership audit."""
    counts = audit.get("counts") or {}
    recomputed = {"source_sast_observations": len(sast),
                  "high_critical": sum(1 for value in sast.values() if value in {"critical", "high"}),
                  "unknown_severity": sum(1 for value in sast.values() if value == "unknown")}
    for key, value in recomputed.items():
        if counts.get(key) != value:
            raise IntegrityError(f"accepted scanner_correlation audit {key}={counts.get(key)} contradicts the "
                                 f"accepted observations ({value})")


def collect_leads(scope: AcceptedScope) -> LeadCollection:
    """Normalize every accepted lead of every family; absent families are gaps, not empty."""
    gaps: list[ScopeGap] = []
    available: dict[str, bool] = {}
    for family in FAMILIES:
        coverages = [scope.producer(name) for name in FAMILY_PRODUCERS[family]]
        available[family] = any(item.shards for item in coverages)
        if not available[family]:
            gaps.append(ScopeGap(family, "run", "missing",
                                 f"lead family {family} has no accepted producer shard "
                                 f"({', '.join(FAMILY_PRODUCERS[family])}); its leads are unknown, not absent"))
        else:
            coverages.extend(scope.producer(name) for name in FAMILY_CONTEXT_PRODUCERS.get(family, ()))
            for item in coverages:
                gaps.extend(ScopeGap(family, gap.scope, gap.state, gap.reason) for gap in item.gaps
                            if gap.state != "missing")

    leads: dict[str, Lead] = {}
    non_lead: Counter[str] = Counter()

    def add(lead: Lead) -> None:
        if lead.observation_id in leads:
            raise IntegrityError(f"accepted lead identity appears twice: {lead.observation_id}")
        leads[lead.observation_id] = lead

    observation_shards = scope.select(lambda shard: shard["name"] == "observations")
    relations = _relations(scope, observation_shards)
    states, audit, correlation_shards = _correlation_leads(scope, gaps) if (
        available["source_sast"] or available["codeql"]) else ({}, None, ())
    sast_classified: dict[str, str] = {}
    for shard in observation_shards:
        for row in scope.store.entities((shard,), kinds=("tool_observation",)):
            if classify(row["payload"]) == "source_sast":
                sast_classified[row["identity"]] = normalize_reported_severity(row["payload"])["value"]
            family = observation_family(row, shard)
            if family is None:
                non_lead[classify(row["payload"])] += 1
                continue
            payload = row["payload"]
            reported, native, basis = severity_for(family, payload)
            path, line, exact = _location(row)
            state = states.get(row["identity"], {}) if family in {"source_sast", "codeql"} else {}
            if row["identity"] in sast_classified and states:
                if not state:
                    raise IntegrityError(f"accepted source-SAST observation has no correlation lead fact: "
                                         f"{row['identity']}")
                if (state.get("severity_rule") == SEVERITY_RULE
                        and state.get("normalized_reported_severity") != reported):
                    raise IntegrityError(f"correlation severity contradicts {SEVERITY_RULE}: {row['identity']}")
            related = tuple(sorted(set(relations.get(row["identity"], ()))))
            add(Lead(
                observation_id=row["identity"], family=family, scanner=scanner_of(payload), rule_id=rule_of(payload),
                native_severity=native, reported_severity=reported, severity_basis=basis,
                message=_message(payload), rule_cwe=_cwes(payload), path=path, start_line=line,
                location_exact=exact, shard_name=str(shard["name"]), shard_id=str(shard.get("shard_id", "default")),
                shard_sha256=scope.shard_sha256(shard),
                suppression_status=str(state.get("suppression_status") or "unknown"),
                duplicate_of=state.get("duplicate_of") if isinstance(state.get("duplicate_of"), str) else None,
                flow_ids=tuple(sorted(str(item) for item in state.get("flow_ids") or ())),
                related=related))

    for shard in scope.producer("post_build_hardening").shards:
        for row in scope.store.entities((shard,), kinds=("tool_observation",)):
            payload = row["payload"]
            if payload.get("producer") != "deterministic-build-security-rules":
                continue
            status = str(payload.get("status") or "").upper()
            if status == "UNKNOWN":
                gaps.append(ScopeGap("post_build_hardening", f"{shard['name']}/{shard['shard_id']}:"
                                     f"{payload.get('check_id')}", "partial",
                                     "post-build hardening check outcome is UNKNOWN"))
            if status != "FAIL":
                continue
            reported, native, basis = severity_for("post_build_hardening", payload)
            path, line, exact = _location(row)
            add(Lead(row["identity"], "post_build_hardening", "deterministic-build-security-rules",
                     str(payload.get("check_id") or "unknown"), native, reported, basis, _message(payload),
                     _cwes(payload), path, line, exact, str(shard["name"]), str(shard.get("shard_id", "default")),
                     scope.shard_sha256(shard)))

    for shard in scope.producer("control_evidence").shards:
        for row in scope.store.entities((shard,), kinds=("precomputed_fact",)):
            result = row["payload"].get("result") or {}
            status = result.get("control_status")
            if status == "cannot_verify":
                gaps.append(ScopeGap("owasp_control", f"{result.get('control_identity')}:{result.get('component_id')}",
                                     "partial", "OWASP control could not be verified"))
            if status != "not_satisfied":
                continue
            reported, native, basis = severity_for("owasp_control", result)
            path, line, exact = _location(row)
            subject = row["payload"].get("subject_identity")
            add(Lead(row["identity"], "owasp_control", "owasp-workbench", str(result.get("control_identity") or "unknown"),
                     native, reported, basis, _message(result), _cwes(result), path, line, exact,
                     str(shard["name"]), str(shard.get("shard_id", "default")), scope.shard_sha256(shard),
                     related=((subject, "component"),) if isinstance(subject, str) else (),
                     component_hint=str(result["component_id"]) if result.get("component_id") else None))

    if states:
        invented = sorted(set(states) - set(sast_classified))
        if invented:
            raise IntegrityError(f"scanner_correlation lists leads absent from accepted observations: {invented[:5]}")
    if audit is not None:
        _compare_correlation_audit(audit, sast_classified)
    ordered = tuple(leads[key] for key in sorted(leads))
    return LeadCollection(ordered, sorted_gaps(gaps), available, audit, correlation_shards,
                          dict(sorted(non_lead.items())))
