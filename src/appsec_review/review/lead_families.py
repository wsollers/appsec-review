"""Versioned lead-family normalization over accepted shards (lane A intake).

Every accepted lead family has one versioned rule that maps an accepted record to a normalized
*reported* severity. Reported severity orders review work; it is never an adjudicated severity, and
an unmapped label stays ``unknown`` rather than low. A family whose accepted producer shard is
absent yields a coverage gap, never an empty (clean) lead list.

Families: source SAST and CodeQL reuse ``retrieval.observations`` normalization and the accepted
``scanner_correlation`` lead facts of ``indexing/sast.py``; artifact scanners; dependency
advisories (the advisory's own CVSS; else the pinned NVD CVSS, preferring v4.0, then v3.1, v3.0
and v2, with basis ``nvd-cvss-band``; else the advisory's severity label); CI rules; post-build
hardening checks; OWASP control failures; secret scanner findings (``secret``: unknown reported severity, rule
CWE-798, no scanner value or match ever kept) and Dockerfile/IaC misconfiguration (``config_scanner``).
:data:`OBSERVATION_PRODUCERS` is the explicit lead decision per observation producer; an observation whose
scanner is neither mapped nor listed as a deliberate non-lead is a named ``unmapped_observations`` gap. Dependency and artifact-scanner leads carry the bounded
``advisory_context`` of ``review.advisories`` (reference context only).
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
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
from appsec_review.review import advisories as advisory_reference
from appsec_review.review.models import IntegrityError
from appsec_review.review.scope import AcceptedScope, ScopeGap, sorted_gaps
from appsec_review.review.secret_redaction import redact_message

SECRET_CWE = "CWE-798"       # rule-level mapping of the ``secret`` family: use of hard-coded credentials

FAMILIES = ("source_sast", "codeql", "artifact_scanner", "dependency_advisory", "ci_rule",
            "post_build_hardening", "owasp_control", "secret", "config_scanner")
FAMILY_RULES = {family: f"appsec-review/lead-family/{family}/1" for family in FAMILIES}
# Families whose versioned rule consults the pinned NVD CVSS when the scanner reports none.
FAMILY_RULES.update({family: f"appsec-review/lead-family/{family}/2"
                     for family in ("artifact_scanner", "dependency_advisory")})
# source_sast/2: the family also takes the evidence-collection tools whose records carry the generic
# ``static_analysis`` category (shellcheck, psalm) and Infer (job_cpp_compiled_analysis); severity unchanged.
FAMILY_RULES["source_sast"] = "appsec-review/lead-family/source_sast/2"
ADVISORY_FAMILIES = frozenset({"artifact_scanner", "dependency_advisory"})
# Producer whose accepted shard must exist for the family to have coverage.
FAMILY_PRODUCERS = {
    "source_sast": ("source_sast",), "codeql": ("codeql",), "artifact_scanner": ("artifact_scanner",),
    "dependency_advisory": ("dependency_scanner", "artifact_scanner"), "ci_rule": ("ci_configuration",),
    "post_build_hardening": ("post_build_hardening",), "owasp_control": ("control_evidence",),
    "secret": ("secret_scanner",), "config_scanner": ("config_scanner",),
}


@dataclass(frozen=True, slots=True)
class ProducerDecision:
    """The explicit lead decision for one observation producer: a family, or the reason it is not a lead."""

    job: str                      # the producing job
    scanner: str                  # scanner id (``tool-*``, ``infer``, ...), ``*`` for every scanner of the job
    family: str | None            # None: deliberately not a lead
    reason: str

    def __post_init__(self) -> None:
        if not self.reason or (self.family is not None and self.family not in FAMILIES):
            raise ValueError(f"a producer decision names a known family or none, and always a reason: {self}")


_EV, _CLANG, _CPP = "job_evidence_collection", "job_clang_static_analysis", "job_cpp_compiled_analysis"
_POST_BUILD = "job_post_build_security_assessment"
_CODEQL, _ARTIFACT, _CI ="job_codeql_analysis", "job_artifact_security_analysis", "job_ci_configuration_analysis"
# Every producer of ``tool_observation`` rows in the accepted observation index and what lane A does with its
# rows. A producer or scanner absent from this table is a named coverage gap at assembly, and
# ``tests/review/test_lead_coverage.py`` fails when a producer in the code is absent from it.
OBSERVATION_PRODUCERS: tuple[ProducerDecision, ...] = (
    ProducerDecision(_EV, "tool-gitleaks", "secret", "secret scanner; the scanner reports no severity"),
    *(ProducerDecision(_EV, tool, "source_sast", "source SAST") for tool in (
        "tool-semgrep", "tool-opengrep", "tool-gosec", "tool-mobsfscan", "tool-cppcheck", "tool-pmd",
        "tool-phpstan", "tool-phpcs", "tool-spotbugs",
        "tool-shellcheck", "tool-psalm")),     # the last two record the generic ``static_analysis`` category
    ProducerDecision(_EV, "tool-osv-scanner", "dependency_advisory", "dependency advisory"),
    ProducerDecision(_EV, "tool-grype", "dependency_advisory", "dependency advisory"),
    *(ProducerDecision(_EV, tool, "config_scanner", "Dockerfile and IaC misconfiguration") for tool in (
        "tool-hadolint", "tool-checkov", "tool-trivy")),
    ProducerDecision(_EV, "tool-zizmor", None,
                     "GitHub Actions findings are reviewed from job_ci_configuration_analysis, which runs zizmor on "
                     "the same workflow files (ci_rule); mapping both would duplicate every lead"),
    ProducerDecision(_EV, "tool-syft", None, "SBOM inventory: package rows are context for dependency review, "
                                             "not findings"),
    ProducerDecision(_EV, "tool-blint", None,
                     "binary hardening of catalog binaries has no source line and nests per-check severities inside "
                     "one record; built-artifact hardening is reviewed as artifact_scanner and post_build_hardening "
                     "(follow-up: normalize the nested severities, then admit)"),
    ProducerDecision(_CLANG, "*", "source_sast", "Clang Static Analyzer and clang-tidy findings"),
    ProducerDecision(_CPP, "infer", "source_sast", "Infer findings (null dereference, leaks, buffer overrun)"),
    ProducerDecision(_CODEQL, "*", "codeql", "CodeQL results"),
    ProducerDecision(_ARTIFACT, "*", "artifact_scanner", "artifact scanner records (blint, syft, builtin)"),
    ProducerDecision(_CI, "*", "ci_rule", "CI configuration rules"),
    # Producers of ``tool_observation`` rows outside the ``observations`` index.
    ProducerDecision(_POST_BUILD, "deterministic-build-security-rules", "post_build_hardening",
                     "build_security index; FAIL checks are leads, PASS and UNKNOWN are coverage"),
    ProducerDecision(_POST_BUILD, "*", None,
                     "any other post-build observation is model-proposed output, never scanner evidence"),
    ProducerDecision("job_code_graph_index", "*", None,
                     "graph index rows are derived code-graph context (clang-tidy diagnostics, CPG functions), "
                     "reviewed through the package neighborhood, not through lead packages"),
    ProducerDecision("job_cpg_analysis", "*", None,
                     "Joern publishes evidence-artifact and CPG function rows, no tool observations"),
)
# Observation class -> family for a scanner the table does not name (fail toward review, not toward silence);
# classes that are never findings.
CLASS_FAMILY = {"source_sast": "source_sast", "secret": "secret", "configuration": "config_scanner"}
NOT_A_LEAD_CLASSES: Mapping[str, str] = {
    "diagnostic": "tool diagnostics describe a scanner run, not the target; they surface as coverage gaps",
    "inventory": "software inventory rows are context, not findings",
    "binary": "binary-hardening rows: see the tool-blint decision",
}


def producer_decision(job: str | None, scanner: str) -> ProducerDecision | None:
    """The explicit decision for ``scanner`` of ``job``; versioned scanner ids match by their leading id."""
    names = {scanner, scanner.split(":", 1)[0]}
    decisions = [item for item in OBSERVATION_PRODUCERS if item.job == job]
    return next((item for item in decisions if item.scanner in names),
                next((item for item in decisions if item.scanner == "*"), None))
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


SEVERITY_SOURCES = ("rule_table", "cwe_catalog", "model_triage")
ASSESSED_VALUES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, slots=True)
class AssessedSeverity:
    """An audited severity assigned to a lead whose scanner reported none (``review.lead_triage``).

    It orders and admits the lead only; it never feeds scoring, ship-block decisions or claim states.
    """

    value: str
    source: str                     # rule_table | cwe_catalog | model_triage
    basis: str
    reason: str
    version: str                    # the rule-table version, or the triage prompt/guidance version
    triage_id: str

    def __post_init__(self) -> None:
        if self.value not in ASSESSED_VALUES or self.source not in SEVERITY_SOURCES:
            raise ValueError(f"invalid assessed severity: {self.value}/{self.source}")

    def record(self) -> dict[str, str]:
        return {"value": self.value, "source": self.source, "basis": self.basis, "reason": self.reason,
                "rule_or_prompt_version": self.version, "triage_id": self.triage_id}


@dataclass(frozen=True, slots=True)
class LeadTriage:
    """The triage outcome the severity-triage step hands to lead collection for one lead."""

    state: str                              # assessed | unresolved | not_needed
    assessed: AssessedSeverity | None = None
    gap: str | None = None                  # triage_failed:<code> / triage_skipped:<code> for an unresolved lead
    reason: str | None = None               # why the lead stays unknown (the model's reason for insufficient context)
    references: tuple[Mapping[str, Any], ...] = ()


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
    # Bounded reference context from the accepted dependency_advisories facts (review.advisories).
    advisory: Mapping[str, Any] | None = field(default=None, compare=False, hash=False)
    # Lead severity triage (review.lead_triage): ``reported_severity`` is the scanner's own value and is never
    # rewritten. ``assessed_severity`` is a separate, audited assessment for a lead the scanner left ``unknown``.
    # ``triage_state`` is None when no triage ran for this collection (the lead then has no severity record).
    assessed_severity: "AssessedSeverity | None" = None
    triage_state: str | None = None
    triage_gap: str | None = None
    triage_reason: str | None = None
    severity_references: tuple[Mapping[str, Any], ...] = field(default=(), compare=False, hash=False)

    @property
    def effective_severity(self) -> str:
        """The severity that orders and admits the lead: reported if known, else assessed, else ``unknown``."""
        if self.reported_severity != "unknown":
            return self.reported_severity
        return self.assessed_severity.value if self.assessed_severity is not None else "unknown"

    @property
    def effective_from(self) -> str:
        if self.reported_severity != "unknown":
            return "reported"
        return "assessed" if self.assessed_severity is not None else "unknown"

    def severity_record(self) -> dict[str, Any] | None:
        """The two-sided severity record (original and assessed), or None when no triage ran."""
        if self.triage_state is None:
            return None
        return {
            "original": {"reported_severity": self.reported_severity, "native_severity": self.native_severity,
                         "severity_basis": self.severity_basis, "severity_rule": self.severity_rule,
                         "scanner": self.scanner, "rule_id": self.rule_id},
            "assessed": self.assessed_severity.record() if self.assessed_severity is not None else None,
            "references": [dict(item) for item in self.severity_references],
            "effective": {"value": self.effective_severity, "from": self.effective_from},
            "gap": ({"code": self.triage_gap, "reason": self.triage_reason}
                    if self.triage_gap else None),
        }

    @property
    def kev_listed(self) -> bool | None:
        return advisory_reference.kev_listed(self.advisory)

    @property
    def epss_percentile(self) -> float | None:
        return advisory_reference.epss_percentile(self.advisory)

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


def with_triage(lead: Lead, outcome: LeadTriage | None) -> Lead:
    """``lead`` carrying its triage outcome; ``reported_severity`` is never touched."""
    if lead.reported_severity != "unknown":
        return replace(lead, triage_state="not_needed")
    if outcome is None:
        return replace(lead, triage_state="unresolved", triage_gap="triage_failed:missing_result",
                       triage_reason="the triage step produced no result for this lead")
    return replace(lead, triage_state=outcome.state, assessed_severity=outcome.assessed, triage_gap=outcome.gap,
                   triage_reason=outcome.reason, severity_references=tuple(outcome.references))


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


def severity_for(family: str, payload: Mapping[str, Any],
                 advisory: Mapping[str, Any] | None = None) -> tuple[str, str | None, str]:
    """Return ``(reported, native, basis)`` under the family's versioned rule.

    ``advisory`` is the lead's ``advisory_context``; its preferred NVD CVSS sets the reported
    severity of a dependency or artifact-scanner lead only when the scanner reported no CVSS.
    """
    if family in {"source_sast", "codeql", "ci_rule", "config_scanner"}:
        value = normalize_reported_severity(payload)
        return value["value"], value["native"], value["basis"]
    if family == "secret":
        # Secret scanners report no severity: unknown (never low) unless a scanner ever names a mapped label.
        native = _first(payload, ("native_severity", "severity", "level"))
        if native is None or str(native).strip().upper() in {"UNKNOWN", "UNDEFINED"}:
            return "unknown", None, "no-native-severity"
        value = _label(native)
        return value["value"], str(native)[:128], value["basis"]
    if family in {"dependency_advisory", "artifact_scanner"}:
        nested = payload.get("observation") if isinstance(payload.get("observation"), Mapping) else {}
        for source in (payload, nested):
            score = _score(_first(source, ("cvss_score", "cvss_base_score", "cvss", "security_severity")))
            if score is not None:
                return _band(score), str(_first(source, ("cvss_score", "cvss_base_score", "cvss",
                                                         "security_severity"))), "advisory-cvss-band"
        nvd = advisory_reference.nvd_severity(advisory)
        if nvd is not None:
            return _band(nvd[0]), nvd[1][:128], "nvd-cvss-band"
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


def _job_of(shard: Mapping[str, Any]) -> str | None:
    return (shard.get("producer") or {}).get("job")


def observation_family(row: Mapping[str, Any], shard: Mapping[str, Any]) -> str | None:
    """Family of one accepted ``tool_observation`` row, or ``None`` when it is not a lead.

    ``None`` is either an explicit decision (:data:`OBSERVATION_PRODUCERS`, :data:`NOT_A_LEAD_CLASSES`; see
    :func:`non_lead_key`) or an unmapped scanner, which ``collect_leads`` reports as a named gap.
    """
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
    if observation_class in NOT_A_LEAD_CLASSES:
        return None
    decision = producer_decision(_job_of(shard), scanner_of(payload))
    if decision is not None:
        return decision.family
    return CLASS_FAMILY.get(observation_class)


def non_lead_key(row: Mapping[str, Any], shard: Mapping[str, Any]) -> str | None:
    """Accounting key of an observation that is deliberately not a lead; ``None`` when no decision covers it."""
    payload = row["payload"]
    observation_class = classify(payload)
    if observation_class in NOT_A_LEAD_CLASSES:
        return f"class:{observation_class}"
    scanner = scanner_of(payload)
    decision = producer_decision(_job_of(shard), scanner)
    return f"scanner:{scanner.split(':', 1)[0]}" if decision is not None and decision.family is None else None


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


def collect_leads(scope: AcceptedScope, triage: Mapping[str, LeadTriage] | None = None) -> LeadCollection:
    """Normalize every accepted lead of every family; absent families are gaps, not empty.

    ``triage`` (lead identity -> :class:`LeadTriage`, from ``review.lead_triage``) attaches the audited assessed
    severity of leads the scanner left ``unknown``. Without it every lead is exactly as the scanner reported it.
    """
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
    unmapped: Counter[tuple[str, str]] = Counter()

    def add(lead: Lead) -> None:
        if lead.observation_id in leads:
            raise IntegrityError(f"accepted lead identity appears twice: {lead.observation_id}")
        leads[lead.observation_id] = lead

    observation_shards = scope.select(lambda shard: shard["name"] == "observations")
    relations = _relations(scope, observation_shards)
    advisory_facts = advisory_reference.advisory_facts(scope)
    states, audit, correlation_shards = _correlation_leads(scope, gaps) if (
        available["source_sast"] or available["codeql"]) else ({}, None, ())
    sast_classified: dict[str, str] = {}
    for shard in observation_shards:
        for row in scope.store.entities((shard,), kinds=("tool_observation",)):
            if classify(row["payload"]) == "source_sast":
                sast_classified[row["identity"]] = normalize_reported_severity(row["payload"])["value"]
            family = observation_family(row, shard)
            if family is None:
                key = non_lead_key(row, shard)
                if key is not None:
                    non_lead[key] += 1
                else:
                    unmapped[(f"{shard['name']}/{shard.get('shard_id', 'default')}", scanner_of(row["payload"]))] += 1
                continue
            payload = row["payload"]
            context = (advisory_reference.context_for(advisory_facts.get(row["identity"]))
                       if family in ADVISORY_FAMILIES else None)
            reported, native, basis = severity_for(family, payload, context)
            path, line, exact = _location(row)
            rule_id, message, rule_cwe = rule_of(payload), _message(payload), _cwes(payload)
            if family == "secret":
                # The sanitized index blanks rule ids that name a key ("generic-api-key"); the entity name keeps it.
                if rule_id in {"unknown", "<redacted>"} and row.get("name"):
                    rule_id = str(row["name"])[:128]
                rule_id, message = redact_message(rule_id, bound=128) or "unknown", redact_message(message)
                rule_cwe = tuple(sorted({*rule_cwe, SECRET_CWE}, key=lambda item: int(item[4:])))
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
                observation_id=row["identity"], family=family, scanner=scanner_of(payload), rule_id=rule_id,
                native_severity=native, reported_severity=reported, severity_basis=basis,
                message=message, rule_cwe=rule_cwe, path=path, start_line=line,
                location_exact=exact, shard_name=str(shard["name"]), shard_id=str(shard.get("shard_id", "default")),
                shard_sha256=scope.shard_sha256(shard),
                suppression_status=str(state.get("suppression_status") or "unknown"),
                duplicate_of=state.get("duplicate_of") if isinstance(state.get("duplicate_of"), str) else None,
                flow_ids=tuple(sorted(str(item) for item in state.get("flow_ids") or ())),
                related=related, advisory=context))

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

    for (shard_label, scanner), count in sorted(unmapped.items()):
        gaps.append(ScopeGap("unmapped_observations", f"{shard_label}:{scanner}", "partial",
                             f"{count} observation(s) of scanner {scanner} are neither mapped to a lead family nor "
                             "listed as deliberate non-leads (review.lead_families.OBSERVATION_PRODUCERS); they were "
                             "not reviewed"))
    if states:
        invented =sorted(set(states) - set(sast_classified))
        if invented:
            raise IntegrityError(f"scanner_correlation lists leads absent from accepted observations: {invented[:5]}")
    if audit is not None:
        _compare_correlation_audit(audit, sast_classified)
    ordered = tuple(leads[key] for key in sorted(leads))
    if triage is not None:
        ordered = tuple(with_triage(lead, triage.get(lead.observation_id)) for lead in ordered)
    return LeadCollection(ordered, sorted_gaps(gaps), available, audit, correlation_shards,
                          dict(sorted(non_lead.items())))
