"""Fan-in stages: cross-lane merge, R5 adjudication, scoring, completeness, and publication.

Each stage is a pure function of the sealed ledger shards and lane documents it reads, plus one new
sealed shard of its own. Merging verifies every hash chain, and a merge whose head depends on shard
order is a framework-integrity failure. Publication re-verifies the accepted scope, the package
manifest, and every referenced cell receipt from bytes before it writes the ledger and handoff.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from appsec_review.config.inference_review import PocCandidateSettings
from appsec_review.review import adjudication as r5
from appsec_review.review import advisories as advisory_reference
from appsec_review.review.accounting import Accounting, PoolOutcome, exact_accounting
from appsec_review.review.adjudication import Adjudication, adjudicate
from appsec_review.review.claims import possible_duplicates
from appsec_review.review.identity import make_id, sha256_hex
from appsec_review.review.ledger import (
    EVENT_SCHEMA, LedgerWriter, MergedLedger, Projection, gap_from_json, merge_shards, project,
)
from appsec_review.review.models import (
    Admissibility, ClaimState, Gap, GapClass, IntegrityError, JudgeVerdict, JudgeVerdictValue, Lane,
    RelationKind, make_gap,
)
from appsec_review.review.scoring import (
    DERIVATION_RULE, UNAVAILABLE_CATALOG, ImpactCatalog, consumed_factors, default_factor_registry, default_registry,
    registry_from_settings,
)
from appsec_review.review.scoring.factors import EvidenceSource, FactorSet, factor_input
from appsec_review.review.scoring.interface import ScoreProviderResult, ScoreRequest, SeverityAssessment
from appsec_review.review import ship_block
from appsec_review.review.ship_block import ShipBlockInputs, ShipBlockSettings
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .datasets import PLANNED_CONSUMERS
from .schemas import SchemaSet

HANDOFF_SCHEMA = "appsec-review/inference-review-handoff/2"
FINDING_SCHEMA = "appsec-review/finding-package/2"
COVERAGE_SCHEMA = "appsec-review/inference-review-coverage-matrix/1"
def scorer_actor(implementation: str) -> str:
    """The deterministic ``independent_scorer`` actor of one provider implementation."""
    return make_id("actor", 1, {"role": "independent_scorer", "provider": implementation})


SCORER_ACTOR = scorer_actor("application_risk_matrix/1")
# PROPOSED -> final state; confirmation and the R5 row-4 reachability/configuration states pass through
# ``supported`` because the condition is established before policy or contradiction narrows it.
TRANSITION_PATHS: Mapping[ClaimState, tuple[ClaimState, ...]] = {
    ClaimState.CONFIRMED: (ClaimState.SUPPORTED, ClaimState.CONFIRMED),
    ClaimState.NOT_REACHABLE: (ClaimState.SUPPORTED, ClaimState.NOT_REACHABLE),
    ClaimState.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION: (
        ClaimState.SUPPORTED, ClaimState.NOT_EXPLOITABLE_IN_OBSERVED_CONFIGURATION),
}


def merge_verified(paths: Sequence[Path]) -> MergedLedger:
    """Merge shards in two enumeration orders; differing heads are a non-deterministic merge."""
    forward = merge_shards(paths)
    backward = merge_shards(list(reversed(paths)))
    if forward.head != backward.head or forward.events != backward.events:
        raise IntegrityError("non-deterministic ledger merge")
    return forward


# ------------------------------------------------------------------------------------------------
# merge.claims


def merge_claims(lanes: Sequence[Mapping[str, Any]], shard_paths: Sequence[Path],
                 package_entities: Mapping[str, Sequence[str]], components: Sequence[str]) -> dict[str, Any]:
    merged = merge_verified(shard_paths)
    projection = project(merged.events)
    proposals: dict[str, set[str]] = defaultdict(set)
    independence: dict[str, list[Any]] = defaultdict(list)
    verifier_gaps: dict[str, list[Any]] = defaultdict(list)
    for lane in lanes:
        for claim_id, packages in lane["proposals"].items():
            proposals[claim_id].update(packages)
        for claim_id, values in lane["independence"].items():
            independence[claim_id].extend(values)
        for claim_id, values in lane["verifier_gaps"].items():
            verifier_gaps[claim_id].extend(values)
    if set(proposals) != set(projection.claims):
        raise IntegrityError("lane documents and ledger shards disagree on the proposed claims")
    scope: dict[str, list[str]] = {}
    for claim_id, packages in proposals.items():
        entities = set(components)
        for package_id in packages:
            entities.update(package_entities[package_id])
        scope[claim_id] = sorted(entities)
    claims = [view.claim for view in projection.claims.values()]
    return {
        "schema": "appsec-review/inference-review-merge/1", "ledger_head_sha256": merged.head,
        "streams": list(merged.streams), "claims": sorted(projection.claims),
        "duplicate_proposals": {claim_id: {lane.value: count for lane, count in view.duplicate_proposals.items()}
                                for claim_id, view in projection.claims.items()
                                if sum(view.duplicate_proposals.values())},
        "proposal_packages": {claim_id: sorted(values) for claim_id, values in sorted(proposals.items())},
        "independence": {key: sorted(values, key=lambda item: item["verifier_cell_id"])
                         for key, values in sorted(independence.items())},
        "verifier_gaps": {key: sorted(values, key=lambda item: item["gap_id"])
                          for key, values in sorted(verifier_gaps.items())},
        "scope_entities": scope,
        "claim_rounds": {claim_id: max((record["round"] for lane in lanes
                                       for package_id in proposals[claim_id]
                                       for record in lane.get("rounds", {}).get(package_id, ())), default=0)
                         for claim_id in sorted(proposals)},
        "possible_duplicates": [list(pair) for pair in possible_duplicates(claims)],
    }


# ------------------------------------------------------------------------------------------------
# adjudicate.apply_policy


def adjudication_json(item: Adjudication, round_index: int = 0) -> dict[str, Any]:
    return {"adjudication_id": item.adjudication_id, "claim_id": item.claim_id, "round": round_index,
            "prior_state": item.prior_state.value, "state": item.state.value, "deciding_row": item.deciding_row.value,
            "duplicate_of": item.duplicate_of, "verifier_independent": item.verifier_independent,
            "predicates": [{"predicate": status.predicate.value, "required": status.required,
                            "outcome": status.outcome.value, "supporting": list(status.supporting),
                            "contradicting": list(status.contradicting)} for status in item.predicates],
            "counted_relation_ids": list(item.counted_relation_ids), "gap_ids": list(item.gap_ids),
            "policy_sha256": item.policy_sha256}


def apply_policy(merged: Mapping[str, Any], projection: Projection, ledger_path: Path, stream: str) -> dict[str, Any]:
    writer = LedgerWriter(ledger_path, stream)
    adjudicated: list[str] = []
    records: list[dict[str, Any]] = []
    gaps: dict[str, Gap] = {}
    for claim_id, view in projection.claims.items():          # canonical claim id order
        round_index = merged.get("claim_rounds", {}).get(claim_id, 0)
        verifiers = merged["independence"].get(claim_id, [])
        independent = any(item["independent"] for item in verifiers)
        verifier_gap = None
        if not independent and merged["verifier_gaps"].get(claim_id):
            verifier_gap = gap_from_json(merged["verifier_gaps"][claim_id][0])
        decision = adjudicate(view.claim, projection.relations.get(claim_id, ()), independent,
                              merged["scope_entities"].get(claim_id, ()), adjudicated, view.claim.state,
                              verifier_gap=verifier_gap, round=round_index)
        adjudicated.append(claim_id)
        records.append(adjudication_json(decision, round_index))
        state = ClaimState.PROPOSED
        for target in TRANSITION_PATHS.get(decision.state, (decision.state,)):
            writer.transition(claim_id, state, target, reason=f"{r5.RULES_VERSION}:{decision.deciding_row.value}",
                              adjudication_id=decision.adjudication_id, round=round_index)
            state = target
        for gap in decision.gaps:
            gaps.setdefault(gap.gap_id, gap)
    for gap_id in sorted(gaps):
        writer.record_gap(gaps[gap_id])
    receipt = writer.seal()
    counts = defaultdict(int)
    for record in records:
        counts[record["state"]] += 1
    return {"schema": "appsec-review/inference-review-adjudications/1", "rules": r5.RULES_VERSION,
            "policy_sha256": r5.POLICY_SHA256, "adjudications": records, "states": dict(sorted(counts.items())),
            "ledger_shard": {"events": receipt.event_count, "sha256": file_sha256(ledger_path)}}


# ------------------------------------------------------------------------------------------------
# scoring.score_claims


_REFERENCE_LIMITATION = ("reference_inputs are pinned-feed context (NVD CVSS, CISA KEV) about the advisory, not "
                         "about this target; FIRST EPSS is never a scoring input")
LIMITATIONS: Mapping[str, tuple[str, ...]] = {
    "application_risk_matrix/1": (
        "application_risk_matrix/1 rates impact from a configured CWE table only; it is not a CVSS score and "
        "does not assess environment or business impact", _REFERENCE_LIMITATION),
    "application_risk_matrix/3": (
        "application_risk_matrix/3 rates configured score-factors/1 evidence factors with a configured model; "
        "it is not a CVSS score", "environmental_business_impact reflects accepted security tags (exposure, "
        "privilege, data sensitivity), not deployment or business data",
        "impact_class is a cwe_impact_overrides entry or is derived (cwe-impact-derivation/1) from the run's "
        "pinned MITRE CWE catalog consequences, which describe the weakness class, not this target",
        _REFERENCE_LIMITATION),
}


def score_package_json(result: ScoreProviderResult) -> dict[str, Any]:
    native = dict(result.native)
    rendered: dict[str, Any] = {"nomenclature": str(native.get("matrix", result.implementation_version))}
    if native.get("band"):
        rendered["rating"] = str(native["band"])
    if native.get("cell"):
        rendered["matrix_cell"] = [str(item) for item in native["cell"]]

    def dimension(value) -> dict[str, Any] | None:
        return None if value is None else {"scale": value.scale, "rating": value.rating, "value": value.value}

    factors = result.factors or FactorSet((), ())
    citations = []
    for item in factors.values:
        by_kind: dict[str, list[str]] = defaultdict(list)
        for citation in item.citations:
            by_kind[citation.kind.value].append(citation.id)
        citations.append({"factor": item.factor.value, "evidence_relations": sorted(by_kind["evidence_relation"]),
                          "entities": sorted(by_kind["entity"]), "tag_assignments": sorted(by_kind["tag_assignment"]),
                          "references": sorted(by_kind["adjudication"] + by_kind["reference_input"]
                                               + by_kind["configuration"])})
    limitations = LIMITATIONS.get(result.implementation_version, ())
    assessment = result.severity_assessment or SeverityAssessment(
        "complete" if result.technical_severity is not None and result.technical_severity.rating else "unrated",
        None, None)
    return {"schema": result.schema, "severity_assessment": assessment.record(), "score_id": result.score_id, "claim_id": result.claim_id,
            "adjudication_id": result.adjudication_id,
            "provider": {"id": result.provider_id, "interface": result.interface_version,
                         "implementation": result.implementation_version},
            "provider_config_sha256": result.provider_config_sha256, "policy_sha256": result.policy_sha256,
            "native": rendered, "native_result_sha256": result.native_sha256,
            "technical_severity": dimension(result.technical_severity),
            "exploitability_confidence": dimension(result.exploitability_confidence),
            "environmental_business_impact": dimension(result.environmental_business_impact),
            "remediation_priority": dimension(result.remediation_priority),
            "assumptions": list(result.assumptions), "missing_factors": list(result.missing_factors),
            "evidence_relations": list(result.evidence_relations), "factor_citations": citations,
            "factors": [{"factor": item.factor.value, "scale": item.scale, "value": item.value,
                         "detail": item.record()["detail"]} for item in factors.values],
            "missing_factor_reasons": [{"factor": factor, "reason": reason}
                                       for factor, reason in result.missing_factor_reasons],
            "limitations": list(limitations),
            "scorer": result.scorer_actor_id, "input_fingerprint": result.input_fingerprint,
            "overrides": [dict(item) for item in result.overrides],
            **({"reference_inputs": dict(result.reference_inputs)} if result.reference_inputs else {})}


def claim_references(merged: Mapping[str, Any], documents: Mapping[str, Mapping[str, Any]]
                     ) -> dict[str, dict[str, Any]]:
    """Labelled reference scoring inputs per claim, from the lane A lead packages that proposed it.

    Only a finding-lead package names the single lead a claim was raised from; a hunt menu lists many
    leads, so hunt proposals contribute nothing. Several proposing lead packages are merged
    deterministically (union of CVSS vectors, KEV listed if any is, highest EPSS percentile).
    """
    found: dict[str, dict[str, Any]] = {}
    for claim_id, package_ids in sorted(merged.get("proposal_packages", {}).items()):
        cvss: dict[tuple, dict[str, Any]] = {}
        kev: list[bool | None] = []
        epss: list[dict[str, Any]] = []
        for package_id in sorted(package_ids):
            document = documents.get(package_id) or {}
            if document.get("kind") != "finding_lead":
                continue
            for lead in document.get("lead_menu", ()):
                inputs = advisory_reference.reference_inputs(lead.get("advisory_context"))
                for item in inputs["reference_cvss"]:
                    cvss[(item["cve_id"], item["version"], item["vector"])] = item
                if lead.get("advisory_context"):
                    kev.append(inputs["kev_listed"])
                if inputs["epss"]:
                    epss.append(inputs["epss"])
        if not cvss and not kev and not epss:
            continue
        found[claim_id] = {
            "reference_cvss": [cvss[key] for key in sorted(cvss, key=lambda value: tuple(map(str, value)))][:8],
            "kev_listed": True if any(item is True for item in kev) else (
                False if kev and all(item is False for item in kev) else None),
            "epss": max(epss, key=lambda item: (item.get("percentile") or 0.0, str(item.get("cve_id"))))
            if epss else None}
    return found


def claim_lead_families(merged: Mapping[str, Any], documents: Mapping[str, Mapping[str, Any]]
                        ) -> dict[str, tuple[str, ...]]:
    """Lead families of the lane A finding-lead packages that proposed each claim.

    As with :func:`claim_references`, only a finding-lead package names the lead a claim was raised
    from; hunt proposals contribute nothing. ``ship-block-policy/1`` reads these to decide whether a
    claim is a dependency finding.
    """
    found: dict[str, tuple[str, ...]] = {}
    for claim_id, package_ids in sorted(merged.get("proposal_packages", {}).items()):
        families = {str(lead["lead_family"]) for package_id in package_ids
                    for document in [documents.get(package_id) or {}] if document.get("kind") == "finding_lead"
                    for lead in document.get("lead_menu", ()) if lead.get("lead_family")}
        if families:
            found[claim_id] = tuple(sorted(families))
    return found


def claim_lead_severities(merged: Mapping[str, Any], documents: Mapping[str, Mapping[str, Any]]
                          ) -> dict[str, tuple[dict[str, Any], ...]]:
    """Audited lead-severity records from finding-lead packages that proposed each claim."""
    found: dict[str, tuple[dict[str, Any], ...]] = {}
    for claim_id, package_ids in sorted(merged.get("proposal_packages", {}).items()):
        records: dict[str, dict[str, Any]] = {}
        for package_id in sorted(package_ids):
            document = documents.get(package_id) or {}
            if document.get("kind") != "finding_lead":
                continue
            for lead in document.get("lead_menu", ()):
                record = lead.get("severity_record")
                if isinstance(record, Mapping):
                    records[str(lead["observation_id"])] = {
                        "observation_id": str(lead["observation_id"]), "severity_record": dict(record)}
        if records:
            found[claim_id] = tuple(records[key] for key in sorted(records))
    return found


def score_claims(adjudications: Sequence[Mapping[str, Any]], projection: Projection,
                 cwe_impact_overrides: Mapping[str, Any], out_dir: Path, ledger_path: Path, stream: str,
                 schemas: SchemaSet, references: Mapping[str, Mapping[str, Any]] | None = None, *,
                 scoring: Any | None = None, evidence: EvidenceSource | None = None,
                 cwe_catalog: ImpactCatalog | None = None) -> dict[str, Any]:
    """Score every confirmed or supported claim with every registered provider.

    ``scoring`` is the job's ``ScoringSettings``; it selects the enabled provider implementations and
    their models (without it, ``application_risk_matrix`` runs at its default implementation and
    model with ``cwe_impact_overrides``). ``cwe_catalog`` is the run's pinned MITRE CWE catalog,
    from which ``impact_class`` is derived (decision 11); without it the factor is missing unless
    overridden. Each provider receives exactly the ``score-factors/1`` factors it declares,
    extracted from the claim's counted supporting relations; ``evidence`` re-resolves their cited
    entities and supplies accepted tags, and without it payload- and tag-derived factors are
    missing with a reason. FIRST EPSS from ``references`` is dropped here: it is never a scoring
    input.
    """
    overrides = scoring.cwe_impact_overrides if scoring is not None else cwe_impact_overrides
    registry = (registry_from_settings(scoring, cwe_catalog) if scoring is not None
                else default_registry(overrides, catalog=cwe_catalog))
    factor_registry = default_factor_registry(overrides, cwe_catalog)
    writer = LedgerWriter(ledger_path, stream)
    scores: list[dict[str, Any]] = []
    # An enabled provider that cannot run is a named gap, once per run, and is published below.
    for missing_provider in registry.unavailable:
        writer.record_gap(make_gap(GapClass.SCORE_GAP, f"provider:{missing_provider.provider}",
                                   missing_provider.reason))
    for record in adjudications:
        state = ClaimState(record["state"])
        if state not in (ClaimState.CONFIRMED, ClaimState.SUPPORTED):
            continue
        claim = projection.claims[record["claim_id"]].claim
        supporting = sorted({relation for item in record["predicates"] for relation in item["supporting"]})
        reference = (references or {}).get(claim.claim_id) or {}
        data = factor_input(claim_id=claim.claim_id, adjudication_id=record["adjudication_id"], claim_state=state,
                            weakness_cwe=claim.weakness_cwe, affected_entities=claim.affected_entities,
                            predicates=record["predicates"], relations=projection.relations.get(claim.claim_id, ()),
                            source=evidence, kev_listed=reference.get("kev_listed"))
        for provider_id in registry.ids():
            provider = registry.get(provider_id)
            wanted = consumed_factors(provider)
            request = ScoreRequest(
                claim_id=claim.claim_id, adjudication_id=record["adjudication_id"], claim_state=state,
                weakness_cwe=claim.weakness_cwe, evidence_relation_ids=tuple(supporting), environment_sha256=None,
                policy_sha256=record["policy_sha256"], scorer_actor_id=scorer_actor(provider.implementation_version),
                reference_cvss=tuple(dict(item) for item in reference.get("reference_cvss", ())),
                kev_listed=reference.get("kev_listed"),
                factors=factor_registry.extract(data, wanted) if wanted else None)
            outcome = registry.score(provider_id, request)
            if isinstance(outcome, Gap):
                writer.record_gap(outcome)
                continue
            package = score_package_json(outcome)
            schemas.validate("score-package", package)
            path = Path(out_dir) / f"{package['score_id']}.json"
            atomic_bytes(path, canonical_json(package))
            severity = package["technical_severity"]
            scores.append({"score_id": package["score_id"], "claim_id": claim.claim_id, "sha256": file_sha256(path),
                           "file": path.name, "provider": outcome.implementation_version,
                           "band": package["native"].get("rating"), "missing_factors": package["missing_factors"],
                           "technical_severity": severity["rating"] if severity else None,
                           "severity_assessment": package["severity_assessment"]})
    receipt = writer.seal()
    implementations = sorted(registry.get(item).implementation_version for item in registry.ids())
    catalog = cwe_catalog if cwe_catalog is not None else UNAVAILABLE_CATALOG
    return {"schema": "appsec-review/inference-review-scores/3", "providers": implementations,
            "unavailable_providers": [item.record() for item in registry.unavailable],
            "impact_class": {"rule": DERIVATION_RULE, "catalog": catalog.identity()},
            "scores": sorted(scores, key=lambda item: item["score_id"]),
            "ledger_shard": {"events": receipt.event_count, "sha256": file_sha256(ledger_path)}}


# ------------------------------------------------------------------------------------------------
# completeness.audit


def coverage_matrix(hunt_lane: Mapping[str, Any], units: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Lane B unit x strategy x persona coverage; a lane B cell is never a clean verdict."""
    rows = [dict(row) for row in hunt_lane.get("coverage", ())]
    for unit in units:
        if not unit.get("hunted"):
            rows.append({"unit_key": unit["unit_key"], "package_id": None, "strategy": None, "persona": None,
                         "status": "gap", "cell_id": None, "reason": "below_hunt_cutoff"})
    rows.sort(key=lambda row: (str(row["unit_key"]), str(row["package_id"]), str(row["strategy"]),
                               str(row["persona"]), str(row["cell_id"])))
    summary: dict[str, int] = defaultdict(int)
    for row in rows:
        summary[row["status"]] += 1
    return {"schema": COVERAGE_SCHEMA, "rows": rows, "summary": dict(sorted(summary.items())),
            "statement": "lane B reports which lenses reviewed each unit; it never concludes a unit is free of defects"}


def completeness_gaps(units: Iterable[Mapping[str, Any]], scope_gaps: Iterable[Mapping[str, Any]],
                      cwe_reference: Mapping[str, Any] | None = None,
                      admission: Iterable[Mapping[str, Any]] = ()) -> list[Gap]:
    gaps = [make_gap(GapClass.COVERAGE_GAP, str(unit["unit_key"]), "below_hunt_cutoff")
            for unit in units if not unit.get("hunted")]
    gaps.extend(make_gap(GapClass.COVERAGE_GAP, f"producer:{gap['producer']}:{gap['scope']}",
                         f"{gap['state']}: {gap['reason']}") for gap in scope_gaps)
    gaps.extend(make_gap(GapClass.COVERAGE_GAP, str(item["lead_id"]),
                         f"lead_not_admitted:{item['residual_coverage']}")
                for item in admission if item["status"] == "not_admitted")
    if cwe_reference and cwe_reference.get("gap"):
        # Claim CWEs were validated against the narrower rule/crosswalk set; never silently.
        gaps.append(make_gap(GapClass.COVERAGE_GAP, "reference:mitre_cwe",
                             f"{cwe_reference['gap']}; claim CWE validation fell back to "
                             f"{cwe_reference.get('accepted_count', 0)} rule/crosswalk CWE ids"))
    return sorted({gap.gap_id: gap for gap in gaps}.values(), key=lambda gap: gap.gap_id)


def audit(lanes: Sequence[Mapping[str, Any]], shard_paths: Sequence[Path], incomplete_gap_ratio: float
          ) -> tuple[Accounting, Projection, MergedLedger]:
    merged = merge_verified(shard_paths)
    projection = project(merged.events)
    expected_cells = {cell_id: Lane(lane) for item in lanes for cell_id, lane in item["expected_cells"].items()}
    expected_packages = {package_id: Lane(lane) for item in lanes for package_id, lane in item["packages"].items()}
    lead_accounting = {package_id: leads for item in lanes
                       for package_id, leads in (item.get("lead_accounting") or {}).items()}
    accounting = exact_accounting(projection, expected_cells, expected_packages,
                                  incomplete_gap_ratio=incomplete_gap_ratio, lead_accounting=lead_accounting)
    return accounting, projection, merged


# ------------------------------------------------------------------------------------------------
# publication


def handoff_status(accounting: Accounting) -> str:
    if accounting.outcome is PoolOutcome.COMPLETE:
        return "COMPLETE"
    if accounting.outcome is PoolOutcome.EMPTY:
        return "EMPTY"
    return "DEGRADED"


def _ship_block_inputs(state: ClaimState, claim_scores: Sequence[Mapping[str, Any]],
                       references: Mapping[str, Any], lead_families: Sequence[str], model_distinct: bool
                       ) -> tuple[ShipBlockInputs, dict[str, Any]]:
    """The policy inputs of one finding and its displayed (never deciding) context."""
    deciding = sorted((item for item in claim_scores if item["provider"] == ship_block.SEVERITY_PROVIDER),
                      key=lambda item: item["score_id"])
    severity = deciding[0] if deciding else None
    assessment = (severity or {}).get("severity_assessment") or {}
    inputs = ShipBlockInputs(
        claim_state=state, technical_severity=severity.get("technical_severity") if severity else None,
        severity_score_id=severity["score_id"] if severity else None, lead_families=tuple(lead_families),
        severity_missing_factors=tuple(sorted(assessment.get("unresolved_factors", ()))),
        severity_floor=assessment.get("severity_floor"), severity_ceiling=assessment.get("severity_ceiling"),
        kev_listed=references.get("kev_listed"), verifier_model_distinct=bool(model_distinct))
    displayed = {
        "reference_cvss": [dict(item) for item in references.get("reference_cvss", ())][:8],
        "non_deciding_scores": sorted(item["score_id"] for item in claim_scores
                                      if item["provider"] != ship_block.SEVERITY_PROVIDER)[:16],
    }
    return inputs, displayed


def finding_judge(verdicts: Sequence[JudgeVerdict]) -> dict[str, Any] | None:
    """The ``judge_verdict`` of a finding package, from the claim\'s judge verdicts in the ledger.

    ``verdict`` is the judges\' unanimous outcome and ``unresolved`` when they differ. ``disagrees_with_state`` is set
    when the judge sided against the published finding (blue correct, or neither side correct); the package then
    shows that disagreement beside its state. The verdict never changes the state.
    """
    if not verdicts:
        return None
    ordered = sorted(verdicts, key=lambda item: item.verdict_id)
    outcomes = {item.verdict for item in ordered}
    overall = next(iter(outcomes)) if len(outcomes) == 1 else JudgeVerdictValue.UNRESOLVED
    return {"verdict": overall.value,
            "disagrees_with_state": overall in (JudgeVerdictValue.BLUE_CORRECT, JudgeVerdictValue.NEITHER),
            "judges": [{"verdict_id": item.verdict_id, "verdict": item.verdict.value, "cell_id": item.cell_id,
                        "judge_model_distinct": item.judge_model_distinct, "reason": item.reason[:2000]}
                       for item in ordered[:8]]}


def finding_packages(projection: Projection, adjudications: Sequence[Mapping[str, Any]],
                     merged: Mapping[str, Any], scores: Sequence[Mapping[str, Any]], *, manifest_sha256: str,
                     out_dir: Path, schemas: SchemaSet, references: Mapping[str, Mapping[str, Any]] | None = None,
                     lead_families: Mapping[str, Sequence[str]] | None = None,
                     lead_severities: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
                     ship_block_settings: ShipBlockSettings = ShipBlockSettings(),
                     require_distinct_model: bool = True) -> list[dict[str, Any]]:
    """Confirmed and supported claims only; supported is labelled not independently confirmed.

    Each package carries its ``ship-block-policy/1`` decision with the inputs and citations that
    decided it. ``references`` and ``lead_families`` are :func:`claim_references` and
    :func:`claim_lead_families`; without them no finding is a KEV-listed dependency finding.
    """
    by_claim_scores: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for score in scores:
        by_claim_scores[score["claim_id"]].append(score)
    claim_gaps: dict[str, list[str]] = defaultdict(list)
    for gap in projection.gaps:
        claim_gaps[gap.subject_id].append(gap.gap_id)
    written = []
    for record in adjudications:
        state = ClaimState(record["state"])
        if state not in (ClaimState.CONFIRMED, ClaimState.SUPPORTED):
            continue
        claim = projection.claims[record["claim_id"]].claim
        verifiers = merged["independence"].get(claim.claim_id, [])
        independent = [item for item in verifiers if item["independent"]]
        reviewed = independent or [item for item in verifiers if item.get("review_id")]
        # Decision 2 is judged on the verifiers that count: the independent ones when any exist.
        model_distinct = any(item.get("verifier_model_distinct", False) for item in (independent or verifiers))
        supporting = sorted({relation for item in record["predicates"] for relation in item["supporting"]})
        analyst = sorted(relation.relation_id for relation in projection.relations.get(claim.claim_id, ())
                         if relation.kind is RelationKind.SUPPORTS and relation.complete
                         and relation.admissibility is Admissibility.ANALYST_ASSESSED)
        missing = sorted(item["predicate"] for item in record["predicates"]
                         if item["required"] and item["outcome"] != "satisfied")
        review_id = reviewed[0]["review_id"] if reviewed else None
        claim_scores = by_claim_scores.get(claim.claim_id, ())
        inputs, displayed = _ship_block_inputs(state, claim_scores,
                                               (references or {}).get(claim.claim_id) or {},
                                               (lead_families or {}).get(claim.claim_id, ()), model_distinct)
        decision = ship_block.decide(inputs, ship_block_settings, require_distinct_model=require_distinct_model)
        judged = projection.judge_verdicts.get(claim.claim_id, ())
        judge = finding_judge(judged)
        body = {
            "schema": FINDING_SCHEMA, "claim_id": claim.claim_id, "lane": claim.lane.value, "state": state.value,
            "label": "confirmed" if state is ClaimState.CONFIRMED else "not_independently_confirmed",
            "title": f"{claim.security_predicate} ({claim.weakness_cwe or 'unmapped weakness'})"[:200],
            "adjudication_id": record["adjudication_id"], "direct_evidence": supporting[:256],
            "analyst_assessed_evidence": analyst[:256],
            "missing_predicates": missing,
            "verification_review_id": review_id,
            "scores": sorted(item["score_id"] for item in claim_scores)[:16], "poc": None, "attack_chains": [],
            "remediation_inputs": {"safe_regression_artifact": None},
            "independence": {"independent": bool(independent),
                             "provider_distinct": any(item["provider_distinct"] for item in verifiers),
                             "verifier_model_distinct": model_distinct,
                             "judge_model_distinct": all(item.judge_model_distinct for item in judged) if judged else None},
            "judge_verdict": judge,
            "lead_severities": [dict(item) for item in (lead_severities or {}).get(claim.claim_id, ())],
            "ship_block": decision.record(inputs, adjudication_id=record["adjudication_id"],
                                          verification_review_id=review_id, displayed_context=displayed),
            "gaps": sorted(set(claim_gaps.get(claim.claim_id, ())) | set(record["gap_ids"]))[:256],
            "provenance": {"run_manifest_sha256": manifest_sha256, "ledger_head_sha256": projection.head},
        }
        package = {**body, "finding_package_id": make_id("finding_package", 1, body)}
        schemas.validate("finding-package", package)
        path = Path(out_dir) / f"{package['finding_package_id']}.json"
        atomic_bytes(path, canonical_json(package))
        written.append({"finding_package_id": package["finding_package_id"], "sha256": file_sha256(path),
                        "claim_id": claim.claim_id, "state": state.value, "lane": claim.lane.value,
                        "ship_block_status": decision.status.value, "missing_predicates": missing,
                        "gaps": package["gaps"], "file": path.name,
                        # Inputs of poc_candidates; not part of the handoff\'s finding_packages list.
                        "judge_verdict": judge["verdict"] if judge else None,
                        "technical_severity": inputs.technical_severity, "direct_evidence": list(supporting[:256])})
    return sorted(written, key=lambda item: item["finding_package_id"])


def poc_candidates(findings: Sequence[Mapping[str, Any]], briefs: Iterable[Mapping[str, Any]],
                   settings: PocCandidateSettings) -> list[dict[str, Any]]:
    """Claims a later job may build a proof-of-concept function for (review-judge-and-poc.md section 4).

    A claim is listed when **all** of these hold: its R5 state is ``supported`` or ``confirmed`` (it has a finding
    package); the judge said ``red_correct`` (``partly`` too when ``settings.accept_partly``); one of its red cells
    gave a ``poc_basis`` whose ``entry`` and ``path`` resolved (non-empty after label resolution); and its risk-matrix
    technical severity is one of ``settings.risk_ratings``. Nothing else about the claim is copied.
    """
    accepted = {JudgeVerdictValue.RED_CORRECT.value} | (
        {JudgeVerdictValue.PARTLY.value} if settings.accept_partly else set())
    by_claim: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for brief in briefs:
        basis = brief.get("poc_basis") or {}
        if basis.get("entry") and basis.get("path"):
            by_claim[str(brief["claim_id"])].append(brief)
    found = []
    for finding in sorted(findings, key=lambda item: item["claim_id"]):
        claim_id = finding["claim_id"]
        if (finding["state"] not in (ClaimState.CONFIRMED.value, ClaimState.SUPPORTED.value)
                or finding.get("judge_verdict") not in accepted
                or finding.get("technical_severity") not in settings.risk_ratings
                or claim_id not in by_claim):
            continue
        brief = min(by_claim[claim_id], key=lambda item: (str(item["cell_id"]), str(item["package_id"])))
        found.append({"claim_id": claim_id, "package_id": brief["package_id"], "state": finding["state"],
                      "judge_verdict": finding["judge_verdict"],
                      "poc_basis": {"sha256": sha256_hex(brief["poc_basis"]), "brief": dict(brief["poc_basis"])},
                      "finding_package": {"finding_package_id": finding["finding_package_id"],
                                          "sha256": finding["sha256"]},
                      "evidence_refs": list(finding["direct_evidence"])})
    return found


def remediation_partition(findings: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Decision 4: ``(remediation_intake, verification_backlog)``.

    Only ``confirmed`` finding packages enter remediation intake; ``supported`` packages form the
    separate verification backlog, labelled ``unconfirmed`` with their missing predicates and gaps.
    """
    intake, backlog = [], []
    for item in sorted(findings, key=lambda value: value["finding_package_id"]):
        entry = {"finding_package_id": item["finding_package_id"], "sha256": item["sha256"],
                 "claim_id": item["claim_id"], "lane": item["lane"], "ship_block_status": item["ship_block_status"]}
        if item["state"] == ClaimState.CONFIRMED.value:
            intake.append(entry)
        elif item["state"] == ClaimState.SUPPORTED.value:
            backlog.append({**entry, "label": "unconfirmed", "missing_predicates": list(item["missing_predicates"]),
                            "gap_ids": list(item["gaps"])})
        else:
            raise IntegrityError(f"finding package has an unpublishable state: {item['state']}")
    return intake, backlog


def build_handoff(*, run_id: str, manifest_sha256: str, configuration_sha256: str, projection: Projection,
                  accounting: Accounting, shards: Sequence[Mapping[str, Any]], findings: Sequence[Mapping[str, Any]],
                  scores: Sequence[Mapping[str, Any]], package_manifest_sha256: str,
                  coverage: Mapping[str, Any], possible: Sequence[Sequence[str]], schemas: SchemaSet,
                  ship_block_policy_sha256: str, verification: Mapping[str, Any],
                  lead_severity_triage: Mapping[str, Any] | None = None,
                  poc_candidate_list: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    if not accounting.exact:
        reasons = ", ".join(sorted({gap.reason for gap in accounting.violations}))
        raise IntegrityError(f"publication_error: claim accounting is not exact ({reasons})")
    intake, backlog = remediation_partition(findings)
    handoff = {
        "schema": HANDOFF_SCHEMA, "run_id": run_id, "accepted_manifest_sha256": manifest_sha256,
        "configuration_sha256": configuration_sha256, "status": handoff_status(accounting),
        "ledger_head_sha256": projection.head, "projection_sha256": projection.sha256(),
        "accounting": accounting.to_json(), "shards": [dict(item) for item in shards],
        "finding_packages": [{"finding_package_id": item["finding_package_id"], "sha256": item["sha256"]}
                             for item in findings],
        "remediation_intake": intake, "verification_backlog": backlog,
        "ship_block": {**ship_block.summarize({"lane": item["lane"], "status": item["ship_block_status"]}
                                              for item in findings),
                       "policy_sha256": ship_block_policy_sha256},
        "verification": dict(verification),
        "lead_severity_triage": dict(lead_severity_triage) if lead_severity_triage is not None else None,
        "planned_consumers": [dict(item) for item in PLANNED_CONSUMERS],
        "score_packages": [{"score_id": item["score_id"], "sha256": item["sha256"]} for item in scores],
        "gap_ids": [gap.gap_id for gap in projection.gaps],
        "package_manifest_sha256": package_manifest_sha256, "coverage_matrix": dict(coverage),
        "possible_duplicates": [list(pair) for pair in possible],
        "poc_candidates": [dict(item) for item in poc_candidate_list],
    }
    errors = schemas.errors("handoff", handoff)
    if errors:
        raise IntegrityError(f"publication_error: handoff does not satisfy its schema: {'; '.join(errors[:3])}")
    return handoff


def shard_records(run_root: Path, paths: Sequence[Path]) -> list[dict[str, Any]]:
    records = []
    for path in sorted(paths, key=lambda item: item.as_posix()):
        rows = sum(1 for _ in Path(path).read_bytes().splitlines())
        records.append({"path": Path(path).resolve().relative_to(Path(run_root).resolve()).as_posix(),
                        "schema": EVENT_SCHEMA, "sha256": file_sha256(path), "rows": rows})
    return records


def write_ledger(merged: MergedLedger, projection: Projection, out_dir: Path) -> dict[str, Any]:
    ledger = Path(out_dir) / "claim-ledger.jsonl"
    atomic_bytes(ledger, b"".join(canonical_json(event) for event in merged.events))
    projection_path = Path(out_dir) / "projection.json"
    atomic_bytes(projection_path, canonical_json(projection.to_json()))
    head = {"schema": "appsec-review/claim-ledger-head/1", "ledger_head_sha256": merged.head,
            "projection_sha256": projection.sha256(), "streams": list(merged.streams),
            "events": len(merged.events), "ledger_sha256": file_sha256(ledger),
            "projection_file_sha256": file_sha256(projection_path)}
    atomic_json(Path(out_dir) / "ledger-head.json", head)
    return head


def verify_receipts(projection: Projection, receipts_root: Path) -> int:
    """Every terminal cell record that names a receipt must match the receipt bytes on disk."""
    checked = 0
    for cell_id, records in projection.cells.items():
        for record in records:
            if record.receipt_sha256 is None:
                if record.attempts != 0:              # only never-attempted cells may lack a receipt
                    raise IntegrityError(f"cell record without a receipt: {cell_id}")
                continue
            path = Path(receipts_root) / cell_id / f"attempt-{record.attempts}.json"
            if not path.is_file() or file_sha256(path) != record.receipt_sha256:
                raise IntegrityError(f"cell receipt cannot be verified: {cell_id}")
            checked += 1
    return checked


__all__ = ["apply_policy", "audit", "build_handoff", "claim_lead_families", "claim_lead_severities", "claim_references", "coverage_matrix",
           "completeness_gaps", "finding_judge", "finding_packages", "merge_claims", "poc_candidates", "merge_verified", "remediation_partition",
           "score_claims", "scorer_actor", "shard_records", "verify_receipts", "write_ledger"]
