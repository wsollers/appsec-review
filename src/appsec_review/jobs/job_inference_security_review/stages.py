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

from appsec_review.review import adjudication as r5
from appsec_review.review.accounting import Accounting, PoolOutcome, exact_accounting
from appsec_review.review.adjudication import Adjudication, adjudicate
from appsec_review.review.claims import possible_duplicates
from appsec_review.review.identity import make_id
from appsec_review.review.ledger import (
    EVENT_SCHEMA, LedgerWriter, MergedLedger, Projection, gap_from_json, merge_shards, project,
)
from appsec_review.review.models import (
    ClaimState, Gap, GapClass, IntegrityError, Lane, make_gap,
)
from appsec_review.review.scoring import default_registry
from appsec_review.review.scoring.interface import ScoreProviderResult, ScoreRequest
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256

from .schemas import SchemaSet

HANDOFF_SCHEMA = "appsec-review/inference-review-handoff/1"
FINDING_SCHEMA = "appsec-review/finding-package/1"
COVERAGE_SCHEMA = "appsec-review/inference-review-coverage-matrix/1"
SCORER_ACTOR = make_id("actor", 1, {"role": "independent_scorer", "provider": "application_risk_matrix/1"})
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
        "possible_duplicates": [list(pair) for pair in possible_duplicates(claims)],
    }


# ------------------------------------------------------------------------------------------------
# adjudicate.apply_policy


def adjudication_json(item: Adjudication) -> dict[str, Any]:
    return {"adjudication_id": item.adjudication_id, "claim_id": item.claim_id, "round": 0,
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
        verifiers = merged["independence"].get(claim_id, [])
        independent = any(item["independent"] for item in verifiers)
        verifier_gap = None
        if not independent and merged["verifier_gaps"].get(claim_id):
            verifier_gap = gap_from_json(merged["verifier_gaps"][claim_id][0])
        decision = adjudicate(view.claim, projection.relations.get(claim_id, ()), independent,
                              merged["scope_entities"].get(claim_id, ()), adjudicated, view.claim.state,
                              verifier_gap=verifier_gap)
        adjudicated.append(claim_id)
        records.append(adjudication_json(decision))
        state = ClaimState.PROPOSED
        for target in TRANSITION_PATHS.get(decision.state, (decision.state,)):
            writer.transition(claim_id, state, target, reason=f"{r5.RULES_VERSION}:{decision.deciding_row.value}",
                              adjudication_id=decision.adjudication_id)
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


def score_package_json(result: ScoreProviderResult) -> dict[str, Any]:
    native = dict(result.native)
    rendered: dict[str, Any] = {"nomenclature": str(native.get("matrix", result.implementation_version))}
    if native.get("band"):
        rendered["rating"] = str(native["band"])
    if native.get("cell"):
        rendered["matrix_cell"] = [str(item) for item in native["cell"]]

    def dimension(value) -> dict[str, Any] | None:
        return None if value is None else {"scale": value.scale, "rating": value.rating, "value": value.value}

    return {"schema": result.schema, "score_id": result.score_id, "claim_id": result.claim_id,
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
            "evidence_relations": list(result.evidence_relations), "factor_citations": [],
            "limitations": ["application_risk_matrix/1 rates impact from a configured CWE table only; it is not "
                            "a CVSS score and does not assess environment or business impact"],
            "scorer": result.scorer_actor_id, "input_fingerprint": result.input_fingerprint,
            "overrides": [dict(item) for item in result.overrides]}


def score_claims(adjudications: Sequence[Mapping[str, Any]], projection: Projection,
                 cwe_impact_classes: Mapping[str, str], out_dir: Path, ledger_path: Path, stream: str,
                 schemas: SchemaSet) -> dict[str, Any]:
    registry = default_registry(cwe_impact_classes)
    writer = LedgerWriter(ledger_path, stream)
    scores: list[dict[str, Any]] = []
    for record in adjudications:
        state = ClaimState(record["state"])
        if state not in (ClaimState.CONFIRMED, ClaimState.SUPPORTED):
            continue
        claim = projection.claims[record["claim_id"]].claim
        supporting = sorted({relation for item in record["predicates"] for relation in item["supporting"]})
        request = ScoreRequest(claim_id=claim.claim_id, adjudication_id=record["adjudication_id"], claim_state=state,
                               weakness_cwe=claim.weakness_cwe, evidence_relation_ids=tuple(supporting),
                               environment_sha256=None, policy_sha256=record["policy_sha256"],
                               scorer_actor_id=SCORER_ACTOR)
        outcome = registry.score("application_risk_matrix", request)
        if isinstance(outcome, Gap):
            writer.record_gap(outcome)
            continue
        package = score_package_json(outcome)
        schemas.validate("score-package", package)
        path = Path(out_dir) / f"{package['score_id']}.json"
        atomic_bytes(path, canonical_json(package))
        scores.append({"score_id": package["score_id"], "claim_id": claim.claim_id, "sha256": file_sha256(path),
                       "file": path.name, "band": package["native"].get("rating"),
                       "missing_factors": package["missing_factors"]})
    receipt = writer.seal()
    return {"schema": "appsec-review/inference-review-scores/1", "provider": "application_risk_matrix/1",
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


def completeness_gaps(units: Iterable[Mapping[str, Any]], scope_gaps: Iterable[Mapping[str, Any]]) -> list[Gap]:
    gaps = [make_gap(GapClass.COVERAGE_GAP, str(unit["unit_key"]), "below_hunt_cutoff")
            for unit in units if not unit.get("hunted")]
    gaps.extend(make_gap(GapClass.COVERAGE_GAP, f"producer:{gap['producer']}:{gap['scope']}",
                         f"{gap['state']}: {gap['reason']}") for gap in scope_gaps)
    return sorted({gap.gap_id: gap for gap in gaps}.values(), key=lambda gap: gap.gap_id)


def audit(lanes: Sequence[Mapping[str, Any]], shard_paths: Sequence[Path], incomplete_gap_ratio: float
          ) -> tuple[Accounting, Projection, MergedLedger]:
    merged = merge_verified(shard_paths)
    projection = project(merged.events)
    expected_cells = {cell_id: Lane(lane) for item in lanes for cell_id, lane in item["expected_cells"].items()}
    expected_packages = {package_id: Lane(lane) for item in lanes for package_id, lane in item["packages"].items()}
    accounting = exact_accounting(projection, expected_cells, expected_packages,
                                  incomplete_gap_ratio=incomplete_gap_ratio)
    return accounting, projection, merged


# ------------------------------------------------------------------------------------------------
# publication


def handoff_status(accounting: Accounting) -> str:
    if accounting.outcome is PoolOutcome.COMPLETE:
        return "COMPLETE"
    if accounting.outcome is PoolOutcome.EMPTY:
        return "EMPTY"
    return "DEGRADED"


def finding_packages(projection: Projection, adjudications: Sequence[Mapping[str, Any]],
                     merged: Mapping[str, Any], scores: Sequence[Mapping[str, Any]], *, manifest_sha256: str,
                     out_dir: Path, schemas: SchemaSet) -> list[dict[str, Any]]:
    """Confirmed and supported claims only; supported is labelled not independently confirmed."""
    by_claim_scores: dict[str, list[str]] = defaultdict(list)
    for score in scores:
        by_claim_scores[score["claim_id"]].append(score["score_id"])
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
        supporting = sorted({relation for item in record["predicates"] for relation in item["supporting"]})
        body = {
            "schema": FINDING_SCHEMA, "claim_id": claim.claim_id, "state": state.value,
            "label": "confirmed" if state is ClaimState.CONFIRMED else "not_independently_confirmed",
            "title": f"{claim.security_predicate} ({claim.weakness_cwe or 'unmapped weakness'})"[:200],
            "adjudication_id": record["adjudication_id"], "direct_evidence": supporting[:256],
            "verification_review_id": reviewed[0]["review_id"] if reviewed else None,
            "scores": sorted(by_claim_scores.get(claim.claim_id, ()))[:16], "poc": None, "attack_chains": [],
            "remediation_inputs": {"safe_regression_artifact": None},
            "independence": {"independent": bool(independent),
                             "provider_distinct": any(item["provider_distinct"] for item in verifiers)},
            "gaps": sorted(set(claim_gaps.get(claim.claim_id, ())) | set(record["gap_ids"]))[:256],
            "provenance": {"run_manifest_sha256": manifest_sha256, "ledger_head_sha256": projection.head},
        }
        package = {**body, "finding_package_id": make_id("finding_package", 1, body)}
        schemas.validate("finding-package", package)
        path = Path(out_dir) / f"{package['finding_package_id']}.json"
        atomic_bytes(path, canonical_json(package))
        written.append({"finding_package_id": package["finding_package_id"], "sha256": file_sha256(path),
                        "claim_id": claim.claim_id, "state": state.value, "file": path.name})
    return sorted(written, key=lambda item: item["finding_package_id"])


def build_handoff(*, run_id: str, manifest_sha256: str, configuration_sha256: str, projection: Projection,
                  accounting: Accounting, shards: Sequence[Mapping[str, Any]], findings: Sequence[Mapping[str, Any]],
                  scores: Sequence[Mapping[str, Any]], package_manifest_sha256: str,
                  coverage: Mapping[str, Any], possible: Sequence[Sequence[str]], schemas: SchemaSet) -> dict[str, Any]:
    if not accounting.exact:
        reasons = ", ".join(sorted({gap.reason for gap in accounting.violations}))
        raise IntegrityError(f"publication_error: claim accounting is not exact ({reasons})")
    handoff = {
        "schema": HANDOFF_SCHEMA, "run_id": run_id, "accepted_manifest_sha256": manifest_sha256,
        "configuration_sha256": configuration_sha256, "status": handoff_status(accounting),
        "ledger_head_sha256": projection.head, "projection_sha256": projection.sha256(),
        "accounting": accounting.to_json(), "shards": [dict(item) for item in shards],
        "finding_packages": [{"finding_package_id": item["finding_package_id"], "sha256": item["sha256"]}
                             for item in findings],
        "score_packages": [{"score_id": item["score_id"], "sha256": item["sha256"]} for item in scores],
        "gap_ids": [gap.gap_id for gap in projection.gaps],
        "package_manifest_sha256": package_manifest_sha256, "coverage_matrix": dict(coverage),
        "possible_duplicates": [list(pair) for pair in possible],
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


__all__ = ["apply_policy", "audit", "build_handoff", "coverage_matrix", "completeness_gaps", "finding_packages",
           "merge_claims", "merge_verified", "score_claims", "shard_records", "verify_receipts", "write_ledger"]
