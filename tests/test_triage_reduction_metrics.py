"""The per-run ``triage_reduction`` metric over small, real, hash-bound review artifacts."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from appsec_review.observability import aggregate_run_metrics
from appsec_review.observability.triage_reduction import (
    DISMISSED_STATES, DISPOSITIONS, INTERPRETATION, SCOPE, TRIAGE_REDUCTION_SCHEMA, UNRESOLVED_REASONS,
    triage_reduction_metrics,
)
from appsec_review.review.lead_families import FAMILY_RULES
from appsec_review.review.models import IntegrityError
from appsec_review.review.neighborhood import NEIGHBORHOOD_RULE
from appsec_review.review.packages import (
    ASSEMBLY_RULE, MANIFEST_SCHEMA, OBLIGATION_RULE, PACKAGE_SCHEMA, Assembly, publish_packages, sha256_hex,
    verify_package_manifest,
)
from appsec_review.review.slicing.contract import SLICE_RULE
from appsec_review.review.units import RANK_RULE
from appsec_review.storage import atomic_bytes, atomic_json, canonical_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from tests.review.test_packages_dataflow_bound import dataflow  # noqa: F401  (module-scoped fixture)

JOB = "job_inference_security_review"
RUN_ID = "2026-10-12-0001"
ATTEMPT = Path("data") / "jobs" / JOB / "attempts" / "attempt_0001"


@dataclass
class Lead:
    lead_id: str
    family: str = "sast"
    scanner: str = "semgrep"
    admitted: bool = True
    residual: str = "review_pending"
    outcome: str | None = None          # red outcome in the lane A document; None = no entry
    packaged: bool = True


@dataclass
class Claim:
    claim_id: str
    state: str
    lead: str | None = None             # lane A lead whose finding_lead package proposed it
    lane: str = "lead"
    duplicate_of: str | None = None
    proposed: bool = True               # listed in the lane document's ``proposals``
    via_cell: bool = False              # linked only through its origin cell's package


@dataclass
class Scenario:
    leads: list[Lead]
    claims: list[Claim] = field(default_factory=list)
    leads_by_outcome: dict[str, int] | None = None
    review_incomplete: bool = False
    omit: tuple[str, ...] = ()


def _write(path: Path, value: Any) -> dict[str, str]:
    atomic_json(path, value)
    return {"path": path.as_posix(), "sha256": file_sha256(path)}


def _write_fixture_manifest(assembly_dir: Path, scenario: Scenario) -> tuple[dict[str, str], str, Path]:
    """Publish minimal packages under a manifest that satisfies ``review-package-manifest.schema.json``.

    The package bodies carry only what the triage reader uses (``kind``, ``lane``, ``lead_menu``); the
    manifest carries every field the schema requires, so it passes ``verify_package_manifest`` exactly as an
    ``assemble_packages`` manifest does.
    """
    package_of: dict[str, str] = {}
    entries = []

    def publish(body: dict[str, Any], *, family: str | None, unit_key: str | None) -> str:
        package_id = f"{body['kind']}-{sha256_hex(body)}"
        path = assembly_dir / "packages" / f"{package_id}.json"
        atomic_bytes(path, canonical_json({**body, "package_id": package_id}))
        entries.append({"package_id": package_id, "kind": body["kind"], "lane": body["lane"], "lead_family": family,
                        "partition_key": family or "hunt", "unit_key": unit_key,
                        "lead_count": len(body["lead_menu"]), "sha256": file_sha256(path),
                        "bytes": path.stat().st_size, "unit_context_sha256": None})
        return package_id

    packaged = [lead for lead in scenario.leads if lead.admitted and lead.packaged]
    for lead in packaged:
        package_of[lead.lead_id] = publish(
            {"kind": "finding_lead", "lane": "lead", "lead_menu": [
                {"observation_id": lead.lead_id, "lead_family": lead.family, "scanner": lead.scanner}]},
            family=lead.family, unit_key=None)
    hunt_id = publish({"kind": "hunt", "lane": "hunt", "lead_menu": []}, family=None, unit_key="unit-1")

    def by_family(leads: list[Lead]) -> dict[str, dict[str, int]]:
        counts: dict[str, dict[str, int]] = {}
        for lead in leads:
            counts.setdefault(lead.family, {"high": 0})["high"] += 1
        return counts

    admitted = [lead for lead in scenario.leads if lead.admitted]
    families = sorted({lead.family for lead in scenario.leads})
    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA, "assembly_rule": ASSEMBLY_RULE, "package_schema": PACKAGE_SCHEMA,
        "run_id": RUN_ID, "manifest_sha256": "d" * 64, "target_snapshot": None,
        "settings": {"admit_severities": ["critical", "high"], "slice_strategies": []}, "graph_settings": {},
        "admission": [{"lead_id": lead.lead_id, "effective_severity": "high",
                       "status": "admitted" if lead.admitted else "not_admitted", "reasons": [],
                       "residual_coverage": "review_pending" if lead.admitted else lead.residual}
                      for lead in sorted(scenario.leads, key=lambda item: item.lead_id)],
        "rules": {"families": dict(FAMILY_RULES), "rank": RANK_RULE, "obligations": OBLIGATION_RULE,
                  "neighborhood": NEIGHBORHOOD_RULE, "slice": SLICE_RULE},
        # Manifest rows carry the source-disposition globs the scope was accepted under (T-165).
        "source_dispositions": {"rule": "appsec-review/source-disposition/1",
                                "vendored": [], "sdk": [], "generated": [], "test": []},
        "inputs": [], "evidence_map_sha256": sha256_hex({}),
        "packages": sorted(entries, key=lambda entry: entry["package_id"]),
        # Manifest v7 rows pin a hunt package's unit context; this fixture hunt body carries none (T-5000).
        "unit_contexts": [],
        "units": [{"unit_key": "unit-1", "position": 1, "unit_count": 1, "score": 1.0, "rule": RANK_RULE,
                   "basis": [], "hunted": True, "lead_count": 0, "package_ids": [hunt_id]}],
        "gaps": [], "cwe_reference": None,
        "counts": {"leads": by_family(scenario.leads), "admitted": by_family(admitted),
                   "kev_admitted": dict.fromkeys(families, 0),
                   "non_lead_observations": {"secret": 2, "config": 1},
                   "dispositions": {"rule": "appsec-review/source-disposition/1", "files": {}, "leads": {}},
                   "packages": {"finding_lead": len(packaged), "hunt": 1},
                   "units": {"total": 1, "hunted": 1, "below_cutoff": 0},
                   "neighborhood_bounds": {"call_depth": len(packaged), "dataflow_path": 0}},
        "audit": {"lane_a": {"status": "passed", "expected": len(packaged), "packaged": len(packaged),
                             "by_family": by_family(packaged), "suppressed": 0, "duplicates": 0, "kev_admitted": 0},
                  "lane_b": {"status": "passed", "listed_leads": 0},
                  "families_available": dict.fromkeys(families, True)},
    }
    manifest["content_sha256"] = sha256_hex(manifest)
    manifest_path = assembly_dir / "package-manifest.json"
    atomic_bytes(manifest_path, canonical_json(manifest))
    return package_of, hunt_id, manifest_path


def build_run(tmp_path: Path, scenario: Scenario, assembly: Assembly | None = None) -> Path:
    run_root = tmp_path / "runs" / RUN_ID
    attempt = run_root / ATTEMPT
    rel = lambda path: path.relative_to(run_root).as_posix()  # noqa: E731

    def ref(path: Path) -> dict[str, Any]:
        return {"path": rel(path), "sha256": file_sha256(path), "size_bytes": path.stat().st_size}

    assembly_dir = attempt / "steps" / "packages" / "tasks" / "assemble_lead_packages" / "assembly"
    if assembly is None:
        package_of, hunt_id, manifest_path = _write_fixture_manifest(assembly_dir, scenario)
    else:
        manifest_path = publish_packages(assembly, assembly_dir)
        package_of = {lead["observation_id"]: package.package_id for package in assembly.packages
                      if package.kind == "finding_lead" for lead in json.loads(package.body)["lead_menu"]}
        hunt_id = next((package.package_id for package in assembly.packages if package.kind == "hunt"), None)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    packages_doc = attempt / "steps" / "packages" / "tasks" / "assemble_lead_packages" / "lead-packages.json"
    atomic_json(packages_doc, {"schema": "appsec-review/inference-review-lane-packages/1", "lane": "lead",
                               "package_manifest": ref(manifest_path),
                               "package_manifest_content_sha256": manifest["content_sha256"],
                               "packages": [], "admission": manifest["admission"]})

    accounting: dict[str, dict[str, Any]] = {package: {} for package in package_of.values()}
    for lead in scenario.leads:
        if lead.lead_id in package_of and lead.outcome is not None:
            accounting[package_of[lead.lead_id]][lead.lead_id] = {"outcome": lead.outcome, "cells": {}}
    proposals = {claim.claim_id: [package_of[claim.lead]] for claim in scenario.claims
                 if claim.lead is not None and claim.proposed}
    lane_path = attempt / "steps" / "lead_review" / "tasks" / "teams" / "lane.json"
    atomic_json(lane_path, {"schema": "appsec-review/inference-review-lane/1", "lane": "lead",
                            "packages": {package: "lead" for package in package_of.values()},
                            "lead_accounting": accounting, "proposals": proposals})

    cells: dict[str, list[dict[str, Any]]] = {}
    claims = []
    for claim in scenario.claims:
        package = package_of[claim.lead] if claim.lead is not None else hunt_id
        origin = [f"cell-{claim.claim_id}"]
        cells[origin[0]] = [{"cell_id": origin[0], "package_id": package, "lane": claim.lane}]
        claims.append({"claim_id": claim.claim_id, "lane": claim.lane,
                       "package_id": "elsewhere" if claim.via_cell else package, "state": claim.state,
                       "duplicate_of": claim.duplicate_of, "origin_cell_ids": origin, "state_history": []})
    head = "a" * 64
    ledger_dir = attempt / "steps" / "publication" / "tasks" / "publish_claim_ledger"
    projection = {"schema": "appsec-review/claim-projection/1", "ledger_head_sha256": head,
                  "claims": sorted(claims, key=lambda item: item["claim_id"]), "cells": cells}
    projection_path = ledger_dir / "projection.json"
    atomic_bytes(projection_path, canonical_json(projection))
    receipt_path = ledger_dir / "ledger-head-receipt.json"
    atomic_json(receipt_path, {"schema": "appsec-review/claim-ledger-head/1", "ledger_head_sha256": head,
                               "projection_sha256": "b" * 64, "projection_file_sha256": file_sha256(projection_path),
                               "ledger_sha256": "c" * 64})

    observed = {outcome: 0 for outcome in ("proposal", "no_proposal", "blocked", "unaccounted")}
    for leads in accounting.values():
        for summary in leads.values():
            observed[summary["outcome"]] += 1
    review_path = attempt / "steps" / "publication" / "tasks" / "publish_handoff" / "review-handoff.json"
    atomic_json(review_path, {
        "schema": "appsec-review/inference-review-handoff/3", "run_id": RUN_ID,
        "lead_package_manifest_sha256": manifest["content_sha256"], "projection_sha256": "b" * 64,
        "ledger_head_sha256": head,
        "accounting": {"lanes": [
            {"lane": "lead", "leads_by_outcome": scenario.leads_by_outcome or observed,
             "review_incomplete": scenario.review_incomplete},
            {"lane": "hunt", "leads_by_outcome": dict.fromkeys(observed, 0), "review_incomplete": False}]}})

    outputs = {
        "packages.assemble_lead_packages": {"artifact": ref(packages_doc)},
        "lead_review.teams": {"artifact": ref(lane_path)},
        "publication.publish_claim_ledger": {"artifact": ref(receipt_path)},
        "publication.publish_handoff": {"schema": "appsec-review/inference-security-review/1",
                                        "artifact": ref(review_path)},
    }
    outputs = {unit: value for unit, value in outputs.items() if unit not in scenario.omit}
    handoff = run_root / ATTEMPT / "handoff.json"
    write_fixture_handoff(run_root, handoff, {"job_id": JOB, "attempt_id": "attempt_0001", "outputs": outputs,
                                              "source_fingerprint": "fixture-snapshot"})
    atomic_json(run_root / "data" / "jobs" / JOB / "latest.json",
                {"handoff_path": rel(handoff), "handoff_sha256": file_sha256(handoff)})
    return run_root


def mixed() -> Scenario:
    return Scenario(
        leads=[
            Lead("L1", outcome="proposal"),
            Lead("L2", outcome="proposal"),
            Lead("L3", family="sca", scanner="osv", outcome="proposal"),
            Lead("L4", family="sca", scanner="osv", outcome="no_proposal"),
            Lead("L5", scanner="codeql", outcome="proposal"),
            Lead("L6", outcome="proposal"),
            Lead("L7", scanner="codeql", outcome="blocked"),
            Lead("N1", admitted=False, residual="exploration_reserve_cutoff"),
            Lead("N2", admitted=False, residual="outside_admission_policy"),
            Lead("N3", admitted=False, residual="outside_admission_policy"),
        ],
        claims=[
            Claim("C1", "confirmed", lead="L1"),
            Claim("C2", "supported", lead="L2"),
            Claim("C3", "contradicted", lead="L3"),
            Claim("C5", "duplicate", lead="L5", duplicate_of="C1"),
            Claim("C6", "not_reachable", lead="L6", proposed=False, via_cell=True),
            Claim("H1", "supported", lane="hunt"),
            Claim("H2", "contradicted", lane="hunt"),
        ])


def test_mixed_dispositions_counts_ratios_and_breakdowns(tmp_path: Path) -> None:
    section = triage_reduction_metrics(build_run(tmp_path, mixed()))

    assert section["schema"] == TRIAGE_REDUCTION_SCHEMA and section["available"] is True
    assert section["scope"] == SCOPE and section["interpretation"] == INTERPRETATION
    assert section["leads"] == {"collected": 10, "admitted": 7, "not_admitted": 3,
                                "not_admitted_by_residual_coverage": {"exploration_reserve_cutoff": 1,
                                                                      "outside_admission_policy": 2},
                                "non_lead_observations": 3}
    # L5's duplicate resolves to C1 (confirmed); L6 links through its origin cell's package
    assert section["admitted_dispositions"] == {"survived_confirmed": 2, "survived_supported": 1,
                                                "dismissed_by_adjudication": 2, "no_claim_raised": 1,
                                                "unresolved": 1}
    assert section["dismissed_by_claim_state"] == {**dict.fromkeys(DISMISSED_STATES, 0),
                                                   "contradicted": 1, "not_reachable": 1}
    assert section["unresolved_by_reason"] == {**dict.fromkeys(UNRESOLVED_REASONS, 0), "blocked": 1}
    assert section["hunt_lane_claims_excluded"] == 2
    assert section["reduction"] == {"ratio_over_resolved": 0.5, "lower_bound_over_admitted": 0.428571,
                                    "resolved_denominator": 6, "admitted_denominator": 7}
    assert section["by_family"] == {
        "sast": {"admitted": 5, "survived_confirmed": 2, "survived_supported": 1, "dismissed_by_adjudication": 1,
                 "no_claim_raised": 0, "unresolved": 1},
        "sca": {"admitted": 2, "survived_confirmed": 0, "survived_supported": 0, "dismissed_by_adjudication": 1,
                "no_claim_raised": 1, "unresolved": 0}}
    assert list(section["by_scanner"]) == ["codeql", "osv", "semgrep"]
    assert section["by_scanner"]["codeql"] == {"admitted": 2, "survived_confirmed": 1, "survived_supported": 0,
                                               "dismissed_by_adjudication": 0, "no_claim_raised": 0,
                                               "unresolved": 1}
    assert section["review_incomplete"] is False
    assert section["integrity_gap_codes"] == []
    assert section["accounting_complete"] is False            # one blocked lead stays unresolved
    assert set(section["sources"]) == {"job_handoff", "review_handoff", "lead_packages", "lead_package_manifest",
                                       "lane_document", "claim_ledger_receipt", "claim_projection"}
    run_root = tmp_path / "runs" / RUN_ID
    for source in section["sources"].values():
        assert file_sha256(run_root / source["path"]) == source["sha256"]


def test_complete_accounting_and_no_proposal_is_its_own_bucket(tmp_path: Path) -> None:
    scenario = mixed()
    scenario.leads = [lead for lead in scenario.leads if lead.lead_id != "L7"]
    section = triage_reduction_metrics(build_run(tmp_path, scenario))

    assert section["admitted_dispositions"]["no_claim_raised"] == 1
    assert section["admitted_dispositions"]["dismissed_by_adjudication"] == 2
    assert sum(section["dismissed_by_claim_state"].values()) == 2    # the no-claim lead is not a dismissal
    assert section["reduction"]["ratio_over_resolved"] == section["reduction"]["lower_bound_over_admitted"] == 0.5
    assert section["accounting_complete"] is True and section["integrity_gap_codes"] == []


def test_unresolved_leads_are_never_reduced(tmp_path: Path) -> None:
    scenario = Scenario(
        leads=[Lead("L1", outcome="blocked"), Lead("L2", outcome="proposal"), Lead("L3", outcome="proposal"),
               Lead("L4", outcome="proposal"), Lead("L5", outcome="proposal"), Lead("L6", outcome="unaccounted")],
        claims=[Claim("C2", "insufficient_evidence", lead="L2"), Claim("C4", "proposed", lead="L4"),
                Claim("C5", "coverage_gap", lead="L5")])
    section = triage_reduction_metrics(build_run(tmp_path, scenario))

    assert section["admitted_dispositions"] == {**dict.fromkeys(DISPOSITIONS, 0), "unresolved": 6}
    assert section["unresolved_by_reason"] == {"blocked": 1, "unaccounted": 1, "insufficient_evidence": 1,
                                               "coverage_gap": 1, "claim_not_final": 1, "proposal_without_claim": 1}
    assert section["reduction"] == {"ratio_over_resolved": None, "lower_bound_over_admitted": 0.0,
                                    "resolved_denominator": 0, "admitted_denominator": 6}
    assert section["accounting_complete"] is False


def test_open_claim_outranks_a_dismissal_for_the_same_lead(tmp_path: Path) -> None:
    scenario = Scenario(leads=[Lead("L1", outcome="proposal")],
                        claims=[Claim("C1", "contradicted", lead="L1"), Claim("C2", "insufficient_evidence", lead="L1")])
    section = triage_reduction_metrics(build_run(tmp_path, scenario))

    assert section["admitted_dispositions"]["unresolved"] == 1
    assert section["unresolved_by_reason"]["insufficient_evidence"] == 1
    assert section["dismissed_by_claim_state"]["contradicted"] == 0


def test_unresolvable_duplicate_is_an_integrity_gap_not_a_dismissal(tmp_path: Path) -> None:
    scenario = Scenario(leads=[Lead("L1", outcome="proposal")],
                        claims=[Claim("C1", "duplicate", lead="L1", duplicate_of="missing")])
    section = triage_reduction_metrics(build_run(tmp_path, scenario))

    assert section["available"] is True
    assert section["admitted_dispositions"]["unresolved"] == 1
    assert section["unresolved_by_reason"]["claim_not_final"] == 1
    assert section["integrity_gap_codes"] == ["duplicate_unresolved"]
    assert section["accounting_complete"] is False


def test_zero_admitted_leads_give_null_ratios(tmp_path: Path) -> None:
    scenario = Scenario(leads=[Lead("N1", admitted=False, residual="outside_admission_policy")],
                        claims=[Claim("H1", "supported", lane="hunt")])
    section = triage_reduction_metrics(build_run(tmp_path, scenario))

    assert section["available"] is True
    assert section["leads"]["admitted"] == 0 and section["leads"]["not_admitted"] == 1
    assert section["admitted_dispositions"] == dict.fromkeys(DISPOSITIONS, 0)
    assert section["reduction"] == {"ratio_over_resolved": None, "lower_bound_over_admitted": None,
                                    "resolved_denominator": 0, "admitted_denominator": 0}
    assert section["hunt_lane_claims_excluded"] == 1
    assert section["by_family"] == {} and section["by_scanner"] == {}


def test_outcome_mismatch_missing_outcome_and_incomplete_review_are_named_gaps(tmp_path: Path) -> None:
    scenario = Scenario(leads=[Lead("L1", outcome="no_proposal"), Lead("L2", outcome=None)],
                        leads_by_outcome={"proposal": 0, "no_proposal": 2, "blocked": 0, "unaccounted": 0},
                        review_incomplete=True)
    section = triage_reduction_metrics(build_run(tmp_path, scenario))

    assert section["available"] is True
    assert section["integrity_gap_codes"] == ["lead_outcome_mismatch", "lead_outcome_missing", "review_incomplete"]
    assert section["admitted_dispositions"]["no_claim_raised"] == 1
    assert section["unresolved_by_reason"]["unaccounted"] == 1
    assert section["review_incomplete"] is True and section["accounting_complete"] is False


def test_unpackaged_admitted_lead_is_unlinked(tmp_path: Path) -> None:
    section = triage_reduction_metrics(build_run(tmp_path, Scenario(leads=[Lead("L1", packaged=False)])))

    assert section["integrity_gap_codes"] == ["lead_package_unlinked"]
    assert section["unresolved_by_reason"]["unaccounted"] == 1
    assert section["by_family"] == {"(unlinked)": {"admitted": 1, **dict.fromkeys(DISPOSITIONS, 0), "unresolved": 1}}


def _assert_unavailable(section: dict[str, Any], code: str) -> None:
    assert section["available"] is False and section["accounting_complete"] is False
    assert section["integrity_gap_codes"] == [code]
    assert section["leads"]["admitted"] is None and section["hunt_lane_claims_excluded"] is None
    assert set(section["admitted_dispositions"].values()) == {None}
    assert section["reduction"]["ratio_over_resolved"] is None and section["sources"] is None


def test_missing_review_handoff_is_unavailable_not_zero(tmp_path: Path) -> None:
    _assert_unavailable(triage_reduction_metrics(tmp_path), "review_handoff_unavailable")


@pytest.mark.parametrize(("unit", "code"), (
    ("lead_review.teams", "lane_document_unavailable"),
    ("packages.assemble_lead_packages", "lead_manifest_unavailable"),
    ("publication.publish_claim_ledger", "claim_projection_unavailable"),
))
def test_missing_bound_output_names_its_gap(tmp_path: Path, unit: str, code: str) -> None:
    _assert_unavailable(triage_reduction_metrics(build_run(tmp_path, Scenario(
        leads=[Lead("L1", outcome="no_proposal")], omit=(unit,)))), code)


def test_tampered_projection_is_unavailable(tmp_path: Path) -> None:
    run_root = build_run(tmp_path, mixed())
    path = next(run_root.rglob("projection.json"))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["claims"][0]["state"] = "contradicted"
    path.write_bytes(canonical_json(document))
    _assert_unavailable(triage_reduction_metrics(run_root), "claim_projection_unavailable")


def test_tampered_package_is_unavailable(tmp_path: Path) -> None:
    run_root = build_run(tmp_path, mixed())
    path = sorted((next(run_root.rglob("package-manifest.json")).parent / "packages").glob("finding_lead-*.json"))[0]
    document = json.loads(path.read_text(encoding="utf-8"))
    document["lead_menu"][0]["scanner"] = "bandit"
    path.write_bytes(canonical_json(document))
    _assert_unavailable(triage_reduction_metrics(run_root), "lead_manifest_unavailable")


def test_the_fixture_manifest_satisfies_the_manifest_schema_and_a_rehashed_violation_is_refused(
        tmp_path: Path) -> None:
    path = next(build_run(tmp_path, mixed()).rglob("package-manifest.json"))
    verify_package_manifest(path)

    document = json.loads(path.read_text(encoding="utf-8"))
    del document["audit"], document["content_sha256"]
    path.write_bytes(canonical_json({**document, "content_sha256": sha256_hex(document)}))
    with pytest.raises(IntegrityError, match="violates review-package-manifest.schema.json"):
        verify_package_manifest(path)


def test_a_real_assembled_manifest_passes_the_triage_reader(tmp_path: Path, dataflow) -> None:
    assembly = dataflow[3]
    packaged = {lead["observation_id"] for package in assembly.packages if package.kind == "finding_lead"
                for lead in json.loads(package.body)["lead_menu"]}
    rows = assembly.manifest["admission"]
    assert packaged and {row["lead_id"] for row in rows if row["status"] == "admitted"} == packaged
    scenario = Scenario(leads=[Lead(row["lead_id"], admitted=row["status"] == "admitted",
                                    residual=row["residual_coverage"],
                                    outcome="no_proposal" if row["lead_id"] in packaged else None)
                               for row in rows])
    section = triage_reduction_metrics(build_run(tmp_path, scenario, assembly))

    assert section["available"] is True and section["integrity_gap_codes"] == []
    assert section["leads"]["collected"] == len(rows) and section["leads"]["admitted"] == len(packaged)
    assert section["leads"]["non_lead_observations"] == sum(
        assembly.manifest["counts"]["non_lead_observations"].values())
    assert section["admitted_dispositions"] == {**dict.fromkeys(DISPOSITIONS, 0), "no_claim_raised": len(packaged)}
    assert section["sources"]["lead_package_manifest"]["sha256"] == hashlib.sha256(assembly.manifest_bytes).hexdigest()


def test_tampered_handoff_bound_lane_document_is_unavailable(tmp_path: Path) -> None:
    run_root = build_run(tmp_path, mixed())
    path = next(run_root.rglob("lane.json"))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["proposals"] = {}
    path.write_bytes(canonical_json(document))
    # the lane document is a handoff-bound output, so the accepted handoff's integrity check rejects it first
    _assert_unavailable(triage_reduction_metrics(run_root), "review_handoff_unavailable")


def test_run_metrics_carry_the_section_under_schema_7(tmp_path: Path) -> None:
    empty = aggregate_run_metrics(tmp_path / "empty")
    assert empty["schema"] == "appsec-review/run-metrics/7"
    _assert_unavailable(empty["triage_reduction"], "review_handoff_unavailable")

    run_root = build_run(tmp_path / "reviewed", mixed())
    report = aggregate_run_metrics(run_root)
    assert report["triage_reduction"] == triage_reduction_metrics(run_root)
    assert report["triage_reduction"]["available"] is True
