"""Small synthetic boundary fixtures, never evidence of a real accepted run.

No runner, model, target, Git, subprocess or network access. The input verifier's tests must
separately establish acceptance/custody; these fixtures start at its verified-state boundary.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from appsec_review.jobs.job_final_publication_gate import classify as classifier
from appsec_review.jobs.job_final_publication_gate.attachments import capability
from appsec_review.jobs.completion_contracts import CompletionCapability, nonexecution_assurance
from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_openvex_export import contracts as c
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.review import ship_block

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas" / "openvex-export"
OUTPUT_PREFIX = "data/jobs/job_openvex_export/attempts/fixture/steps/export/tasks/assemble"
RELEASE = "fixture-release/1"


def settings_mapping(*, enabled: bool = False, **overrides: Any) -> dict[str, Any]:
    return {**OpenVexExportSettings().to_mapping(), "enabled": enabled, **overrides}


def enabled_settings(**overrides: Any) -> OpenVexExportSettings:
    return OpenVexExportSettings.from_mapping({
        **settings_mapping(enabled=True), "author_kind": "organization", "author": "Example Security Team", "role": "",
        "action_statement": "Disable the synthetic test endpoint.",
        "repository_iri": "https://example.test/repository", **overrides,
    })


def fixture_id(prefix: str, seed: str) -> str:
    return f"{prefix}-{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


def fixture_ref(name: str) -> c.ArtifactRef:
    return c.ArtifactRef(f"data/fixtures/{name}.json", c.json_sha256({"fixture": name}))


def schema_registry(schema_root: Path = SCHEMAS) -> Registry:
    """Only explicit resources are resolvable, also in an installed share/ layout."""
    def deny(uri: str) -> Resource:
        raise NoSuchResource(ref=uri)

    registry = Registry(retrieve=deny)
    for relative in c.SCHEMA_SHA256:
        document = json.loads((schema_root / relative).read_bytes())
        registry = registry.with_resource(document["$id"], Resource.from_contents(document))
    return registry


def schema_validator(name: str, schema_root: Path = SCHEMAS) -> Draft202012Validator:
    document = json.loads((schema_root / name).read_bytes())
    return Draft202012Validator(document, registry=schema_registry(schema_root))


def _finding(index: int, bucket: c.GateBucket) -> c.VerifiedFinding:
    seed = str(index)
    package_ref, score_ref, evidence_ref = (fixture_ref(f"{kind}-{seed}") for kind in ("finding", "score", "evidence"))
    confirmed = bucket != c.GateBucket.VERIFICATION_BACKLOG
    score_id = fixture_id("score", seed)
    score = {
        "score_id": score_id, "sha256": score_ref.sha256,
        "provider": {"id": "fixture", "interface": "score/1", "implementation": "synthetic"},
        "native": {"nomenclature": None, "rating": None, "score": None},
        "technical_severity": {"scale": "fixture/1", "rating": "high", "value": 8},
        "exploitability_confidence": None, "environmental_business_impact": None, "remediation_priority": None,
        "missing_factors": [],
        "severity_assessment": {"assessment": "complete", "severity_floor": "high",
                                "severity_ceiling": "high", "unresolved_factors": []},
    }
    projection = {
        "finding_package_id": fixture_id("finding", seed), **package_ref.to_json(),
        "claim_id": fixture_id("claim", seed), "adjudication_id": fixture_id("adjudication", seed),
        "lane": "hunt", "state": "confirmed" if confirmed else "supported",
        "label": "confirmed" if confirmed else "not_independently_confirmed",
        "title": f"Synthetic finding {index}",
        "ship_block": {
            "policy": "ship-block-policy/1", "policy_sha256": fixture_ref("policy").sha256,
            "status": "ship_blocking" if confirmed else "needs_verification",
            "reasons": [], "technical_severity": "high", "technical_severity_score_id": score_id,
            "technical_severity_floor": "high", "technical_severity_ceiling": "high", "missing_factors": [],
            "distinct_verification_required": True, "verifier_model_distinct": True,
        },
        "independence": {"independent": True, "provider_distinct": True,
                         "verifier_model_distinct": True, "judge_model_distinct": None},
        "judge_verdict": None, "verification_review_id": fixture_id("review", seed),
        "direct_evidence": [fixture_id("evrel", seed)], "analyst_assessed_evidence": [],
        "missing_predicates": [], "gap_ids": [], "scores": [score],
        "poc": {"status": "unavailable", "result_id": None} if bucket == c.GateBucket.WITHHELD else None,
        "attack_chains": [], "bucket": bucket.value,
        "withheld_reasons": ["poc_outcome_unavailable"] if bucket == c.GateBucket.WITHHELD else [],
    }
    return c.VerifiedFinding(projection, (score_ref,), (evidence_ref,))


def make_verified_inputs(
    buckets: Sequence[c.GateBucket | str] = (c.GateBucket.PUBLISHABLE,), *,
    settings: OpenVexExportSettings | None = None, review_gap: bool = False,
    run_id: str = "run-openvex-fixture", gate_completed_at: str = "2026-10-28T10:00:00-04:00",
    completion_attachments: bool = False,
) -> c.VerifiedInputs:
    settings = settings or enabled_settings()
    findings = tuple(_finding(index, c.GateBucket(bucket)) for index, bucket in enumerate(buckets))
    refs = {name: fixture_ref(name) for name in (
        "gate-handoff", "review-handoff", "review", "scope", "manifest", "configuration-manifest",
        "configuration", "claim-ledger", "projection", "coverage", "lead-manifest", "hunt-manifest", "policy",
        "lead-package-set", "hunt-package-set", "lead-package", "hunt-package", "chain-manifest",
    )}
    capabilities = {name.value: capability(False) for name in CompletionCapability}
    capabilities["attack_chains"] = capability(True, summary=refs["chain-manifest"].to_json())
    attachments: dict[str, list[dict[str, Any]]] = {name.value: [] for name in CompletionCapability}
    if completion_attachments:
        eligible = [finding for finding in findings if finding.bucket == c.GateBucket.PUBLISHABLE]
        if len(eligible) < 2:
            raise ValueError("the synthetic completion snapshot requires two publishable findings")
        chain_id = fixture_id("chain", "completion")
        refs["chain"] = fixture_ref("chain")
        for finding in eligible[:2]:
            findings = tuple(replace(item, projection={**c.json_body(item.projection), "attack_chains": [chain_id]})
                             if item.finding_package_id == finding.finding_package_id else item for item in findings)
        attachments["attack_chains"] = [{
            "chain_id": chain_id, "status": "qualified_supported",
            "component_claim_ids": [finding.claim_id for finding in eligible[:2]],
            "artifact": refs["chain"].to_json(), "gap_count": 1, "disposition": "assessed",
        }]
        capabilities["attack_chains"] = capability(True, summary=refs["chain-manifest"].to_json(), count=1, gaps=1)
        finding = eligible[0]
        for name in ("poc_generation", "remediation_planning", "remediation_validation", "dossiers"):
            refs[f"{name}-handoff"] = fixture_ref(f"{name}-handoff")
            refs[f"{name}-summary"] = fixture_ref(f"{name}-summary")
            capabilities[name] = capability(True, handoff=refs[f"{name}-handoff"].to_json(),
                                            summary=refs[f"{name}-summary"].to_json(),
                                            count=1 if name == "poc_generation" else
                                            len(eligible) + int(name == "dossiers"),
                                            gaps=0 if name == "dossiers" else
                                            1 if name == "poc_generation" else len(eligible))
        poc_files = {name: fixture_ref(f"poc-{name}") for name in ("source", "compile", "readme", "provenance")}
        refs.update({f"poc-{name}": reference for name, reference in poc_files.items()})
        attachments["poc_generation"] = [{
            "claim_id": finding.claim_id, "finding_package_id": finding.finding_package_id,
            "status": "compile_failed", "description": "Compile-only fixture outcome. Nothing was executed.",
            "functions": {"test_function": "test_fixture", "negative_control": "control_fixture"},
            "files": {name: reference.to_json() for name, reference in poc_files.items()},
            **nonexecution_assurance(),
        }]
        for name, key, status in (("remediation_planning", "plan", "manual_design_required"),
                                   ("remediation_validation", "validation", "manual_validation_required")):
            for index, item in enumerate(eligible):
                refs[f"{key}-{index}"] = fixture_ref(f"{key}-{index}")
                binding = {"claim_id": item.claim_id, "finding_package_id": item.finding_package_id,
                           "sha256": item.reference.sha256}
                attachments[name].append({
                    "finding": binding, "status": status, key: refs[f"{key}-{index}"].to_json(),
                    "gap_ids": ["synthetic_manual_review"], **nonexecution_assurance(),
                })
        for index, (kind, item) in enumerate(
                [("confirmed_finding", item) for item in eligible] + [("poc", eligible[0])]):
            dossier_files = {name: fixture_ref(f"dossier-{index}-{name}") for name in ("json", "latex", "pdf", "receipt")}
            refs.update({f"dossier-{index}-{name}": reference for name, reference in dossier_files.items()})
            attachments["dossiers"].append({
                "dossier_id": fixture_id("dossier", str(index)), "kind": kind,
                "finding": {"claim_id": item.claim_id, "finding_package_id": item.finding_package_id,
                            "sha256": item.reference.sha256},
                "status": "rendered", "gap_ids": [],
                "files": {name: reference.to_json() for name, reference in dossier_files.items()},
            })
    gaps = [fixture_id("gap", "coverage")] if review_gap else []
    counts = {"confirmed": sum(f.projection["state"] == "confirmed" for f in findings),
              "supported": sum(f.projection["state"] == "supported" for f in findings)}
    status = "DEGRADED" if review_gap else "COMPLETE" if findings else "EMPTY"
    review = {
        "status": status, "review_incomplete": review_gap,
        "accepted_manifest_sha256": refs["manifest"].sha256, "configuration_sha256": c.json_sha256("review-settings"),
        "ledger_head_sha256": c.json_sha256("ledger-head"), "projection_sha256": c.json_sha256("projection"),
        "ship_block_policy_sha256": refs["policy"].sha256,
        "package_manifest_sha256": refs["hunt-manifest"].sha256,
        "lead_package_manifest_sha256": refs["lead-manifest"].sha256,
    }
    block = ship_block.summarize({"lane": f.projection["lane"], "status": f.projection["ship_block"]["status"]}
                                 for f in findings)
    inputs = {
        "run_id": run_id, "review": review,
        "inputs": {name: refs[key].to_json() for name, key in (
            ("job_handoff", "review-handoff"), ("review_handoff", "review"),
            ("claim_ledger", "claim-ledger"), ("projection", "projection"), ("coverage_matrix", "coverage"))},
        "accounting": {
            "outcome": status, "review_incomplete": review_gap, "incomplete_gap_ratio": 0.1,
            "gap_ratio": 1 if review_gap else 0, "claims_total": len(findings), "duplicate_proposals": 0,
            "claims_by_state": counts, "gaps_by_class": {"coverage": 1} if review_gap else {},
        },
        "lanes": [], "ship_block": {"policy": "ship-block-policy/1", "policy_sha256": refs["policy"].sha256, **block},
        "verification": {"require_distinct_model_for_ship_blocking": True, "distinct": True, "warning": None},
        "coverage": {"rows": 1, "summary": {"gap": 1} if review_gap else {"reviewed": 1},
                     "statement": "Synthetic coverage is not a safety verdict"},
        "partition": {
            "confirmed": [f.finding_package_id for f in findings if f.projection["state"] == "confirmed"],
            "supported": [f.finding_package_id for f in findings if f.projection["state"] == "supported"],
        },
        "possible_duplicate_pairs": 0, "packages": [c.json_body(f.projection) for f in findings],
        "capabilities": capabilities, "attachments": attachments,
        "gap_ids": gaps,
        "bindings": sorted([ref.to_json() for name, ref in refs.items() if name != "gate-handoff"] + [
            ref.to_json() for finding in findings
            for ref in (finding.reference, *finding.score_refs, *finding.evidence_refs)], key=lambda ref: ref["path"]),
    }
    gate = classifier.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, inputs, classifier.classify(inputs))
    gate_ref = c.ArtifactRef("data/fixtures/gate.json", c.json_sha256(gate))
    provenance = c.ExportProvenance(
        refs["gate-handoff"], gate_ref, refs["review-handoff"], refs["review"], refs["scope"], refs["manifest"],
        refs["configuration-manifest"], refs["configuration"], review["configuration_sha256"],
        review["lead_package_manifest_sha256"], review["package_manifest_sha256"], review["ledger_head_sha256"],
        review["projection_sha256"], review["ship_block_policy_sha256"],
    )
    all_refs = set(refs.values()) | {gate_ref}
    for finding in findings:
        all_refs.update((finding.reference, *finding.score_refs, *finding.evidence_refs))
    inventory = tuple(c.SizedArtifactRef(ref.path, ref.sha256, len(c.canonical_bytes(gate)) if ref == gate_ref
                                        else len(c.canonical_bytes({"fixture": Path(ref.path).stem})))
                      for ref in all_refs)
    return c.VerifiedInputs(
        run_id, provenance, c.SourceIdentity(
            settings.repository_iri or c.snapshot_repository_iri(c.json_sha256("synthetic-snapshot")),
            c.RepositoryIdentityBasis.OPERATOR_DECLARED if settings.repository_iri
            else c.RepositoryIdentityBasis.SOURCE_SNAPSHOT,
                                             c.json_sha256("synthetic-snapshot"), None, ("Synthetic test configuration",)),
        gate_completed_at, settings.settings_sha256(), gate, findings, inventory,
    )


def example_bundle(inputs: c.VerifiedInputs | None = None, settings: OpenVexExportSettings | None = None, *,
                   output_prefix: str = OUTPUT_PREFIX, exporter_release: str = RELEASE) -> c.ExportBundle:
    """Schema-valid example bodies, not the production projection/validation implementation."""
    settings = settings or enabled_settings()
    inputs = inputs or make_verified_inputs(settings=settings)
    provenance, gate = inputs.provenance, inputs.gate
    product = c.source_product_id(inputs.source.repository_iri, inputs.source.target_snapshot,
                                  provenance.resolved_config_sha256)
    included = [finding for finding in inputs.findings if finding.bucket == c.GateBucket.PUBLISHABLE]
    statements, mappings, packages = [], [], []
    for finding in inputs.findings:
        identity = None
        if finding in included:
            vulnerability = c.vulnerability_id(inputs.source.repository_iri, inputs.source.target_snapshot,
                                               finding.claim_id)
            statement = {
                "version": 1, "vulnerability": {"@id": vulnerability, "name": vulnerability},
                "timestamp": inputs.gate_completed_at, "products": [{"@id": product}], "status": "affected",
                "status_notes": c.STATUS_NOTES, "action_statement": settings.action_statement,
            }
            identity = c.statement_id(settings.author, statement)
            mappings.append({
                "statement_id": identity, "statement_index": len(statements), "vulnerability_id": vulnerability,
                "product_id": product, "finding_package_id": finding.finding_package_id,
                "finding_package": finding.reference.to_json(), "claim_id": finding.claim_id,
                "claim_ledger": c.json_body(gate["inputs"]["claim_ledger"]),
                "projection": c.json_body(gate["inputs"]["projection"]), "settings_sha256": inputs.settings_sha256,
                "evidence_refs": [ref.to_json() for ref in finding.evidence_refs],
            })
            statements.append({"@id": identity, **statement})
        packages.append({
            "finding": c.json_body(finding.projection), "score_refs": [ref.to_json() for ref in finding.score_refs],
            "evidence_refs": [ref.to_json() for ref in finding.evidence_refs],
            "disposition": "included" if identity else "excluded", "statement_id": identity,
            "reason": "included" if identity else f"gate_{finding.bucket.value}",
        })
    document = None
    if statements:
        document = {
            "@context": c.OPENVEX_CONTEXT, "author": settings.author, "timestamp": inputs.gate_completed_at,
            "version": 1, "tooling": c.exporter_tooling(exporter_release), "statements": statements,
            **({"role": settings.role} if settings.role else {}),
        }
        document = {"@id": c.document_id(document), **document}
    document_bytes = None if document is None else c.canonical_bytes(document)
    document_ref = None if document_bytes is None else c.output_reference(output_prefix, c.DOCUMENT_NAME, document_bytes)
    gaps = [limitation["limitation_id"] for limitation in gate["limitations"] if limitation["kind"] == "gap"]
    outcome = "exported_with_gaps" if gaps else "exported"
    if not statements:
        outcome = "no_statements"
        gaps.append(c.NO_STATEMENTS_GAP)
    counts = gate["package_counts"]
    manifest = {
        "schema": c.OPENVEX_EXPORT_MANIFEST_SCHEMA, "run_id": inputs.run_id, "outcome": outcome,
        "disclosure": c.DISCLOSURE,
        "provenance": {
            **provenance.to_json(), "settings_sha256": inputs.settings_sha256,
            "gate_completed_at": inputs.gate_completed_at, "timestamp_source": c.TIMESTAMP_SOURCE,
            "exporter_component": c.EXPORTER_COMPONENT, "exporter_release": exporter_release,
            "schema_sha256": c.UPSTREAM_SCHEMA_SHA256, "validation_profile": c.VALIDATION_PROFILE,
            "validation_profile_sha256": c.VALIDATION_PROFILE_SHA256,
        },
        "review_context": {key: c.json_body(gate[key]) for key in (
            "review", "accounting", "ship_block", "verification", "coverage", "limitations",
            "gap_ids", "capabilities", "attachments", "status")},
        "products": [{
            **inputs.source.to_json(), "product_id": product,
            "accepted_manifest": provenance.accepted_manifest.to_json(),
            "resolved_config_sha256": provenance.resolved_config_sha256, "scope_statement": c.STATUS_NOTES,
        }],
        "packages": packages, "statement_mappings": mappings,
        "document": None if document_ref is None else document_ref.to_json(),
        "accounting": {
            "gate_total": counts["total"], "gate_publishable": counts["publishable"],
            "gate_verification_backlog": counts["verification_backlog"], "gate_withheld": counts["withheld"],
            "included_findings": len(included), "excluded_findings": counts["total"] - len(included),
            "statement_count": len(statements), "product_count": 1,
            "exclusion_counts": {"gate_verification_backlog": counts["verification_backlog"],
                                 "gate_withheld": counts["withheld"]},
        },
        "bindings": [ref.reference.to_json() for ref in inputs.input_inventory],
    }
    manifest_bytes = c.canonical_bytes(manifest)
    manifest_ref = c.output_reference(output_prefix, c.MANIFEST_NAME, manifest_bytes)
    result = {
        "schema": c.OPENVEX_EXPORT_RESULT_SCHEMA, "run_id": inputs.run_id, "outcome": outcome,
        "gate": provenance.gate.to_json(), "manifest": manifest_ref.to_json(),
        "document": None if document_ref is None else document_ref.to_json(), "statement_count": len(statements),
        "included_findings": len(included), "excluded_findings": counts["total"] - len(included), "gaps": gaps,
    }
    result_bytes = c.canonical_bytes(result)
    return c.ExportBundle(document, manifest, result, document_bytes, manifest_bytes, result_bytes, document_ref,
                          manifest_ref, c.output_reference(output_prefix, c.RESULT_NAME, result_bytes))
