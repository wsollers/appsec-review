"""Accepted OWASP authority -> indirect control product -> provisional lead and model context."""
from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from appsec_review.indexing import products
from appsec_review.indexing.derive import publish_derived
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_review_data_indexing.job import owasp_status
from appsec_review.owasp_workbench import indexes
from appsec_review.owasp_workbench.evidence import EvidenceResolver
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexIdentity, LogicalIdentity, RetrievalCore, SourceLocation, write_manifest,
)
from appsec_review.review.evidence import classify
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.models import Admissibility, Predicate
from appsec_review.review.package_view import ViewLimits, build_view
from appsec_review.review.packages import assemble_packages
from appsec_review.review.ranking import DEFAULT_RANK_WEIGHTS
from appsec_review.review.scope import accept_manifest
from appsec_review.review.units import build_units
from appsec_review.storage import atomic_json, file_sha256
from tests.fixtures.inference_review.builder import FEEDS, build_accepted_index_set


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "review-packages.schema.json").read_text(encoding="utf-8"))
CONTROL = "asvs:5.0.0:V1.2.4"
COMPONENT = "component:0001"


def _fixture(base: Path):
    return build_accepted_index_set(base, omit_feeds=FEEDS, stale_feeds=(),
        omit=("codeql", "osv", "ci", "priority", "history", "dependency_advisories", "reference_intelligence"))


@dataclass(frozen=True)
class DownstreamArtifacts:
    derived: Any
    projection: dict[str, Any]
    product_rows: tuple[dict[str, Any], ...]
    scope: Any
    collection: Any
    assembly: Any
    core: RetrievalCore
    views: dict[str, Any]


def project_and_assemble(fixture) -> DownstreamArtifacts:
    """Project an already accepted real OWASP job publication, without mocking any downstream step.

    The fixture needs only run_root. Its original upstream manifest is left immutable; a new accepted
    retrieval manifest names the control product and the original manifest as an explicit ancestor.
    """
    root = fixture.run_root
    scope = accept_manifest(root)
    publication = owasp_status(root)
    store = ShardSet(root, scope.shards)
    rule = products.product_rule("control_evidence")
    context = products.ProductContext(root, scope.target_snapshot, store, {}, {}, publication, 1000, rule.version)
    derived = rule.build(context, rule.select(store))
    projection = publish_derived(
        root, index="precomputed", shard_id="owasp-control-evidence", job_id="job_review_data_indexing",
        unit_id="owasp-downstream", rule="control_evidence", rule_version=rule.version,
        snapshot=scope.target_snapshot, inputs={"owasp": publication["manifest_sha256"],
                                               "manifest": scope.manifest_sha256},
        build=lambda: derived, producer={"query_set": "control_evidence"})
    identities = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}) for raw in scope.shards]
    raw = projection["index_identity"]
    identities.append(IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}))
    upstream = {"path": scope.manifest_path.relative_to(root).as_posix(), "sha256": scope.manifest_sha256}
    path = root / "data" / "indices" / "manifests" / f"owasp-downstream-{projection['fingerprint']}.json"
    original_manifest = json.loads(scope.manifest_path.read_text(encoding="utf-8"))
    write_manifest(path, run_id=scope.run_id, target_snapshot=scope.target_snapshot,
                   target_root=Path(original_manifest["target_root"]), indexes=identities,
                   upstream_manifests=[upstream])
    pointer_path = root / "data" / "indices" / "accepted.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = root / pointer["handoff_path"]
    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
    handoff["artifacts"].append({"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
                                 "size_bytes": path.stat().st_size})
    atomic_json(handoff_path, handoff)
    atomic_json(pointer_path, {**pointer, "manifest_path": path.relative_to(root).as_posix(),
                              "manifest_sha256": file_sha256(path), "handoff_sha256": file_sha256(handoff_path)})
    projected_scope = accept_manifest(root)
    collection = collect_leads(projected_scope)
    assembly = assemble_packages(projected_scope, collection=collection)
    core = RetrievalCore(root.parent, root.name)
    views = {package.package_id: build_view(package.document(), core, ViewLimits())
             for package in assembly.packages}
    rows = tuple(projected_scope.store.entities(projected_scope.producer("control_evidence").shards,
                                                 kinds=("precomputed_fact",)))
    return DownstreamArtifacts(derived, projection, rows, projected_scope, collection, assembly, core, views)


def _references(fixture, component: str = COMPONENT, path: str = "svc/api/handler.py") -> tuple[dict, dict]:
    scope = accept_manifest(fixture.run_root)
    resolver = EvidenceResolver(RetrievalCore(fixture.runs_dir, fixture.run_id), scope)
    first = resolver.materialize(fixture.ids[path], component_id=component)["reference"]
    if path == "svc/api/handler.py":
        first = resolver.materialize(first["source_identity"], component_id=component,
                                    locator={**first["locator"], "lines": [3, 3]})["reference"]
    counter_path = "svc/api/util.py" if component == COMPONENT else "native/src/io.c"
    second = resolver.materialize(fixture.ids[counter_path], component_id=component)["reference"]
    return first, second


def _record(first: dict, second: dict, *, row_id: str = "owasp:sql", component: str = COMPONENT) -> dict:
    obligation = {"obligation_id": row_id + ":binding", "rule_version": "owasp-proof/1",
                  "subject_id": "db.raw:handler", "scope": {"component_id": component,
                    "build_unit_id": first["build_unit_id"]}, "invariant": "Values are bound separately from SQL",
                  "supported": True, "evidence_mode": "static_source"}
    independent = {"obligation": obligation, "outcome": "satisfied", "supporting": [second],
                   "contradictory": [], "rationale": "A guard is visible only on the inspected alternate path",
                   "assumptions": ["Deployment configuration is unestablished"], "evidence_requests": [],
                   "limitations": ["Static evidence only"], "gaps": [], "hypotheses": [], "citation_checks": []}
    assessed = {"obligation": obligation, "outcome": "not_satisfied", "final_outcome": "not_satisfied",
                "supporting": [], "contradictory": [first], "rationale": "This query call does not bind input",
                "assumptions": ["The caller can supply request input"], "evidence_requests": ["Trace other callers"],
                "limitations": ["No runtime execution"], "gaps": [], "hypotheses": [],
                "citation_checks": [{"reference": first, "resolution": "resolved", "subject_binding": True}],
                "disposition": "dissent", "independent_assessment": independent}
    observation = {"observation_id": row_id + ":hypothesis", "obligation_id": obligation["obligation_id"],
                   "mechanism": "Request input reaches db.raw without parameter binding at this call",
                   "severity": "high", "ship_blocking": False, "state": "awaiting_independent_verification",
                   "evidence": [first], "verification_outcome": "dissent"}
    return {"row_id": row_id, "control_identity": CONTROL, "component_id": component,
            "applicability": "applicable", "assessment_mode": "assessment",
            "control_status": "not_satisfied", "verification_status": "dissent", "lead_eligible": True,
            "execution_completion": "succeeded", "coverage_completeness": "scoped",
            "worker_attempt_count": 1, "reviewer_attempt_count": 2,
            "obligations": [assessed], "observations": [observation],
            "disagreements": [{"obligation_id": obligation["obligation_id"], "worker": "not_satisfied",
                               "reviewer": "satisfied", "reviewer_rationale": independent["rationale"]}],
            # The independent citation intentionally appears only inside the independent assessment.
            "evidence_used": [first], "gaps": ["Alternate paths remain unverified"],
            "limitations": ["This assessment concerns only the named query call"]}


def _publish(fixture, records: list[dict], *, mode: str = "assessment") -> dict:
    scope = accept_manifest(fixture.run_root)
    shard = indexes.publish_shard(fixture.run_root, family="control-result", shard_id="downstream-test",
                                  records=records, fingerprint_inputs={"test": "owasp-downstream"})
    return indexes.publish_manifest(fixture.run_root, run_id=fixture.run_id, shards=[shard],
        accepted_upstream_manifest={"path": scope.manifest_path.relative_to(fixture.run_root).as_posix(),
                                    "sha256": scope.manifest_sha256},
        configuration_sha256="b" * 64, assessment_mode=mode)


@pytest.fixture
def downstream(tmp_path):
    fixture = _fixture(tmp_path)
    first, second = _references(fixture)
    record = _record(first, second)
    _publish(fixture, [record])
    return fixture, record, project_and_assemble(fixture)


def test_original_custody_and_independent_dissent_survive_products_packages_and_views(downstream):
    fixture, record, result = downstream
    [lead] = [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    assert lead.path is None and lead.start_line is None and lead.location_exact is False
    assert lead.component_hint == COMPONENT and lead.build_unit_hint == "py-svc"
    assessment = lead.control_assessment
    assert assessment["provisional"] is True and assessment["verification_status"] == "dissent"
    assert assessment["obligations"] == record["obligations"]
    assert assessment["observations"] == record["observations"]
    assert assessment["disagreements"] == record["disagreements"]
    assert assessment["limitations"] == record["limitations"] and assessment["gaps"] == record["gaps"]
    assert assessment["worker_attempt_count"] == 1 and assessment["reviewer_attempt_count"] == 2
    assert len(assessment["evidence"]) == 2
    for evidence in assessment["evidence"]:
        original = {key: value for key, value in evidence.items() if key not in {"resolved", "resolution_gap"}}
        assert evidence["resolved"] is True
        assert original in [record["evidence_used"][0],
                           record["obligations"][0]["independent_assessment"]["supporting"][0]]
    row = result.product_rows[0]
    compact = row["payload"]["result"]
    assert compact["metadata_storage"] == "authoritative_workbench_reference"
    assert "<truncated>" not in json.dumps(compact)
    assert products.load_control_assessment(fixture.run_root, fixture.snapshot, compact) == assessment
    package = next(package for package in result.assembly.packages
                   if package.kind == "finding_lead" and package.lead_ids == (lead.observation_id,))
    document = package.document()
    jsonschema.Draft202012Validator(SCHEMA).validate(document)
    assert document["lead_menu"][0]["control_assessment"] == assessment
    assert document["scope"]["build_unit_id"] == "py-svc"
    assert document["evidence"][0]["resolution"] == "unresolved"
    assert {item["source_identity"] for item in assessment["evidence"]} <= set(document["retrieval"]["entity_ids"])
    view = result.views[package.package_id]
    assert view.document["leads"][0]["where"] == {"path": None, "line": None, "function": None}
    assert view.document["leads"][0]["control_assessment"] == assessment
    source = next(row for row in view.document["source"] if "db.raw" in "\n".join(row["text"]))
    assert source["ref"] == fixture.ids["svc/api/handler.py"]
    assert source["ref"] != lead.observation_id and source["lines"] == "3-3"
    assert source["role"] == "cited_source"


@pytest.mark.parametrize(("mode", "status", "applicability", "has_hypothesis", "expected"), [
    ("qualification", "not_satisfied", "applicable", True, False),
    ("assessment", "cannot_verify", "applicable", True, False),
    ("assessment", "satisfied", "applicable", True, False),
    ("assessment", "not_applicable", "not_applicable", True, False),
    ("assessment", "not_satisfied", "not_applicable", True, False),
    ("assessment", "not_satisfied", "applicable", False, False),
    ("assessment", "not_satisfied", "applicable", True, True),
])
def test_only_concrete_adverse_assessment_can_nominate_a_provisional_lead(
        tmp_path, mode, status, applicability, has_hypothesis, expected):
    fixture = _fixture(tmp_path)
    record = _record(*_references(fixture))
    record.update(control_status=status, applicability=applicability)
    if not has_hypothesis:
        record["observations"] = []
    _publish(fixture, [record], mode=mode)
    result = project_and_assemble(fixture)
    assert bool([lead for lead in result.collection.leads if lead.family == "owasp_control"]) is expected
    if mode == "qualification":
        assert result.derived.coverage[0][1] == "partial"
        assert any("qualification-only" in gap for gap in result.derived.gaps)
        for package in result.assembly.packages:
            assert "control_assessment" not in json.dumps(package.document())
            assert "control_assessment" not in json.dumps(result.views[package.package_id].document)


@pytest.mark.parametrize("mutation", ["run", "target", "component", "build", "publication", "content", "lines"])
def test_foreign_or_changed_underlying_custody_is_a_gap_not_a_lead(tmp_path, mutation):
    fixture = _fixture(tmp_path)
    record = _record(*_references(fixture))
    # Leave evidence_used intact: references buried in the independent review must also be checked.
    reference = record["obligations"][0]["independent_assessment"]["supporting"][0]
    if mutation == "run":
        reference["run_id"] = "another-run"
    elif mutation == "target":
        reference["target_snapshot"] = "target-sha256:" + "8" * 64
    elif mutation == "component":
        reference["component_id"] = "component:0002"
    elif mutation == "build":
        reference["build_unit_id"] = "native-main"
    elif mutation == "publication":
        reference["publication"]["manifest_sha256"] = "0" * 64
    elif mutation == "content":
        reference["content_sha256"] = "0" * 64
    else:
        reference["locator"]["lines"] = [900, 901]
    _publish(fixture, [record])
    result = project_and_assemble(fixture)
    assert not [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    assert result.product_rows[0]["payload"]["result"]["unresolved_evidence"] == 1
    assert any("citation(s)" in gap.reason for gap in result.collection.gaps if gap.producer == "owasp_control")


def test_precomputed_interpretation_is_indirect_even_with_only_resolving_source(downstream):
    _fixture, _record_value, result = downstream
    [lead] = [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    payload = {"schema": "appsec-review/precomputed-fact/1", "result": lead.control_assessment}
    assert all(item["resolved"] for item in lead.control_assessment["evidence"])
    for predicate in Predicate:
        assert classify(EntityKind.PRECOMPUTED_FACT, predicate, tuple(Predicate),
                        fact_payload=payload) is Admissibility.INDIRECT


def test_scoped_effective_controls_reach_blue_context_without_claiming_component_safety(tmp_path):
    fixture = _fixture(tmp_path)
    row = _record(*_references(fixture))
    row.update(control_status="satisfied", verification_status="independently_assessed", lead_eligible=False)
    row["observations"] = []
    row["obligations"][0].update(outcome="satisfied", final_outcome="satisfied",
                                  disposition="independently_assessed")
    native = _record(*_references(fixture, "component:0002", "native/src/parse.c"),
                     row_id="native-only", component="component:0002")
    native.update(control_status="satisfied", lead_eligible=False)
    _publish(fixture, [row, native])
    result = project_and_assemble(fixture)
    packages = [item for item in result.assembly.packages if item.document()["scope"]["component_id"] == COMPONENT]
    assert packages
    for package in packages:
        document = package.document()
        jsonschema.Draft202012Validator(SCHEMA).validate(document)
        controls = [entry["control_assessment"] for entry in document["context"] if entry["role"] == "control_context"]
        assert controls and all(item["component_id"] == COMPONENT for item in controls)
        assert controls[0]["control_status"] == "satisfied"
        assert controls[0]["obligations"] == row["obligations"]
        assert "component-safety proof" in controls[0]["interpretation"]
        assert {item["source_identity"] for item in controls[0]["evidence"]} <= set(document["retrieval"]["entity_ids"])
        view_controls = [entry["control_assessment"] for entry in result.views[package.package_id].document["other_context"]
                         if entry["role"] == "control_context"]
        assert view_controls == controls


def test_scanner_and_owasp_same_underlying_source_are_not_independent_or_extra_hints(downstream):
    fixture, _record_value, result = downstream
    [owasp] = [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    assert owasp.duplicate_of == fixture.ids["sast_high"]
    scanner_package = next(item for item in result.assembly.packages
                           if item.kind == "finding_lead" and item.lead_ids == (fixture.ids["sast_high"],))
    assert owasp.observation_id not in {row["ref"] for row in scanner_package.document()["neighborhood"]["corroboration"]}
    scanner = next(lead for lead in result.collection.leads if lead.observation_id == fixture.ids["sast_high"])
    single = replace(result.collection, leads=(replace(scanner, reported_severity="medium"),))
    duplicate = replace(single, leads=(*single.leads, replace(owasp, reported_severity="medium")))
    for collection in (single, duplicate):
        units = build_units(result.scope, collection, unit_max_files=100)
        hints = sum(signal.value or 0 for unit in units for signal in unit.signals if signal.signal == "lead_hints")
        assert hints == DEFAULT_RANK_WEIGHTS.lead_hint_medium


def test_password_reasoning_is_preserved_but_literal_credentials_are_redacted(tmp_path):
    fixture = _fixture(tmp_path)
    row = _record(*_references(fixture))
    rationale = "Password verification is unestablished; check password hashing."
    row["obligations"][0]["rationale"] = rationale
    row["obligations"][0]["limitations"] = ["password = plaintext-fixture-credential"]
    _publish(fixture, [row])
    result = project_and_assemble(fixture)
    [lead] = [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    assert lead.control_assessment["obligations"][0]["rationale"] == rationale
    assert "plaintext-fixture-credential" not in json.dumps(lead.control_assessment)
    assert "<redacted:" in json.dumps(lead.control_assessment)


def test_authoritative_workbench_tampering_is_not_hidden_by_projection(downstream):
    fixture, _record_value, result = downstream
    reference = result.product_rows[0]["payload"]["result"]["workbench_reference"]
    path = fixture.run_root / reference["path"]
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="control-result shard changed"):
        collect_leads(result.scope)


def test_original_upstream_manifest_is_pinned_and_path_confined(tmp_path):
    fixture = _fixture(tmp_path)
    _publish(fixture, [_record(*_references(fixture))])
    status = owasp_status(fixture.run_root)
    status["accepted_upstream_manifest"] = {"path": "../outside.json", "sha256": "0" * 64}
    scope = accept_manifest(fixture.run_root)
    context = products.ProductContext(fixture.run_root, fixture.snapshot, scope.store, {}, {}, status, 100, "test")
    with pytest.raises(ValueError):
        products.product_rule("control_evidence").build(context, ())


def test_missing_workbench_is_unavailable_not_clean(tmp_path):
    status = owasp_status(tmp_path)
    store = ShardSet(tmp_path, ())
    context = products.ProductContext(tmp_path, "target-sha256:" + "7" * 64, store, {}, {}, status, 100, "test")
    derived = products.product_rule("control_evidence").build(context, ())
    assert not derived.entities and derived.coverage[0][1] == "unavailable"
    assert "no accepted index" in derived.gaps[0]


def test_declaration_only_hypothesis_cannot_become_a_vulnerability_lead(tmp_path):
    fixture = _fixture(tmp_path)
    scope = accept_manifest(fixture.run_root)
    resolver = EvidenceResolver(RetrievalCore(fixture.runs_dir, fixture.run_id), scope)
    declaration = resolver.materialize(fixture.ids["component:svc"], component_id=COMPONENT)["reference"]
    _, second = _references(fixture)
    row = _record(declaration, second)
    _publish(fixture, [row])
    result = project_and_assemble(fixture)
    assert not [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    assert result.product_rows[0]["payload"]["result"]["lead_eligible"] is False


def test_deep_original_source_custody_is_lossless_without_weakening_index_sanitization(tmp_path):
    from appsec_review.retrieval.source_resolution import generated_path, publish_source
    from tests.review.test_packages_memory_context import _publish as append_shards

    fixture = _fixture(tmp_path)
    data = (fixture.target / "svc/api/handler.py").read_bytes()
    sha = file_sha256(fixture.target / "svc/api/handler.py")
    workspace_path = "out/query.py"
    canonical = LogicalIdentity.derive(EntityKind.SOURCE_FILE, fixture.snapshot, {
        "build_unit_id": "py-svc", "workspace_path": workspace_path, "sha256": sha,
        "format": "generated-source"})
    path = generated_path(canonical.value, workspace_path)
    artifact = {"canonical_identity": canonical.value, "workspace_path": workspace_path, "sha256": sha,
                "kind": "generated-source", "scope_role": "deliverable", "artifact_origin": "build-output"}
    backing = publish_source(fixture.run_root, target_snapshot=fixture.snapshot, logical_path=path,
        artifact=artifact, build_unit_id="py-svc", handoff_sha256="a" * 64, data=data)
    lines = data.splitlines(keepends=True)
    identity = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, fixture.snapshot, {"deep-custody": path})
    custody = {"source_domain": "generated", "source_backing": backing}
    location = SourceLocation(fixture.snapshot, path, sha,
        sum(map(len, lines[:2])), sum(map(len, lines[:3])), 3, 3, 1, 21, custody, "fixture-exact", 1.0)
    entity = EntityRecord(identity, "deep-source", "deep-source", "query source",
                          {"component_id": COMPONENT, "build_unit_id": "py-svc"}, location)
    append_shards(fixture, [("source", "deep-custody", {"job": "job_target_catalog"},
                            [entity], [], ("deep-custody", "complete", None))])
    scope = accept_manifest(fixture.run_root)
    resolver = EvidenceResolver(RetrievalCore(fixture.runs_dir, fixture.run_id), scope)
    reference = resolver.materialize(identity.value, component_id=COMPONENT)["reference"]
    assert reference["locator"]["source_custody"] == custody
    _, second = _references(fixture)
    _publish(fixture, [_record(reference, second)])
    result = project_and_assemble(fixture)
    [lead] = [lead for lead in result.collection.leads if lead.family == "owasp_control"]
    preserved = lead.control_assessment["observations"][0]["evidence"][0]
    assert preserved == reference
    assert preserved["locator"]["source_custody"]["source_backing"]["sha256"] == backing["sha256"]
    assert "<truncated>" not in json.dumps(lead.control_assessment)
    assert "<truncated>" not in json.dumps(result.product_rows)


def test_trusted_service_authorization_control_maps_to_permission_weakness():
    record = {"control_identity": "asvs:5.0.0:V8.3.1", "component_id": COMPONENT}
    result = products._control_assessment(record, {}, {}, None)
    assert result["rule_cwe"] == ["CWE-862"]
