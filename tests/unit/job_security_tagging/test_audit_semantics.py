"""Offline producer/collector regressions for T-5183, T-5184 and T-5185."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import sqlite3

import pytest

from appsec_review.config.collation import ModelPassSettings
from appsec_review.graph.crosscheck import SourceFile
from appsec_review import inference
from appsec_review.inference.errors import ExecutionContractError, ProviderError
from appsec_review.jobs.job_language_build import job as language_build, jvm
from appsec_review.jobs.job_security_tagging import job
from appsec_review.jobs.job_security_tagging.collation import collect_facets
from appsec_review.jobs.job_security_tagging.model_pass import PROPOSAL_SCHEMA, run_model_pass
from appsec_review.jobs.job_security_tagging.producers import (
    AcceptedIndexes, component_topology_sha256, ownership_rules, resolve_scope,
)
from appsec_review.jobs.job_security_tagging.taxonomy import assignment, validate_assignment
from appsec_review.jobs.job_target_catalog import job as catalog
from appsec_review.storage import file_sha256
from appsec_review.runtime import execution_safety
from tests.unit.job_target_catalog.support import context

from .helpers import ROOT, SNAPSHOT, scope, taxonomy, unit_context
from .test_collation import canned, component_tags, settings
from .test_model_pass import MODEL, Scripted, run_pass, valid_proposal


def accepted_catalog(tmp_path, files):
    outputs = {}
    unit = context(tmp_path, "repository_discovery.partition_repository", outputs)
    for path, data in files.items():
        file = unit.job.target_root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    for work in catalog.build_job().units:
        unit = context(tmp_path, work.unit_id, outputs)
        unit.job.config.inventory_max_file_bytes = 4096
        unit.job.source_fingerprint = SNAPSHOT
        outputs[work.unit_id] = work.handler(unit)
    manifest = outputs["publish_catalog.publish_handoff"]["index_manifest"]
    indexes = AcceptedIndexes(unit.job.run_root, manifest_path=unit.job.run_root / manifest["path"],
                              manifest_sha256=manifest["sha256"])
    return unit, indexes, outputs


def collect(indexes, cfg=None, inputs=()):
    vocabulary, rules, _ = taxonomy()
    sc, _ = resolve_scope(indexes, 100)
    records, gaps, document = collect_facets(indexes, sc, vocabulary, rules, cfg or settings(), inputs, 100)
    return sc, records, gaps, document


@pytest.mark.parametrize("tag", ["component:android-mobile", "component:ios-mobile", "func:mobile:deeplink"])
def test_mobile_capabilities_reach_target_rules_with_original_derivation(tmp_path, tag):
    unit, indexes, _ = accepted_catalog(tmp_path, {"app.py": b"import jwt\n"})
    sc, _ = resolve_scope(indexes, 100)
    vocabulary, rules, crosswalk = taxonomy()
    subject = sc.component_subject(sc.components[0]["component_id"])
    capability = assignment(vocabulary=vocabulary, tag=tag, basis="declared", subject=subject,
                            producer={"name": "accepted-mobile-fact"}, evidence=[{"ref": subject["logical_id"]}])
    _, records, _, document = collect(indexes, inputs=[capability])
    mobile = next(record for record in records if record["tag"] == "target:mobile")
    assert mobile["derived_from"] == [capability["assignment_id"]]
    assert document["components"][0]["target_classes"] == ["target:mobile"]
    validate_assignment(vocabulary, mobile)
    identities = {"vocabulary_sha256": vocabulary.sha256, "capability_rules_sha256": rules.sha256,
                  "crosswalk_sha256": crosswalk.sha256}
    published = job._publish_shards(
        unit, [capability, *records], indexes, identities,
        component_topology_sha256(sc.components, ownership_rules()))
    facets = next(shard for shard in published if shard.shard_id == "facets")
    with sqlite3.connect(unit.job.run_root / facets.relative_path) as database:
        rows = [json.loads(row[0]) for row in database.execute(
            "SELECT payload_json FROM entities WHERE kind = 'tag_assignment'")]
    assert next(row for row in rows if row["tag"] == "target:mobile") == mobile


@pytest.mark.parametrize("damage", ["foreign-project", "foreign-component", "vendored", "unselected"])
def test_ineligible_capabilities_never_supply_target_class_inputs(damage):
    vocabulary, rules, _ = taxonomy()
    sc = scope([{"component_id": "component:app", "logical_id": "app", "root": "app"}])
    subject = sc.component_subject("component:app")
    if damage == "foreign-project":
        subject["project_id"] = "foreign-project"
    elif damage == "foreign-component":
        subject["logical_id"] = "foreign-component"
    else:
        path = "app/third_party/mobile.py" if damage == "vendored" else "other/mobile.py"
        subject.update(kind="source_file", logical_id="source", path=path)
    capability = assignment(vocabulary=vocabulary, tag="component:android-mobile", basis="declared",
                            subject=subject, producer={"name": "accepted-mobile-fact"},
                            evidence=[{"ref": subject["logical_id"]}])
    indexes = canned(("app/main.py", "import jwt\n", "Python"),
                     ("app/third_party/mobile.py", "import jwt\n", "Python"))
    records, _, _ = collect_facets(indexes, sc, vocabulary, rules, settings(), [capability], 100)
    assert "target:mobile" not in component_tags(records)


@pytest.mark.parametrize("first_party,document_path", [
    (False, "third_party/openapi.json"), (True, "third_party/openapi.json"), (True, "openapi.json"),
])
def test_document_facets_use_the_same_first_party_scope_as_summary(tmp_path, first_party, document_path):
    path = "app.py" if first_party else "third_party/app.py"
    _, indexes, _ = accepted_catalog(tmp_path, {
        path: b"import jwt\n",
        document_path: json.dumps({"openapi": "3.0.0", "info": {"title": "fixture", "version": "1"},
                                   "paths": {"/login": {"get": {"operationId": "login", "responses": {}}}}},
                                  indent=2).encode(),
    })
    _, records, _, document = collect(indexes)
    assert any(indexes.rows(identity, ("document_record",), 100)[0] for identity in indexes.shards("documents"))
    tags = component_tags(records)
    assert ("mechanism:http" in tags) is (first_party and document_path == "openapi.json")
    assert set(document["components"][0]["facets"]) == {tag for tag in tags if not tag.startswith("target:")}
    if not first_party:
        assert not tags and not document["components"][0]["target_classes"]


def build_receipt(build_unit_id, kind, *, role="deliverable", origin="build-output"):
    return {
        "build_unit_id": build_unit_id, "family": "java" if kind == "jar" else "cpp",
        "build_system": "maven" if kind == "jar" else "cmake",
        "image": {"image_id": "sha256:" + "5" * 64}, "terminal_status": "SUCCEEDED", "gaps": [],
        "commands": [{"command_id": "command:1", "ordinal": 1, "tool": "fixture",
                      "tool_kind": "build-driver", "argv_sha256": "b" * 64}],
        "tool_invocations": [], "declared_compilations": [],
        "artifacts": [{"workspace_path": "out/product", "sha256": "a" * 64, "size_bytes": 4,
                       "kind": kind, "build_unit_id": build_unit_id, "mapping": "exact-workspace-path",
                       "mapping_confidence": 1.0, "scope_role": role, "artifact_origin": origin}],
    }


def published_build(tmp_path, kind, *, bound=True, **overrides):
    unit, indexes, outputs = accepted_catalog(tmp_path, {
        "CMakeLists.txt": b"project(fixture)\nadd_library(product STATIC ${SOURCES})\n",
        "lib.c": b"#include <openssl/evp.h>\nint use(void) { return 1; }\n",
    })
    [build_unit] = outputs["build_discovery.catalog_build_targets"]["targets"]
    receipt = build_receipt(build_unit["build_unit_id"] if bound else "build-unit-foreign", kind, **overrides)
    unit.job.input_manifest_path = indexes.manifest_path
    unit.job.input_manifest_sha256 = indexes.manifest_sha256
    if kind == "jar":
        receipt["retrieval_index"] = jvm._index(unit, receipt)
    manifest = language_build._publish_build_index(unit, [receipt])
    return AcceptedIndexes(unit.job.run_root, manifest_path=unit.job.run_root / manifest["path"],
                           manifest_sha256=manifest["sha256"])


@pytest.mark.parametrize("kind", ["static-library", "executable", "jar"])
def test_real_build_artifacts_distinguish_library_and_program(tmp_path, kind):
    indexes = published_build(tmp_path, kind)
    _, records, gaps, document = collect(indexes)
    summary = document["components"][0]
    assert summary["build_point_kinds"] == [kind.replace("-", "_")]
    if kind == "executable":
        assert "target:library" not in component_tags(records)
        assert any("target_class_unresolved" in gap for gap in gaps)
    else:
        library = next(record for record in records if record["tag"] == "target:library")
        assert library["confidence"] == "high"
        assert library["evidence"][0]["rests_on_absence"] is False
        assert any(evidence.get("index") == "build" for evidence in library["evidence"])


@pytest.mark.parametrize("role,origin", [
    ("shipped_dependency", "build-output"), ("platform", "build-output"), ("deliverable", "accepted-input"),
])
def test_dependency_and_unbuilt_artifacts_cannot_classify_first_party_component(tmp_path, role, origin):
    _, records, _, document = collect(published_build(tmp_path, "static-library", role=role, origin=origin))
    assert document["components"][0]["build_point_kinds"] == []
    library = next(record for record in records if record["tag"] == "target:library")
    assert library["confidence"] == "medium" and library["evidence"][0]["rests_on_absence"] is True


def test_artifact_without_catalog_build_binding_is_a_gap(tmp_path):
    _, records, gaps, document = collect(published_build(tmp_path, "static-library", bound=False))
    assert document["components"][0]["build_point_kinds"] == []
    assert any("build_scope_unresolved" in gap for gap in gaps)
    library = next(record for record in records if record["tag"] == "target:library")
    assert library["confidence"] == "medium"


@pytest.mark.parametrize("kind", ["static-library", "executable"])
def test_unknown_delivery_artifacts_do_not_turn_missing_classification_into_library(tmp_path, kind):
    _, records, gaps, document = collect(published_build(tmp_path, kind, role="unknown"))
    assert document["components"][0]["build_point_kinds"] == []
    assert "target:library" not in component_tags(records)
    assert any("build_scope_unresolved" in gap for gap in gaps)
    assert any("target_class_unresolved" in gap for gap in gaps)


@pytest.mark.parametrize("damage", ["unknown-object", "claim-tag-list", "path-list", "line-list",
                                    "line-bool", "line-float", "assignment-list"])
def test_malformed_nested_json_is_rejected_by_real_handler(tmp_path, monkeypatch, damage):
    def malformed(request):
        value = valid_proposal(request)
        if damage == "unknown-object":
            value["unknown"] = [{}]
        elif damage == "claim-tag-list":
            value["claims"][0]["tag"] = []
        elif damage == "assignment-list":
            value["claims"][2]["citations"][0]["assignment_id"] = []
        else:
            citation = value["claims"][0]["citations"][0]
            if damage == "path-list":
                citation["path"] = []
            else:
                citation["line"] = {"line-list": [], "line-bool": True,
                                    "line-float": float(citation["line"])}[damage]
        return value

    unit, outputs, result = run_pass(tmp_path, monkeypatch, Scripted(malformed))
    assert result["item_count"] == 0 and result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["component_status"] == {"component:app": "rejected"}
    assert result["gaps"][0].startswith("collation:model_pass_rejected:")
    assert job._read(unit, outputs[job.COLLATION]["artifact"])["assignments"]


@pytest.mark.parametrize("failure", ["provider", "cancelled", "integrity"])
def test_active_admission_stop_is_never_swallowed_by_optional_tagging(tmp_path, monkeypatch, failure):
    envelope = execution_safety.policy("00000000-0000-0000-0000-000000000001", {
        "source_commit": "a" * 40, "target_commit": "b" * 40, "configuration": {}})
    guardian = execution_safety.AdmissionGuardian(envelope, tmp_path / "admission",
                                                  resolved_config_sha256="c" * 64)
    guardian.root.mkdir(parents=True)

    def exchange(client, command, **fields):
        # Only the socket transport is replaced; admission, stop latching and its journal are real.
        response = guardian._dispatch({"policy_sha256": client.digest, "command": command, **fields})
        if response.get("ok") is not True:
            raise execution_safety.ReviewStopped(response["reason"])
        return response

    monkeypatch.setattr(execution_safety.SafetyClient, "request", exchange)

    def cancelled(request):
        guardian.fail("offline cancellation", action="cancel")
        return valid_proposal(request)

    if failure == "cancelled":
        transport = Scripted(cancelled)
    else:
        error = (ProviderError("offline provider unavailable", code="unavailable") if failure == "provider"
                 else ExecutionContractError("offline integrity mismatch"))
        transport = Scripted(error=error)
    monkeypatch.setitem(inference.PROVIDERS, "offline", transport)
    with execution_safety.safety_scope(envelope):
        with pytest.raises(execution_safety.ReviewStopped):
            run_pass(tmp_path, monkeypatch, inference.infer)
        first_error = dict(guardian.state["first_error"])
        with pytest.raises(execution_safety.ReviewStopped, match="permanently stopped"):
            with execution_safety.operation("must-not-start"):
                pytest.fail("tagging failure allowed another operation")
    assert guardian.stopped.is_set() and guardian.state["status"] == "STOPPED"
    assert guardian.state["first_error"] == first_error
    assert json.loads(guardian.path.read_text())["first_error"] == first_error
    assert first_error["action"] == ("cancel" if failure == "cancelled" else "inference.offline.fixture")
    assert {"provider": "provider unavailable", "cancelled": "cancellation",
            "integrity": "integrity mismatch"}[failure] in first_error["reason"]
    assert len(transport.calls) == 1
    assert len(guardian.state["active"]) == 1
    assert next(iter(guardian.state["active"].values()))["status"] == "CLEANUP_UNCONFIRMED"
    artifacts = unit_context(tmp_path, job.MODEL_PASS).job.attempt_root / "artifacts" / "security-tagging"
    assert json.loads((artifacts / "facet-facts.json").read_text())["assignments"]
    assert not (artifacts / "model-pass.json").exists()
    assert not (artifacts / "unit-purposes.json").exists()


def test_component_budget_is_spent_only_on_eligible_components(tmp_path):
    vocabulary, rules, _ = taxonomy()
    sc = scope([{"component_id": "component:aaa-empty", "logical_id": "empty", "root": "empty"},
                {"component_id": "component:bbb-vendor", "logical_id": "vendor", "root": "third_party"},
                {"component_id": "component:zzz-app", "logical_id": "app", "root": "app"}])
    indexes = canned(("third_party/lib.py", "import jwt\n", "Python"), ("app/auth.py", "import jwt\n", "Python"))
    cfg = replace(settings(), model_pass=ModelPassSettings(enabled=True, max_components=1, model=MODEL))
    records, _, document = collect_facets(indexes, sc, vocabulary, rules, cfg, [], 100)
    transport = Scripted(lambda request: {
        "schema": PROPOSAL_SCHEMA, "component_id": request.allowed_components[0], "role": [], "asset": [],
        "purpose": "", "claims": [], "unknown": ["role", "asset", "purpose"]})
    _, gaps, result = run_model_pass(repository_root=ROOT, run_root=tmp_path, indexes=indexes, scope=sc,
                                    vocabulary=vocabulary, rules_sha256=rules.sha256, settings=cfg,
                                    collation=document, facet_records=records, infer=transport, limit=100,
                                    unit_id=job.MODEL_PASS)
    assert [call.allowed_components for call in transport.calls] == [("component:zzz-app",)]
    assert not any("model_pass_bound" in gap for gap in gaps)
    assert [row["status"] for row in result["components"]] == ["skipped", "skipped", "accepted"]


@pytest.mark.parametrize("suffix", ["ascii", "😀x", "e\u0301", "\u2028😀"], ids=["ascii", "non-bmp", "combining", "separator"])
def test_lexical_and_model_locations_resolve_raw_utf16_bytes(tmp_path, suffix):
    raw = ("# first line\r\nimport jwt # " + suffix + "\r\n").encode()
    unit, indexes, _ = accepted_catalog(tmp_path, {"app.py": raw})
    vocabulary, rules, _ = taxonomy()
    sc, records, _, document = collect(indexes)
    lexical = next(row for row in records if row["tag"] == "role:auth" and row["basis"] == "declared")
    transport = Scripted(lambda request: {
        "schema": PROPOSAL_SCHEMA, "component_id": request.allowed_components[0],
        "role": ["role:auth"], "asset": [], "purpose": "Authentication import.", "unknown": ["asset"],
        "claims": [{"tag": "role:auth", "citations": [{"path": "app.py", "line": 2}]}]})
    model_records, gaps, _ = run_model_pass(
        repository_root=ROOT, run_root=unit.job.run_root, indexes=indexes, scope=sc,
        vocabulary=vocabulary, rules_sha256=rules.sha256,
        settings=replace(settings(), model_pass=ModelPassSettings(enabled=True, model=MODEL)),
        collation=document, facet_records=records, infer=transport, limit=100, unit_id=job.MODEL_PASS)
    assert not gaps
    source = SourceFile.from_bytes(raw)
    for record in [lexical, *model_records]:
        location = job._subject_location(record)
        assert location.file_sha256 == hashlib.sha256(raw).hexdigest()
        assert location.start_line == location.end_line == 2
        assert source.offset(location.start_line, location.start_column) == location.start_byte == 14
        assert source.offset(location.end_line, location.end_column) == location.end_byte == len(raw) - 2
        assert raw[location.start_byte:location.end_byte] == ("import jwt # " + suffix).encode()
    assert file_sha256(unit.job.target_root / "app.py") == source.sha256


def test_invalid_utf8_is_a_gap_not_replacement_character_evidence(tmp_path):
    unit, indexes, _ = accepted_catalog(tmp_path, {"app.py": b"import jwt # \xff\n"})
    sc, records, gaps, document = collect(indexes)
    assert not any(row["basis"] == "declared" and row["tag"] == "role:auth" for row in records)
    assert any("source_unread" in gap for gap in gaps)
    vocabulary, rules, _ = taxonomy()
    transport = Scripted(lambda request: {
        "schema": PROPOSAL_SCHEMA, "component_id": request.allowed_components[0], "role": [], "asset": [],
        "purpose": "", "claims": [], "unknown": ["role", "asset", "purpose"]})
    _, gaps, _ = run_model_pass(
        repository_root=ROOT, run_root=unit.job.run_root, indexes=indexes, scope=sc,
        vocabulary=vocabulary, rules_sha256=rules.sha256,
        settings=replace(settings(), model_pass=ModelPassSettings(enabled=True, model=MODEL)),
        collation=document, facet_records=records, infer=transport, limit=100, unit_id=job.MODEL_PASS)
    assert any("model_pass_source_unread" in gap for gap in gaps)
    assert transport.calls[0].summary["excerpts"] == []
