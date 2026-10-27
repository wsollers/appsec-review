from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import jsonschema
import pytest

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    write_manifest,
)
from appsec_review.retrieval.core import RetrievalCore
from appsec_review.review.lead_families import collect_leads
from appsec_review.review.package_view import ViewLimits, build_view
from appsec_review.review.packages import PackageSettings, assemble_packages, publish_packages
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import file_sha256
from tests.fixtures.inference_review.builder import SNAPSHOT, build_accepted_index_set


@pytest.fixture(scope="module")
def artifact_run(tmp_path_factory):
    fixture = build_accepted_index_set(tmp_path_factory.mktemp("artifact-packages"))
    manifest = json.loads((fixture.run_root / "data/indices/manifests/fixture.json").read_text())
    identities = [IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))}) for raw in manifest["indexes"]]
    ids = {}

    def identity(kind, key):
        value = LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": key})
        ids[key] = value.value
        return value

    artifact = identity(EntityKind.MANAGED_ASSEMBLY, "dll")
    observation = identity(EntityKind.TOOL_OBSERVATION, "blint")
    action = identity(EntityKind.BUILD_ACTION, "compile")
    linked = identity(EntityKind.EXECUTABLE, "application")
    fact = identity(EntityKind.PRECOMPUTED_FACT, "command")
    path = "native/obj/refint/weak.dll"
    data = {"workspace_path": path, "path": f"data/build/{path}", "sha256": "a" * 64,
            "build_unit_id": "native-main"}

    def builder(name, shard):
        p = fixture.run_root / f"data/indices/{shard}.sqlite"
        return IndexBuilder(p, name=name, fingerprint="b" * 64, target_snapshot=SNAPSHOT, shard_id=shard)

    def publish(b, job, *, gaps=(), query_set=None):
        b.add_coverage("fixture", "partial" if gaps else "complete", gaps[0] if gaps else None)
        producer = {"job": job}
        if query_set:
            producer["query_set"] = query_set
        identities.append(IndexIdentity(b.name, "appsec-review/retrieval-index/2", b.build(), "b" * 64,
                                        b.path.relative_to(fixture.run_root).as_posix(), producer,
                                        tuple(gaps), b.shard_id))

    b = builder("observations", "artifact-scans")
    b.add_entity(EntityRecord(artifact, path, "weak.dll", path, data))
    b.add_entity(EntityRecord(observation, "blint", "CHECK_DLL_CHARACTERISTICS", "missing NX_COMPAT",
                             {"record_kind": "finding", "tool_id": "tool-blint", "category": "binary_hardening",
                              "native_rule_id": "CHECK_DLL_CHARACTERISTICS", "native_severity": "high",
                              "severity": "high", "message": "Missing DLL characteristics",
                              "subject_artifact": artifact.value, "artifact": data, "gaps": [],
                              "exit_code": 0, "timed_out": False}))
    b.add_relation(RelationRecord(RelationKind.OBSERVED_AT, observation.value, artifact.value, True, 1.0))
    same = identity(EntityKind.TOOL_OBSERVATION, "same-artifact-grype")
    b.add_entity(EntityRecord(same, "grype", "grype", "", {
        "record_kind": "scan_summary", "scanner_identity": "tool-grype", "category": "tool_diagnostic",
        "artifact": {"canonical_identity": artifact.value}, "gaps": ["SBOM unavailable for this artifact"]}))
    b.add_relation(RelationRecord(RelationKind.OBSERVED_AT, same.value, artifact.value, True, 1.0))
    unrelated = []
    for number in range(463):
        other = identity(EntityKind.MANAGED_ASSEMBLY, f"other-{number}")
        summary = identity(EntityKind.TOOL_OBSERVATION, f"summary-{number}")
        gap = f"{other.value}: unrelated artifact {number} has no SBOM or producing action"
        unrelated.append(gap)
        b.add_entity(EntityRecord(other, f"other-{number}", f"other-{number}.dll", "",
                                 {"workspace_path": f"other/{number}.dll", "sha256": "d" * 64}))
        b.add_entity(EntityRecord(summary, str(number), "grype", "", {
            "record_kind": "scan_summary", "tool_id": "tool-grype", "category": "vulnerability_matching",
            "subject_artifact": other.value, "gaps": [gap]}))
        b.add_relation(RelationRecord(RelationKind.OBSERVED_AT, summary.value, other.value, True, 1.0))
    publish(b, "job_artifact_security_analysis", gaps=unrelated)

    b = builder("artifacts", "dll-provenance")
    b.add_entity(EntityRecord(artifact, path, "weak.dll", path,
                             {key: value for key, value in data.items() if key != "path"}))
    b.add_entity(EntityRecord(action, "compile", "compiler", "", {
        "tool": "csc", "working_directory": "native", "argv_sha256": "c" * 64}))
    b.add_entity(EntityRecord(linked, "app", "app.exe", "", {"workspace_path": "native/bin/app.exe"}))
    b.add_relation(RelationRecord(RelationKind.GENERATED_FROM, artifact.value, action.value, False, .25,
                                  "producer mapping is ambiguous"))
    b.add_relation(RelationRecord(RelationKind.LINKS_INTO, artifact.value, linked.value, True, 1.0))
    publish(b, "job_artifact_indexing")

    b = builder("precomputed", "safe-build-command")
    b.add_entity(EntityRecord(fact, "command", "build", "", {
        "fact_type": "build_action", "result": {"build_action_id": action.value,
        "exact_command_sha256": "c" * 64, "command_facts": [{"ordered_tokens": [
            {"safe_value": "csc", "kind": "tool"}, {"safe_value": "/out:weak.dll", "kind": "output"},
            {"kind": "redacted"}]}]}}))
    publish(b, "job_precompute_build_provenance", query_set="build_provenance")
    manifest_path = fixture.run_root / "data/indices/manifests/artifact-test.json"
    write_manifest(manifest_path, run_id=fixture.run_id, target_snapshot=SNAPSHOT, target_root=fixture.target,
                   indexes=identities, upstream_manifests=manifest.get("upstream_manifests", ()))
    scope = accept_manifest(fixture.run_root, manifest_path=manifest_path,
                            manifest_sha256=file_sha256(manifest_path))
    return fixture, scope, ids, unrelated


def test_scanner_gap_is_artifact_local_and_global_coverage_is_preserved(artifact_run):
    fixture, scope, ids, unrelated = artifact_run
    settings = replace(PackageSettings(), max_package_bytes=65536)
    collection = collect_leads(scope)
    lead = next(lead for lead in collection.leads if lead.observation_id == ids["blint"])
    assert lead.related == ((ids["dll"], "artifact"),)
    assert not lead.coverage_gaps
    assembly = assemble_packages(scope, settings=settings, collection=collection)
    package = next(p for p in assembly.packages if p.lead_ids == (ids["blint"],))
    doc = package.document()
    assert len(package.body) <= 65536
    assert doc["scope"]["artifact_ids"] == [ids["dll"]]
    assert doc["scope"]["build_unit_id"] == "native-main"
    assert not any("unrelated artifact" in gap["reason"] for gap in doc["coverage_gaps"])
    assert not any(gap["producer"].startswith("code_graph") for gap in doc["coverage_gaps"])
    assert any(gap["producer"] == "tool-grype" and gap["scope"] == ids["dll"]
               and "SBOM" in gap["reason"] for gap in doc["coverage_gaps"])
    assert not any(gap["producer"] == "tool-blint" for gap in doc["coverage_gaps"])
    assert set(unrelated) <= {gap["reason"] for gap in assembly.manifest["gaps"]}
    assert assembly.manifest["audit"]["lane_a"]["status"] == "passed"
    assert any(p.kind == "hunt" for p in assembly.packages)
    schema = json.loads((Path(__file__).parents[2] / "docs/schemas/review-packages.schema.json").read_text())
    for p in assembly.packages:
        jsonschema.validate(p.document(), schema)
    again = assemble_packages(scope, settings=settings, collection=collection)
    assert assembly.manifest_bytes == again.manifest_bytes
    publish_packages(assembly, fixture.run_root / "package-test-output")


def test_dll_identity_safe_commands_and_ambiguous_mapping_reach_view(artifact_run):
    _, scope, ids, _ = artifact_run
    assembly = assemble_packages(scope)
    doc = next(p.document() for p in assembly.packages if p.lead_ids == (ids["blint"],))
    artifact = doc["lead_menu"][0]["artifacts"][0]
    assert artifact["name"] == "weak.dll" and artifact["workspace_path"] == "native/obj/refint/weak.dll"
    assert artifact["sha256"] == "a" * 64
    assert artifact["path"] == "data/build/native/obj/refint/weak.dll"
    producing = next(row for row in artifact["provenance"] if row["relation"] == "GENERATED_FROM")
    assert producing["exact"] is False and producing["confidence"] == .25
    assert producing["commands"][0]["text"] == "csc /out:weak.dll <redacted>"
    assert any(row["relation"] == "LINKS_INTO" and row["target_id"] == ids["application"]
               for row in artifact["provenance"])
    assert {ids["dll"], ids["compile"], ids["application"], ids["command"]} <= set(doc["retrieval"]["entity_ids"])
    core = RetrievalCore(scope.run_root.parent, scope.run_id, manifest_path=scope.manifest_path,
                         manifest_sha256=scope.manifest_sha256)
    view = build_view(doc, core, limits=ViewLimits())
    rendered = json.dumps(view.document)
    assert "native/obj/refint/weak.dll" in rendered and "csc /out:weak.dll" in rendered
    assert "no source text for the lead" not in rendered
    assert "SBOM unavailable for this artifact" in rendered
    assert "producer mapping is ambiguous" in rendered


def test_missing_link_provenance_is_unknown_not_unused(artifact_run):
    from appsec_review.review.artifact_context import ArtifactContext
    _, scope, ids, _ = artifact_run
    lead = next(lead for lead in collect_leads(scope).leads if lead.observation_id == ids["blint"])
    context = ArtifactContext(scope)
    context.relations[ids["dll"]] = []
    records, _, gaps = context.for_lead(lead, limit=64)
    assert records[0]["provenance"] == []
    assert any("absence does not prove unused" in gap.reason for gap in gaps)
    assert any("build command is unknown" in gap.reason for gap in gaps)


def test_hunt_size_probe_includes_continuation_and_partition_local_artifacts(artifact_run, monkeypatch):
    from appsec_review.review.packages import _Assembler
    _, scope, ids, _ = artifact_run
    build = _Assembler._build
    probes = []

    def checked(self, **kwargs):
        if kwargs["kind"] == "hunt" and kwargs["partition"][1] == 99_999:
            probes.append(kwargs["truncation"]["next_partition"])
        return build(self, **kwargs)

    monkeypatch.setattr(_Assembler, "_build", checked)
    assembly = assemble_packages(scope, PackageSettings(hunt_menu_partition_size=1))
    assert probes and all(probes)
    for package in assembly.packages:
        if package.kind != "hunt":
            continue
        doc = package.document()
        if ids["blint"] not in package.lead_ids:
            assert ids["dll"] not in doc["scope"]["artifact_ids"]
            assert ids["dll"] not in doc["retrieval"]["entity_ids"]
        else:
            artifact = doc["lead_menu"][0]["artifacts"][0]
            assert artifact["provenance"] == [] and artifact["provenance_omitted"] == 2


def test_own_scan_gap_and_provenance_truncation_remain_explicit(artifact_run):
    from appsec_review.review.artifact_context import ArtifactContext
    from appsec_review.review.scope import ScopeGap
    _, scope, ids, _ = artifact_run
    collection = collect_leads(scope)
    own = ScopeGap("tool-blint", ids["blint"], "partial", "Blint inspected only some metadata")
    collection = replace(collection, leads=tuple(
        replace(lead, coverage_gaps=(own,)) if lead.observation_id == ids["blint"] else lead
        for lead in collection.leads))
    assembly = assemble_packages(scope, collection=collection)
    doc = next(p.document() for p in assembly.packages
               if p.kind == "finding_lead" and p.lead_ids == (ids["blint"],))
    assert own.record() in doc["coverage_gaps"]
    context = ArtifactContext(scope)
    lead = next(lead for lead in collection.leads if lead.observation_id == ids["blint"])
    records, _, gaps = context.for_lead(lead, limit=1)
    assert records[0]["provenance_omitted"] == 1
    assert any(gap.state == "truncated" for gap in gaps)
