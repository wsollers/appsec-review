"""T-5176: real accepted products retain coverage and bounded artifact capabilities."""

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from appsec_review.indexing.build_facts import build_command_facts
from appsec_review.indexing.derive import publish_derived
from appsec_review.indexing.products_base import AcceptedShards, to_derived
from appsec_review.indexing.sast import build_scanner_correlation
from appsec_review.jobs.job_artifact_indexing.datasets import DATASETS as ARTIFACT_DATASETS
from appsec_review.jobs.job_evidence_collection.datasets import DATASETS as SCANNER_DATASETS
from appsec_review.jobs.job_language_build.datasets import DATASETS as BUILD_DATASETS
from appsec_review.jobs.job_review_data_indexing.datasets import DATASETS as INDEX_DATASETS
from appsec_review.jobs.job_review_package_assembly.job import JOB_ID, _core, build_job
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.mcp.capability import ScopedRetrievalMcpAdapter, issue_capability
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RelationKind, RelationRecord, SourceLocation, write_manifest,
)
from appsec_review.review_packages import assemble_review_packages, verify_review_packages
from appsec_review.retrieval.model import canonical_json
from appsec_review.runtime.datasets import dataset_contract, shard_owner
from appsec_review.runtime.inputs import admit_inputs, input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from .test_handlers import _make_job_context, _make_unit_context


INDEX_JOB = "job_review_data_indexing"
BUILD_JOB = "job_language_build"
ARTIFACT_JOB = "job_artifact_indexing"
SCANNER_JOB = "job_evidence_collection"
_DECLARATIONS = {
    INDEX_JOB: INDEX_DATASETS, BUILD_JOB: BUILD_DATASETS,
    ARTIFACT_JOB: ARTIFACT_DATASETS, SCANNER_JOB: SCANNER_DATASETS,
}
_OMITTED = "2 exec command(s) omitted by the per-action bound"


def _fixture(tmp_path, *, empty=False, scanner_gaps=(), max_commands=3,
             build=True, fact_state=None, top_gaps=(), other_action=False):
    root = tmp_path / "runs" / "2026-11-19-5176"
    target = tmp_path / "target"
    target.mkdir()
    snapshot = "target-sha256:" + "9" * 64
    source = b"int parse(void) { return 0; }\n"
    (target / "main.c").write_bytes(source)
    location = SourceLocation(snapshot, "main.c", hashlib.sha256(source).hexdigest(),
                              0, len(source), 1, 1, 1, len(source), {}, "exact", 1.0)
    shards, handoffs, pins, handoff_paths = [], {}, {}, {}

    def identity(kind, key):
        return LogicalIdentity.derive(kind, snapshot, {"key": key})

    def shard(name, shard_id, producer, entities=(), relations=()):
        fingerprint = hashlib.sha256(canonical_json([name, shard_id])).hexdigest()
        path = root / "data" / "indices" / name / shard_id / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, shard_id=shard_id,
                               target_snapshot=snapshot, fingerprint=fingerprint)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(shard_id, "complete", None)
        owner = shard_owner(_DECLARATIONS[producer], name, shard_id)
        value = IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(),
                              fingerprint, path.relative_to(root).as_posix(),
                              {"job": producer, "unit": f"{owner.step}.fixture"}, (), shard_id)
        shards.append(asdict(value))
        return value

    def accept(producer, selected, extra=()):
        manifest_path = root / "data" / "indices" / "manifests" / f"{producer}.json"
        write_manifest(manifest_path, run_id=root.name, target_snapshot=snapshot,
                       target_root=target, indexes=[IndexIdentity(**item) for item in selected])
        manifest_ref = {"path": manifest_path.relative_to(root).as_posix(),
                        "sha256": file_sha256(manifest_path)}
        attempt = root / "data" / "jobs" / producer / "attempts" / "attempt_0001"
        declarations = _DECLARATIONS[producer]
        atomic_json(attempt / "claim.json", {"dataset_contract": dataset_contract(
            producer, sorted({item.step for item in declarations}), declarations)})
        outputs = {}
        for number, item in enumerate(selected):
            if item["producer"]["job"] != producer:
                continue
            owner = shard_owner(declarations, item["name"], item["shard_id"])
            outputs[f"{owner.step}.fixture_{number}"] = {
                "index_manifest": manifest_ref, "index_identity": item, "terminal_status": "SUCCEEDED"}
        path = write_fixture_handoff(root, attempt / "handoff.json", {
            "job_id": producer, "source_fingerprint": snapshot,
            "artifacts": [manifest_ref, *extra, *[
                {"path": item["relative_path"], "sha256": item["sha256"]} for item in selected]],
            "outputs": outputs,
        })
        pins[producer] = file_sha256(path)
        handoff_paths[producer] = path
        handoffs[producer] = SimpleNamespace(handoff=json.loads(path.read_bytes()))
        # Runtime must use the pin even with no ambient latest/accepted pointer.
        return manifest_path

    observation = identity(EntityKind.TOOL_OBSERVATION, "observation")
    shard("observations", "tool-semgrep", SCANNER_JOB, [] if empty else [
        EntityRecord(observation, "observation", "finding", "inert scanner observation",
                     {"tool_id": "tool-semgrep", "rule_id": "c.test", "category": "source_sast",
                      "severity": "high", "native_severity": "ERROR", "component": "component"},
                     location)])
    accept(SCANNER_JOB, list(shards))
    artifact = identity(EntityKind.BUILD_ARTIFACT, "matched")
    unrelated = identity(EntityKind.BUILD_ARTIFACT, "unrelated")
    action = identity(EntityKind.BUILD_ACTION, "action")
    product = None
    if build and not empty:
        capture = root / "data" / "capture" / "events.jsonl"
        capture.parent.mkdir(parents=True)
        capture.write_bytes(b"".join(canonical_json({
            "kind": "process_exec", "result": 0, "ordinal": ordinal,
            "argv": ["cc", "-c", "main.c", "-o", "main.o"],
            "envp": [{"name": "CFLAGS", "value": "-fstack-protector-strong"}],
        }) + b"\n" for ordinal in range(3)))
        build_entities = [EntityRecord(action, "action", "compile", "inert command",
            {"tool": "cc", "execution_capture": {"events_sha256": file_sha256(capture)}}, None)]
        if other_action:
            build_entities.append(EntityRecord(identity(EntityKind.BUILD_ACTION, "other"), "other",
                "other", "unselected action with no capture", {"tool": "cc"}, None))
        build_shard = shard("build", "language-build-unit", BUILD_JOB, build_entities)
        accept(BUILD_JOB, [asdict(build_shard)], [{
            "path": capture.relative_to(root).as_posix(), "sha256": file_sha256(capture)}])
        artifact_shard = shard("artifacts", "catalog-unit", ARTIFACT_JOB, [
            EntityRecord(item, item.value, "main.o", "inert artifact",
                         {"sha256": "7" * 64, "path": "main.o"}, None)
            for item in (artifact, unrelated)])
        relation_shard = shard("artifacts", "relations-unit", ARTIFACT_JOB, relations=[
            RelationRecord(RelationKind.GENERATED_FROM, artifact.value, action.value,
                           True, 1.0, None, {"mapping_method": "accepted_action"})])
        accept(ARTIFACT_JOB, [asdict(build_shard), asdict(artifact_shard), asdict(relation_shard)])
        product = build_command_facts(AcceptedShards(root, shards, snapshot), root, handoffs,
                                      max_events=10, max_commands=max_commands)
        if fact_state is not None:
            product.facts[0].coverage = fact_state

    scanner = build_scanner_correlation(
        AcceptedShards(root, shards, snapshot), {"files": {}}, [],
        {"menu_partition_size": 20}, scanner_gaps=scanner_gaps)
    for current in [scanner, *([product] if product is not None else [])]:
        derived = to_derived(current, snapshot, 20)
        if current is product and top_gaps:
            entity = derived.entities[0]
            derived.entities[0] = replace(entity, payload={**entity.payload, "gaps": list(top_gaps)})
        publication = publish_derived(
            root, index="precomputed", shard_id=f"qs-{current.query_set}", job_id=INDEX_JOB,
            unit_id=f"precompute.{current.query_set}", rule=current.query_set,
            rule_version=current.rule_version, snapshot=snapshot,
            inputs={"shards": current.inputs}, build=lambda: derived,
            producer={"query_set": current.query_set})
        shards.append(publication["index_identity"])
    shard("inventory", "dataset-inventory", INDEX_JOB)
    manifest_path = accept(INDEX_JOB, shards)
    context = _make_job_context(root, target, source_fingerprint=snapshot,
                               manifest_path=manifest_path, manifest_sha=file_sha256(manifest_path))
    context = replace(context, upstream_handoffs=pins, evidence_target_snapshot=snapshot)
    claim = json.loads((context.attempt_root / "claim.json").read_bytes())
    atomic_json(context.attempt_root / "claim.json", {**claim, "upstream_handoffs": pins})
    return SimpleNamespace(context=context, root=root, shards=shards, product=product,
                           artifact=artifact.value, unrelated=unrelated.value,
                           handoff_paths=handoff_paths)


def _publish(fixture):
    ctx = fixture.context
    admit_inputs(ctx, set(ctx.upstream_handoffs))
    with input_read_scope(ctx) as reads:
        result = build_job().handler(ctx)
        assert result["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}, result
        output = result["outputs"]["publication.publish_packages"]
        assert result["status"] == output["terminal_status"]
        core, _, _ = _core(_make_unit_context(ctx))
        directory = fixture.root / output["package_directory"]
        manifest = verify_review_packages(core, directory)
    packages = [json.loads((directory / f"{item['package_id']}.json").read_bytes())
                for item in manifest["packages"]]
    return output, manifest, packages, core, reads.document()


@pytest.mark.parametrize("reason", [None, "scanner failed; no completed source scan"],
                         ids=["complete-empty", "partial-empty"])
def test_empty_accepted_scanner_product_retains_run_coverage(tmp_path, reason):
    fixture = _fixture(tmp_path, empty=True, scanner_gaps=() if reason is None else (reason,))
    output, manifest, packages, core, _ = _publish(fixture)
    assert packages == [] and output["package_count"] == 0
    assert output["terminal_status"] == ("SUCCEEDED" if reason is None else "COMPLETED_WITH_GAPS")
    assert bool(manifest["coverage_gaps"]) is (reason is not None)
    if reason is not None:
        assert any(item["reason"] == reason for item in manifest["coverage_gaps"])
        assert all(item["schema"] == "appsec-review/producer-gap/1" for item in output["gaps"])
        assert any(reason in item["reason"] for item in output["gaps"])
    assert output["coverage_gap_count"] == len(output["gaps"]) == len(manifest["coverage_gaps"])
    assert assemble_review_packages(core) == (packages, manifest)


def test_selected_partial_build_retains_exact_omitted_work(tmp_path):
    fixture = _fixture(tmp_path, max_commands=1)
    assert fixture.product.status == "complete"
    assert fixture.product.facts[0].coverage == "partial"
    assert fixture.product.facts[0].result["gaps"] == [_OMITTED]
    output, manifest, packages, _, _ = _publish(fixture)
    assert len(packages) == 2
    for package in packages:
        assert len(package["build_context"]["command_facts"]) == 1
        assert package["build_context"]["environment_facts"][0]["safe_value"] == "-fstack-protector-strong"
        assert any(gap["reason"] == _OMITTED and gap["state"] == "partial"
                   and gap["producer"] == "build_provenance" and gap["scope"] in package["context_ids"]
                   for gap in package["coverage_gaps"])
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert sum(gap["reason"] == _OMITTED for gap in manifest["coverage_gaps"]) == 1
    assert sum(_OMITTED in gap["reason"] for gap in output["gaps"]) == 1


@pytest.mark.parametrize(("state", "reasons"), [
    ("partial", ()), ("unavailable", ()), ("complete", ("omitted environment details",)),
], ids=["partial", "unavailable", "complete-with-gap"])
def test_selected_build_fact_status_and_top_level_reasons_survive(tmp_path, state, reasons):
    fixture = _fixture(tmp_path, fact_state=state, top_gaps=reasons)
    _, _, packages, _, _ = _publish(fixture)
    for package in packages:
        gaps = [gap for gap in package["coverage_gaps"]
                if gap["producer"] == "build_provenance" and gap["scope"] in package["context_ids"]]
        assert len(gaps) == 1 and gaps[0]["state"] == ("partial" if state == "complete" else state)
        if reasons:
            assert gaps[0]["reason"] == reasons[0]
        else:
            assert state in gaps[0]["reason"]


def test_complete_selected_build_is_not_qualified_by_unselected_partial_fact(tmp_path):
    fixture = _fixture(tmp_path, other_action=True)
    _, _, packages, _, _ = _publish(fixture)
    for package in packages:
        assert len(package["build_context"]["command_facts"]) == 3
        assert not [gap for gap in package["coverage_gaps"]
                    if gap["producer"] == "build_provenance" and gap["scope"] in package["context_ids"]]


def _scoped(core, package):
    secret = b"p" * 32
    token = issue_capability(package, role="red", round_id="1", secret=secret,
                             expires_at=int(time.time()) + 300)
    return ScopedRetrievalMcpAdapter(RetrievalMcpAdapter(core), package, capability=token,
                                     secret=secret, role="red", round_id="1")


def test_scoped_artifact_resolves_exact_accepted_row_without_widening_grant(tmp_path):
    fixture = _fixture(tmp_path)
    _, _, packages, core, _ = _publish(fixture)
    for package in packages:
        assert package["scope"]["artifact_ids"] == [fixture.artifact]
        scoped = _scoped(core, package)
        with input_read_scope(fixture.context) as reads:
            result = scoped.call("find", {"identity": fixture.artifact})
        assert result["results"][0]["identity"] == fixture.artifact
        assert result["results"][0]["payload"]["sha256"] == "7" * 64
        artifact_reads = [item for item in reads.document()["reads"] if item["producer"] == ARTIFACT_JOB]
        assert {item["output_kind"] for item in artifact_reads} == {
            "artifact_catalog", "artifact_relationships"}
        assert {(item["path"], item["sha256"]) for item in artifact_reads} == {
            (item["relative_path"], item["sha256"]) for item in fixture.shards
            if item["producer"]["job"] == ARTIFACT_JOB}
        assert all(item["handoff_sha256"] == fixture.context.upstream_handoffs[ARTIFACT_JOB]
                   and item["read"] is True and item["cited"] is None for item in artifact_reads)
        with pytest.raises(ValueError, match="outside review package"):
            scoped.call("find", {"identity": fixture.unrelated})


@pytest.mark.parametrize("failure", ["unadmitted", "undeclared", "tampered", "missing"])
def test_scoped_artifact_read_requires_declared_pin_and_exact_bytes(tmp_path, failure):
    fixture = _fixture(tmp_path)
    _, _, packages, core, _ = _publish(fixture)
    context = fixture.context
    if failure == "unadmitted":
        context = replace(context, upstream_handoffs={
            job: sha for job, sha in context.upstream_handoffs.items() if job != ARTIFACT_JOB})
    elif failure == "undeclared":
        context = replace(context, contract=replace(context.contract, inputs=tuple(
            item for item in context.contract.inputs if item.producer != ARTIFACT_JOB)))
    else:
        shard = next(item for item in fixture.shards if item["shard_id"] == "catalog-unit")
        path = fixture.root / shard["relative_path"]
        if failure == "tampered":
            path.write_bytes(path.read_bytes() + b"changed")
        else:
            path.unlink()
    messages = {"unadmitted": "unsupplied shard producer", "undeclared": "undeclared consumption",
                "tampered": "shard bytes changed|integrity", "missing": "No such file|unavailable"}
    with pytest.raises((ValueError, OSError), match=messages[failure]), input_read_scope(context):
        _scoped(core, packages[0]).call("find", {"identity": fixture.artifact})


def test_optional_build_absence_does_not_invent_artifact_grants(tmp_path):
    fixture = _fixture(tmp_path, build=False)
    output, _, packages, _, _ = _publish(fixture)
    assert output["terminal_status"] == "COMPLETED_WITH_GAPS"
    for package in packages:
        assert package["scope"]["artifact_ids"] == []
        assert fixture.artifact not in package["retrieval"]["entity_ids"]
        assert any(gap["reason"] == "no source-matched safe build-action facts"
                   for gap in package["coverage_gaps"])


def test_publication_rejects_missing_admitted_indexing_handoff(tmp_path):
    fixture = _fixture(tmp_path, empty=True)
    fixture.handoff_paths[INDEX_JOB].unlink()
    with pytest.raises(ValueError, match="accepted.*handoff"), input_read_scope(fixture.context):
        build_job().units[0].handler(_make_unit_context(fixture.context))


def test_empty_package_manifest_rejects_removed_coverage(tmp_path):
    fixture = _fixture(tmp_path, empty=True, scanner_gaps=("scanner work missing",))
    output, manifest, _, core, _ = _publish(fixture)
    assert manifest["coverage_gaps"]
    directory = fixture.root / output["package_directory"]
    atomic_json(directory / "manifest.json", {**manifest, "coverage_gaps": []})
    with pytest.raises(ValueError, match="manifest integrity mismatch"):
        verify_review_packages(core, directory)
