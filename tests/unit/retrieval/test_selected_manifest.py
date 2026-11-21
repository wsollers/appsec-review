"""Selected accepted views narrow reads, never the grant or custody checks."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity,
    RelationKind, RelationRecord, RetrievalCore, SourceLocation, write_manifest,
)
from appsec_review.retrieval.index import IndexSelection, load_verified_manifest
from appsec_review.review.scope import accept_manifest
from appsec_review.review.models import IntegrityError
from appsec_review.runtime.contracts import EvidenceAuthority, InputRequirement, JobContract
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.validation import validation_scope
from tests.handoff_fixture import write_fixture_handoff


CATALOG = "job_target_catalog"
HISTORY = "job_source_history_analysis"
SOURCE = IndexSelection(((CATALOG, "source"),))
BOTH = IndexSelection(((CATALOG, "source"), (HISTORY, "history")))


def fixture(tmp_path, *, relation=False, binary=False, generated=False):
    root = tmp_path / "runs" / "2026-11-21-0001"
    target = tmp_path / "target"
    target.mkdir()
    snapshot = "target-sha256:" + "1" * 64
    data = b"int inert(void) { return 1; }\n"
    (target / "file.c").write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    path, native, backing = "file.c", {}, None
    if binary:
        from appsec_review.retrieval.source_resolution import publish_binary_source, binary_source_path
        path = binary_source_path("b" * 64, "0x1")
        backing = publish_binary_source(root, target_snapshot=snapshot, binary_sha256="b" * 64,
            address="0x1", publication_identity="c" * 64, manifest_sha256="d" * 64, data=data)
        native = {"source_domain": "binary", "source_backing": backing}
    elif generated:
        from appsec_review.retrieval.source_resolution import generated_path, publish_source
        canonical = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {
            "build_unit_id": "build", "workspace_path": "out/file.c", "sha256": sha,
            "format": "generated-source"})
        path = generated_path(canonical.value, "out/file.c")
        backing = publish_source(root, target_snapshot=snapshot, logical_path=path, build_unit_id="build",
            handoff_sha256="a" * 64, data=data, artifact={
                "canonical_identity": canonical.value, "workspace_path": "out/file.c", "sha256": sha,
                "kind": "generated-source", "scope_role": "deliverable", "artifact_origin": "build-output"})
        native = {"source_domain": "generated", "source_backing": backing}
    custody_job = "job_binary_evidence_indexing" if binary else "job_tree_sitter_ast"
    custody_output = "binary_pseudo_c" if binary else "generated_source_backing"
    custody_schema = "appsec-review/" + ("binary" if binary else "generated") + "-source-backing/1"
    source = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": path})
    second = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": "second.c"})
    other = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"history": "one"})
    indexes = []
    for name, producer, ids in (("source", CATALOG, (source, second)), ("history", HISTORY, (other,))):
        shard_id = "default" if name == "source" else "git-history"
        index_path = root / "data/indices" / name / "selected.sqlite"
        build = IndexBuilder(index_path, name=name, fingerprint="f" * 64,
                             target_snapshot=snapshot, shard_id=shard_id)
        for identity in ids:
            location = SourceLocation(snapshot, path, sha, 0, len(data), 1, 1, 1, 1,
                                      native, "test-exact", 1.0) if name == "source" else None
            build.add_entity(EntityRecord(identity, identity.value, identity.value, "inert", {}, location))
        if relation and name == "source":
            build.add_relation(RelationRecord(RelationKind.DERIVED_FROM, source.value, other.value, True, 1.0))
        build.add_coverage(name, "complete")
        indexes.append(IndexIdentity(name, "appsec-review/retrieval-index/2", build.build(), "f" * 64,
                                     index_path.relative_to(root).as_posix(), {"job": producer}, shard_id=shard_id))
    manifest = root / "data/indices/manifests/selected.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=snapshot, target_root=target, indexes=indexes)
    pins = {}
    registry = builtin_registry()
    for producer, refs in [
        (CATALOG, [{"path": indexes[0].relative_path, "sha256": indexes[0].sha256}]),
        (HISTORY, [{"path": indexes[1].relative_path, "sha256": indexes[1].sha256}]),
        *([(custody_job, [backing])] if backing else []),
    ]:
        handoff = root / "data/jobs" / producer / "attempts/attempt_0001/handoff.json"
        job = registry.build(producer)
        atomic_json(handoff.with_name("claim.json"), {"dataset_contract": dataset_contract(
            producer, tuple(dict.fromkeys(item.step for item in job.datasets)), job.datasets)})
        write_fixture_handoff(root, handoff, {"job_id": producer, "artifacts": refs,
            "outputs": {"test.publish": {"terminal_status": "SUCCEEDED"}}}, target_snapshot=snapshot)
        pins[producer] = file_sha256(handoff)
        atomic_json(handoff.parent.parent.parent / "latest.json", {
            "handoff_path": handoff.relative_to(root).as_posix(), "handoff_sha256": pins[producer]})
    requirements = [
        InputRequirement(CATALOG, "source_files", "appsec-review/retrieval-index/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement(HISTORY, "history_signals", "appsec-review/retrieval-index/2",
                         authority=EvidenceAuthority.ROUTING_CONTEXT),
    ]
    if backing:
        requirements.extend((
            InputRequirement(custody_job, custody_output, custody_schema,
                             authority=EvidenceAuthority.PRODUCER_EVIDENCE),
            InputRequirement(custody_job, "handoff",
                             "appsec-review/job-handoff/2", authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        ))
    context = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id="job_owasp_control_assessment"),
                              upstream_handoffs=pins, contract=JobContract(inputs=tuple(requirements)))
    return SimpleNamespace(root=root, target=target, manifest=manifest, sha=file_sha256(manifest),
                           indexes=indexes, context=context, source=source.value, backing=backing,
                           custody_job=custody_job, custody_output=custody_output)


def read(value, selection=SOURCE):
    return RetrievalCore(value.root.parent, value.root.name, manifest_path=value.manifest,
                         manifest_sha256=value.sha, selection=selection)


def test_selected_reads_preserve_full_identity_and_leave_excluded_payload_unopened(tmp_path):
    value = fixture(tmp_path)
    (value.root / value.indexes[1].relative_path).write_bytes(b"excluded payload is deliberately unavailable")
    with input_read_scope(value.context) as reads:
        core = read(value)
        scope = accept_manifest(value.root, manifest_path=value.manifest, manifest_sha256=value.sha,
                                selection=SOURCE)
        assert core.find(identity=value.source)["results"]
    assert core.manifest_sha256 == scope.manifest_sha256 == value.sha
    assert len(core.manifest["indexes"]) == 2
    assert core.view_identity == scope.view_identity != value.sha
    assert list(core.indexes) == ["source"] and scope.index_names == ("source",)
    assert scope.evidence_map()["excluded_shards"][0]["disposition"] == "not_selected"
    assert {item["producer"] for item in reads.document()["reads"]} == {CATALOG}
    assert all(item["read"] and item["cited"] is None for item in reads.document()["reads"])
    with pytest.raises(ValueError):
        load_verified_manifest(value.root, value.manifest, value.sha)


@pytest.mark.parametrize("damage", ["bytes", "symlink", "pin", "grant", "owner", "path"])
def test_selected_payload_still_requires_custody_and_exact_grant(tmp_path, damage):
    value = fixture(tmp_path)
    source_path = value.root / value.indexes[0].relative_path
    if damage == "bytes":
        source_path.write_bytes(b"changed")
    elif damage == "symlink":
        moved = source_path.with_name("moved.sqlite")
        source_path.rename(moved)
        source_path.symlink_to(moved)
    elif damage == "pin":
        value.context.upstream_handoffs = {}
    elif damage == "grant":
        value.context.contract = JobContract(inputs=())
    else:
        changed = replace(value.indexes[0], producer={"job": HISTORY}) if damage == "owner" else replace(
            value.indexes[0], relative_path="data/indices/source/other.sqlite")
        write_manifest(value.manifest, run_id=value.root.name, target_snapshot="target-sha256:" + "1" * 64,
                       target_root=value.target, indexes=(changed, value.indexes[1]))
        value.sha = file_sha256(value.manifest)
    selection = IndexSelection(((CATALOG, "source"), (HISTORY, "source")))
    with pytest.raises(ValueError), input_read_scope(value.context):
        read(value, selection)


@pytest.mark.parametrize("prior", ["full", "selected", "admitted"])
def test_full_other_view_and_admitted_memos_do_not_attest_selected_bytes(tmp_path, prior):
    value = fixture(tmp_path)
    memo = {}
    with validation_scope(value.root) as validation:
        if prior == "admitted":
            document = json.loads(value.manifest.read_text())
            validation.admitted_manifests[value.manifest.relative_to(value.root).as_posix()] = {
                "sha256": value.sha, "document": document}
            for identity in value.indexes:
                validation.admitted[(identity.relative_path, identity.sha256)] = (
                    value.root / identity.relative_path).stat().st_size
        else:
            load_verified_manifest(value.root, value.manifest, value.sha, verified=memo,
                                   selection=None if prior == "full" else SOURCE)
        path = value.root / value.indexes[1 if prior == "selected" else 0].relative_path
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with pytest.raises(ValueError), input_read_scope(value.context):
            load_verified_manifest(value.root, value.manifest, value.sha, verified=memo,
                                   selection=BOTH if prior == "selected" else SOURCE)


def test_relations_require_explicitly_selected_and_admitted_endpoint_closure(tmp_path):
    value = fixture(tmp_path, relation=True)
    with pytest.raises(ValueError, match="selected relation endpoint"), input_read_scope(value.context):
        read(value)
    with input_read_scope(value.context) as reads:
        core = read(value, BOTH)
    assert set(core.indexes) == {"source", "history"}
    assert {item["producer"] for item in reads.document()["reads"]} == {CATALOG, HISTORY}


def test_views_cannot_share_query_cursors(tmp_path):
    value = fixture(tmp_path)
    with input_read_scope(value.context):
        first, second = read(value), read(value, BOTH)
        page = first.find(kind="source_file", limit=1)
        assert page["pagination"]["next_cursor"]
        with pytest.raises(ValueError):
            second.find(kind="source_file", limit=1, cursor=page["pagination"]["next_cursor"])


@pytest.mark.parametrize("reader", ["core", "scope", "manifest"])
def test_selected_views_do_not_fall_back_to_ambient_manifest_authority(tmp_path, reader):
    value = fixture(tmp_path)
    with pytest.raises((ValueError, IntegrityError), match="explicit manifest path and pin"):
        if reader == "core":
            RetrievalCore(value.root.parent, value.root.name, selection=SOURCE)
        elif reader == "scope":
            accept_manifest(value.root, selection=SOURCE)
        else:
            load_verified_manifest(value.root, value.manifest, selection=SOURCE)


def test_owasp_and_core_reject_a_symlinked_manifest_even_with_matching_bytes(tmp_path):
    from appsec_review.jobs.job_owasp_control_assessment.job import _core
    value = fixture(tmp_path)
    moved = value.manifest.with_name("moved.json")
    value.manifest.rename(moved)
    value.manifest.symlink_to(moved)
    value.context.input_manifest_path = value.manifest
    value.context.input_manifest_sha256 = value.sha
    with pytest.raises(ValueError):
        _core(SimpleNamespace(job=value.context))
    with pytest.raises(ValueError):
        read(value)


@pytest.mark.parametrize("damage", ["none", "hash", "target", "run", "symlink"])
def test_selected_view_authenticates_ancestry_even_without_selected_parent_payloads(tmp_path, damage):
    value = fixture(tmp_path)
    parent = value.manifest.with_name("parent.json")
    snapshot = "target-sha256:" + ("2" if damage == "target" else "1") * 64
    write_manifest(parent, run_id="2026-11-21-0002" if damage == "run" else value.root.name,
                   target_snapshot=snapshot, target_root=value.target, indexes=())
    parent_sha = file_sha256(parent)
    write_manifest(value.manifest, run_id=value.root.name, target_snapshot="target-sha256:" + "1" * 64,
                   target_root=value.target, indexes=value.indexes, upstream_manifests=(
                       {"path": parent.relative_to(value.root).as_posix(), "sha256": parent_sha},))
    value.sha = file_sha256(value.manifest)
    if damage == "hash":
        parent.write_text(parent.read_text() + " ")
    elif damage == "symlink":
        moved = parent.with_name("moved.json")
        parent.rename(moved)
        parent.symlink_to(moved)
    if damage == "none":
        with input_read_scope(value.context):
            assert read(value).find(identity=value.source)["results"]
    else:
        with pytest.raises(ValueError), input_read_scope(value.context):
            read(value)


def test_selected_queries_do_not_reuse_outer_full_digest_admission(tmp_path):
    value = fixture(tmp_path)
    with validation_scope(value.root) as validation:
        core = read(value)
        identity = value.indexes[0]
        path = value.root / identity.relative_path
        validation.admitted[(identity.relative_path, identity.sha256)] = path.stat().st_size
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with pytest.raises(ValueError), input_read_scope(value.context):
            core.find(identity=value.source)


def test_ancestry_availability_does_not_read_obsolete_selected_producer_payloads(tmp_path):
    value = fixture(tmp_path)
    parent = value.manifest.with_name("previous.json")
    obsolete = replace(value.indexes[0], relative_path="data/indices/source/obsolete.sqlite")
    write_manifest(parent, run_id=value.root.name, target_snapshot="target-sha256:" + "1" * 64,
                   target_root=value.target, indexes=(obsolete,))
    write_manifest(value.manifest, run_id=value.root.name, target_snapshot="target-sha256:" + "1" * 64,
                   target_root=value.target, indexes=value.indexes, upstream_manifests=(
                       {"path": parent.relative_to(value.root).as_posix(), "sha256": file_sha256(parent)},))
    value.sha = file_sha256(value.manifest)
    with input_read_scope(value.context) as receipts:
        assert read(value).find(identity=value.source)["results"]
    assert {item["path"] for item in receipts.document()["reads"]} == {value.indexes[0].relative_path}
    with pytest.raises(ValueError):
        load_verified_manifest(value.root, value.manifest, value.sha)


def test_selected_queries_recheck_custody_grants_after_core_construction(tmp_path):
    value = fixture(tmp_path, generated=True)
    selection = IndexSelection(SOURCE.producer_indexes, ((value.custody_job, value.custody_output),))
    core = read(value, selection)
    value.context.contract = replace(value.context.contract, inputs=tuple(
        item for item in value.context.contract.inputs if item.output_kind != value.custody_output))
    with pytest.raises(ValueError), input_read_scope(value.context):
        core.find(identity=value.source)


@pytest.mark.parametrize("damage", ["none", "not_selected", "not_pinned", "not_granted", "backing", "object"])
@pytest.mark.parametrize("kind", ["binary", "generated"])
def test_source_backing_requires_explicit_custody_selection_and_pins(tmp_path, damage, kind):
    value = fixture(tmp_path, binary=kind == "binary", generated=kind == "generated")
    selection = IndexSelection(SOURCE.producer_indexes, ((value.custody_job, value.custody_output),))
    if damage == "not_selected":
        selection = SOURCE
    elif damage == "not_pinned":
        value.context.upstream_handoffs.pop(value.custody_job)
    elif damage == "not_granted":
        value.context.contract = replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != value.custody_output))
    elif damage == "backing":
        path = value.root / value.backing["path"]
        path.chmod(0o600)
        path.write_bytes(b"changed")
    elif damage == "object":
        backing = json.loads((value.root / value.backing["path"]).read_text())
        source = value.root / backing["source"]["path"]
        source.chmod(0o600)
        source.write_bytes(b"changed")
    if damage != "none":
        with pytest.raises(ValueError), input_read_scope(value.context):
            read(value, selection)
    else:
        with input_read_scope(value.context) as reads:
            read(value, selection)
        assert {row["output_kind"] for row in reads.document()["reads"]} == {
            "source_files", "handoff", value.custody_output}
