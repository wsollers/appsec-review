"""Private publication provenance is checked on every selected reopen."""
from dataclasses import asdict, replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.indexing.derive import Derived, publish_derived
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    RetrievalCore, write_manifest,
)
from appsec_review.retrieval.index import IndexSelection, _SelectedReceiptPolicy, load_verified_manifest, open_selected_shard
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime.contracts import EvidenceAuthority, InputRequirement, JobContract
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import (
    SharedArtifacts, attempt_artifacts, publication_scope_for_owner, put_bytes, receipt_read_scope,
    reference, verify_receipt,
)
from appsec_review.storage.validation import current_validation, validation_scope
from tests.handoff_fixture import write_fixture_handoff


JOB = "job_review_data_indexing"
SNAPSHOT = "target-sha256:" + "1" * 64
READERS = ("entities", "coverage", "relations", "entity_ids", "core")


def publisher(root, attempt_id="attempt_0001"):
    attempt = root / "data/jobs" / JOB / "attempts" / attempt_id
    declarations = builtin_registry().build(JOB).datasets
    atomic_json(attempt / "claim.json", {"orchestration": {}, "dataset_contract": dataset_contract(
        JOB, tuple(dict.fromkeys(item.step for item in declarations)), declarations)})
    write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": JOB, "outputs": {"test.publish": {"terminal_status": "SUCCEEDED"}}}, target_snapshot=SNAPSHOT)
    claim = json.loads((attempt / "claim.json").read_text())
    actor = {key: claim[key] for key in ("run_id", "job_id", "attempt_id", "orchestration")}
    return SharedArtifacts(root, attempt, {**actor, "claim": reference(root, attempt / "claim.json")})


def publish(root, owner, layout, *, name="precomputed", shard="qs-main", target=None):
    entity = EntityRecord(LogicalIdentity.derive(EntityKind.IR_ENTITY, SNAPSHOT, {"shard": shard}),
                          shard, shard, "inert", {})
    if layout == "shared":
        result = publish_derived(root, index=name, shard_id=shard, job_id=JOB, unit_id="test.publish",
            rule="receipt-unit", rule_version="1", snapshot=SNAPSHOT, inputs={"shard": shard, "target": target},
            build=lambda: Derived(entities=[entity], coverage=[("unit", "complete", None)],
                relations=[RelationRecord(RelationKind.DERIVED_FROM, entity.identity.value, target, True, 1.0)]
                if target else []), shared=owner)
        return result["index_identity"], result["shared_receipt"], entity.identity.value
    path = root / "data/indices" / name / shard / "private.sqlite"
    builder = IndexBuilder(path, name=name, fingerprint="f" * 64, target_snapshot=SNAPSHOT, shard_id=shard)
    builder.add_entity(entity)
    builder.add_coverage("unit", "complete")
    with publication_scope_for_owner(owner):
        sha = builder.build()
    identity = asdict(IndexIdentity(name, "appsec-review/retrieval-index/2", sha, "f" * 64,
        path.relative_to(root).as_posix(), {"job": JOB}, shard_id=shard))
    refs = [reference(root, path) for path in owner.attempt_root.glob("shared/index-shard/*.json")]
    receipt = next(ref for ref in refs if verify_receipt(root, ref)["object"]["path"] == identity["relative_path"])
    return identity, receipt, entity.identity.value


def fixture(tmp_path, layout, *, dependency=False):
    root = tmp_path / "runs/2026-11-21-0001"
    target = tmp_path / "target"
    target.mkdir()
    owner = publisher(root)
    other, endpoint = None, None
    if dependency:
        other, _, endpoint = publish(root, owner, "shared", name="links", shard="links-custody")
    identity, receipt, entity = publish(root, owner, layout, target=endpoint)
    replacement_identity, replacement, _ = publish(root, owner, layout, shard="qs-replacement")
    if dependency:
        original = verify_receipt(root, receipt)
        receipt = owner.computed("derived-index", "e" * 64, original["object"],
            computation=original["computation"],
            dependencies=tuple(original["dependencies"]) + (reference(root, root / other["relative_path"]),))
        identity["producer"]["shared_receipt"] = receipt
    write_fixture_handoff(root, owner.attempt_root / "handoff.json", {
        "job_id": JOB, "outputs": {"test.publish": {"terminal_status": "SUCCEEDED"}},
        "artifacts": attempt_artifacts(root, owner.attempt_root)}, target_snapshot=SNAPSHOT)
    assert file_sha256(owner.attempt_root / "claim.json") == owner.actor["claim"]["sha256"]
    manifest = root / "data/indices/manifests/private.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=SNAPSHOT, target_root=target,
        indexes=tuple(IndexIdentity(**item) for item in (identity, *([other] if other else []))))
    requirements = (
        InputRequirement(JOB, "precomputed_products", "appsec-review/retrieval-index/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
        InputRequirement(JOB, "handoff", "appsec-review/job-handoff/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE),
    )
    context = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id="job_owasp_control_assessment"),
        upstream_handoffs={JOB: file_sha256(owner.attempt_root / "handoff.json")},
        contract=JobContract(inputs=requirements))
    return SimpleNamespace(root=root, manifest=manifest, sha=file_sha256(manifest), identity=identity,
        receipt=receipt, replacement=replacement, entity=entity, context=context, other=other,
        owner=owner, replacement_identity=replacement_identity,
        selection=IndexSelection(((JOB, "precomputed"),)))


def readers(value):
    with input_read_scope(value.context):
        scope = accept_manifest(value.root, manifest_path=value.manifest,
                                manifest_sha256=value.sha, selection=value.selection)
        core = RetrievalCore(value.root.parent, value.root.name, manifest_path=value.manifest,
                             manifest_sha256=value.sha, selection=value.selection)
    return scope.store, core


def consume(store, core, value, reader):
    if reader == "core":
        return core.find(identity=value.entity)["results"]
    if reader == "entity_ids":
        return store.entity_ids()
    return list(getattr(store, reader)(store.shards))


@pytest.mark.parametrize("layout", ["named", "shared"])
@pytest.mark.parametrize("mutation", ["mutated", "deleted", "replaced"])
@pytest.mark.parametrize("reader", READERS)
def test_reopens_revalidate_private_publication_receipts(tmp_path, layout, mutation, reader):
    value = fixture(tmp_path, layout)
    store, core = readers(value)
    path = value.root / value.receipt["path"]
    if mutation == "deleted":
        path.unlink()
    elif mutation == "replaced":
        path.write_bytes((value.root / value.replacement["path"]).read_bytes())
    else:
        path.write_bytes(b"receipt changed after construction")
    with pytest.raises(ValueError), input_read_scope(value.context):
        consume(store, core, value, reader)


@pytest.mark.parametrize("layout", ["named", "shared"])
def test_valid_private_publication_reopens_preserve_rows(tmp_path, layout):
    value = fixture(tmp_path, layout)
    store, core = readers(value)
    with input_read_scope(value.context) as reads:
        for method in READERS:
            assert len(consume(store, core, value, method)) == (0 if method == "relations" else 1)
    assert {row["output_kind"] for row in reads.document()["reads"]} == {"precomputed_products"}
    assert all(row["cited"] is None for row in reads.document()["reads"])


@pytest.mark.parametrize("case", ["selected", "custody_only", "missing_selection", "missing_grant"])
def test_receipt_dependencies_require_selection_and_current_grant_before_io(tmp_path, monkeypatch, case):
    value = fixture(tmp_path, "shared", dependency=True)
    if case == "selected":
        value.selection = IndexSelection(((JOB, "precomputed"), (JOB, "links")))
    elif case in {"custody_only", "missing_grant"}:
        value.selection = IndexSelection(value.selection.producer_indexes, ((JOB, "cross_domain_links"),))
    if case != "missing_grant":
        value.context.contract = replace(value.context.contract, inputs=(*value.context.contract.inputs,
            InputRequirement(JOB, "cross_domain_links", "appsec-review/retrieval-index/2",
                             authority=EvidenceAuthority.PRODUCER_EVIDENCE)))
    pins = dict(value.context.upstream_handoffs)
    opened = []
    actual_open = Path.open
    dependency = (value.root / value.other["relative_path"]).resolve()

    def audit_open(path, *args, **kwargs):
        if path.resolve() == dependency:
            opened.append(path)
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", audit_open)
    if case.startswith("missing"):
        with pytest.raises(ValueError), input_read_scope(value.context):
            load_verified_manifest(value.root, value.manifest, value.sha, selection=value.selection)
        assert opened == []
    else:
        store, core = readers(value)
        with input_read_scope(value.context) as reads:
            assert consume(store, core, value, "core")
        assert opened
        assert {row["output_kind"] for row in reads.document()["reads"]} == {
            "precomputed_products", "cross_domain_links", *(("handoff",) if case == "custody_only" else ())}
        assert all(row["cited"] is None for row in reads.document()["reads"])
        if case == "custody_only":
            assert set(core.indexes) == {"precomputed"}
            assert not core.find(kind="ir_entity", indexes=("links",))["results"]
    assert value.context.upstream_handoffs == pins


@pytest.mark.parametrize("layout", ["named", "shared"])
@pytest.mark.parametrize("cache", ["memo", "admitted"])
def test_receipt_cache_cannot_attest_changed_private_publication(tmp_path, layout, cache):
    value = fixture(tmp_path, layout)
    store, core = readers(value)
    with validation_scope(value.root) as context:
        receipt = verify_receipt(value.root, value.receipt)
        if cache == "admitted":
            context.admitted_receipts[value.receipt["path"]] = {
                "sha256": value.receipt["sha256"], "value": receipt}
            context.admitted[(value.receipt["path"], value.receipt["sha256"])] = value.receipt["size_bytes"]
        path = value.root / value.receipt["path"]
        raw = path.read_bytes()
        path.write_bytes(b"[" + raw[1:])
        with pytest.raises(ValueError), input_read_scope(value.context):
            consume(store, core, value, "entities")


@pytest.mark.parametrize("boundary", ["root", "open"])
def test_receipt_must_bind_the_exact_selected_shard(tmp_path, boundary):
    value = fixture(tmp_path, "shared")
    wrong = {**value.identity, "producer": {**value.identity["producer"],
                                          "shared_receipt": value.replacement}}
    manifest = json.loads(value.manifest.read_text())
    manifest["indexes"] = [wrong, value.replacement_identity]
    with pytest.raises(ValueError, match="metadata does not bind the selected shard"), input_read_scope(value.context):
        if boundary == "open":
            open_selected_shard(value.root, wrong, selection=value.selection, manifest=manifest)
        else:
            write_manifest(value.manifest, run_id=value.root.name, target_snapshot=SNAPSHOT,
                           target_root=Path(manifest["target_root"]),
                           indexes=tuple(IndexIdentity(**raw) for raw in manifest["indexes"]))
            load_verified_manifest(value.root, value.manifest, file_sha256(value.manifest),
                                   selection=value.selection)


def test_default_unfiltered_receipt_verification_is_unchanged(tmp_path):
    value = fixture(tmp_path, "shared", dependency=True)
    assert len(verify_receipt(value.root, value.receipt)["dependencies"]) == 2
    assert load_verified_manifest(value.root, value.manifest, value.sha)[1] == value.sha


@pytest.mark.parametrize("reader", READERS)
def test_retained_receipt_closure_does_not_retain_dependency_grants(tmp_path, monkeypatch, reader):
    value = fixture(tmp_path, "shared", dependency=True)
    value.selection = IndexSelection(value.selection.producer_indexes, ((JOB, "cross_domain_links"),))
    broad = replace(value.context.contract, inputs=(*value.context.contract.inputs,
        InputRequirement(JOB, "cross_domain_links", "appsec-review/retrieval-index/2",
                         authority=EvidenceAuthority.PRODUCER_EVIDENCE)))
    narrow = value.context.contract
    value.context.contract = broad
    store, core = readers(value)
    value.context.contract = narrow
    actual_open = Path.open
    dependency = (value.root / value.other["relative_path"]).resolve()
    opened = []

    def audit_open(path, *args, **kwargs):
        if path.resolve() == dependency:
            opened.append(path)
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", audit_open)
    with pytest.raises(ValueError), input_read_scope(value.context):
        consume(store, core, value, reader)
    assert opened == []


@pytest.mark.parametrize("layout", ["named", "shared"])
def test_reused_receipt_revalidates_original_private_provenance(tmp_path, layout):
    value = fixture(tmp_path, layout)
    consumer = publisher(value.root, "attempt_0002")
    if layout == "named":
        consumer.named("index-shard", value.root / value.identity["relative_path"], computed=False)
    else:
        reused = consumer.consume_receipt(value.receipt)
        value.identity["producer"]["shared_receipt"] = reused
        document = json.loads(value.manifest.read_text())
        write_manifest(value.manifest, run_id=value.root.name, target_snapshot=SNAPSHOT,
                       target_root=Path(document["target_root"]), indexes=(IndexIdentity(**value.identity),))
        value.sha = file_sha256(value.manifest)
    with publication_scope_for_owner(consumer):
        store, core = readers(value)
        (value.root / value.receipt["path"]).write_bytes(b"original provenance changed")
        with pytest.raises(ValueError), input_read_scope(value.context):
            consume(store, core, value, "core")


@pytest.mark.parametrize("role", ["dependency", "object"])
def test_receipt_labels_cannot_authorize_unknown_or_excluded_payloads(tmp_path, monkeypatch, role):
    value = fixture(tmp_path, "shared", dependency=role == "object")
    original = verify_receipt(value.root, value.receipt)
    if role == "dependency":
        forbidden = put_bytes(value.root, b'{"schema":"appsec-review/derived-shard/1","label":"metadata"}')
        obj, dependencies = original["object"], (*original["dependencies"], forbidden)
    else:
        forbidden = reference(value.root, value.root / value.other["relative_path"])
        obj, dependencies = forbidden, (reference(value.root, value.root / value.identity["relative_path"]),)
    receipt = value.owner.computed("derived-index", "d" * 64, obj,
                                  computation=original["computation"], dependencies=dependencies)
    write_fixture_handoff(value.root, value.owner.attempt_root / "handoff.json", {
        "job_id": JOB, "outputs": {"test.publish": {"terminal_status": "SUCCEEDED"}},
        "artifacts": attempt_artifacts(value.root, value.owner.attempt_root)}, target_snapshot=SNAPSHOT)
    assert file_sha256(value.owner.attempt_root / "claim.json") == value.owner.actor["claim"]["sha256"]
    value.context.upstream_handoffs[JOB] = file_sha256(value.owner.attempt_root / "handoff.json")
    value.identity["producer"]["shared_receipt"] = receipt
    document = json.loads(value.manifest.read_text())
    write_manifest(value.manifest, run_id=value.root.name, target_snapshot=SNAPSHOT,
        target_root=Path(document["target_root"]),
        indexes=tuple(IndexIdentity(**raw) for raw in (value.identity, *([value.other] if value.other else []))))
    value.sha = file_sha256(value.manifest)
    opened = []
    actual_open = Path.open
    forbidden_path = (value.root / forbidden["path"]).resolve()

    def audit_open(path, *args, **kwargs):
        if path.resolve() == forbidden_path:
            opened.append(path)
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", audit_open)
    with pytest.raises(ValueError), input_read_scope(value.context):
        load_verified_manifest(value.root, value.manifest, value.sha, selection=value.selection)
    assert opened == []


def test_indexed_payload_cannot_masquerade_as_receipt_control_metadata(tmp_path, monkeypatch):
    value = fixture(tmp_path, "shared", dependency=True)
    alias = value.root / f"data/jobs/{JOB}/attempts/attempt_metadata/shared/derived-index/{'f' * 64}.json"
    alias.parent.mkdir(parents=True)
    alias.write_bytes((value.root / value.other["relative_path"]).read_bytes())
    value.other["relative_path"] = alias.relative_to(value.root).as_posix()
    value.identity["producer"]["shared_receipt"] = reference(value.root, alias)
    document = json.loads(value.manifest.read_text())
    write_manifest(value.manifest, run_id=value.root.name, target_snapshot=SNAPSHOT,
        target_root=Path(document["target_root"]),
        indexes=(IndexIdentity(**value.identity), IndexIdentity(**value.other)))
    opened = []
    actual_open = Path.open

    def audit_open(path, *args, **kwargs):
        if path.resolve() == alias.resolve():
            opened.append(path)
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", audit_open)
    with pytest.raises(ValueError, match="cannot be consumed as receipt control metadata"), input_read_scope(value.context):
        load_verified_manifest(value.root, value.manifest, file_sha256(value.manifest), selection=value.selection)
    assert opened == []


@pytest.mark.parametrize("cached", ["memo", "admitted"])
def test_receipt_guard_rechecks_control_bytes_inside_a_warm_scope(tmp_path, cached):
    value = fixture(tmp_path, "shared")
    policy = _SelectedReceiptPolicy(value.selection, json.loads(value.manifest.read_text()), value.identity)
    with input_read_scope(value.context), receipt_read_scope(value.root, policy):
        receipt = verify_receipt(value.root, value.receipt)
        validation = current_validation(value.root)
        if cached == "admitted":
            validation.admitted_receipts[value.receipt["path"]] = {
                "sha256": value.receipt["sha256"], "value": receipt}
            validation.admitted[(value.receipt["path"], value.receipt["sha256"])] = value.receipt["size_bytes"]
        path = value.root / value.receipt["path"]
        raw = path.read_bytes()
        path.write_bytes(b"[" + raw[1:])
        with pytest.raises(ValueError):
            verify_receipt(value.root, value.receipt)


def test_receipt_guard_replays_current_grants_inside_a_warm_scope(tmp_path):
    value = fixture(tmp_path, "shared")
    policy = _SelectedReceiptPolicy(value.selection, json.loads(value.manifest.read_text()), value.identity)
    with receipt_read_scope(value.root, policy):
        with input_read_scope(value.context):
            verify_receipt(value.root, value.receipt)
        narrow = SimpleNamespace(**{**vars(value.context), "contract": replace(
            value.context.contract, inputs=tuple(item for item in value.context.contract.inputs
                                                if item.output_kind != "precomputed_products"))})
        with pytest.raises(ValueError, match="undeclared consumption"), input_read_scope(narrow):
            verify_receipt(value.root, value.receipt)


@pytest.mark.parametrize("change", ["grant", "index"])
def test_entity_metadata_reuse_still_reopens_the_current_source_boundary(tmp_path, change):
    from appsec_review.owasp_workbench.evidence import EvidenceResolver
    from tests.unit.retrieval.test_selected_manifest import SOURCE, fixture as source_fixture, read
    value = source_fixture(tmp_path)
    with input_read_scope(value.context):
        core = read(value)
        scope = accept_manifest(value.root, manifest_path=value.manifest,
                                manifest_sha256=value.sha, selection=SOURCE)
        resolver = EvidenceResolver(core, scope)
        assert resolver._entity(value.source)["identity"] == value.source
        assert resolver._entity(value.source)["identity"] == value.source
    if change == "grant":
        value.context.contract = replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != "source_files"))
    else:
        (value.root / value.indexes[0].relative_path).write_bytes(b"changed after metadata lookup")
    with pytest.raises(ValueError), input_read_scope(value.context):
        resolver._entity(value.source)


def test_cached_path_parsing_never_caches_symlink_custody(tmp_path):
    from appsec_review.storage.shared import safe_path
    directory = tmp_path / "source"
    directory.mkdir()
    (directory / "record").write_bytes(b"same bytes")
    assert safe_path(tmp_path, "source/record").read_bytes() == b"same bytes"
    moved = tmp_path / "moved"
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        safe_path(tmp_path, "source/record")
