"""Named control discovery must authenticate identity before touching the control path."""
from hashlib import sha256
from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.retrieval.index import IndexIdentity, load_verified_manifest, write_manifest
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import (
    REQUEST_SCHEMA, SharedArtifacts, canonical_json, publication_scope_for_owner,
)
from tests.unit.retrieval.test_selected_publication import (
    JOB, READERS, SNAPSHOT, consume, fixture, publish, publisher, readers,
)


def named_with_excluded_payload(tmp_path):
    value = fixture(tmp_path, "named")
    excluded, _, _ = publish(value.root, value.owner, "shared", name="links", shard="links-excluded")
    manifest = json.loads(value.manifest.read_text())
    write_manifest(value.manifest, run_id=value.root.name, target_snapshot=SNAPSHOT,
                   target_root=Path(manifest["target_root"]),
                   indexes=(IndexIdentity(**value.identity), IndexIdentity(**excluded)))
    value.sha = file_sha256(value.manifest)
    return value, excluded


def control_paths(value):
    obj = value.identity
    binding = value.root / "data/shared/named/index-shard" / (
        sha256(obj["relative_path"].encode()).hexdigest() + ".json")
    request = value.root / "data/shared/requests/index-shard" / Path(value.receipt["path"]).stem / (
        value.receipt["sha256"] + ".json")
    return {"binding": binding, "request": request}


def audit_path(monkeypatch, target):
    opened = []
    actual_open = Path.open

    def audit_open(path, *args, **kwargs):
        if path.resolve() == target.resolve():
            opened.append(path)
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", audit_open)
    return opened


@pytest.mark.parametrize("control", ["binding", "request"])
@pytest.mark.parametrize("reader", ("root", *READERS))
def test_discovery_never_hashes_excluded_payload_aliases(tmp_path, monkeypatch, control, reader):
    value, excluded = named_with_excluded_payload(tmp_path)
    store, core = readers(value)
    control_path = control_paths(value)[control]
    assert control_path.is_file()
    source = value.root / excluded["relative_path"]
    control_path.write_bytes(source.read_bytes())
    assert sha256(control_path.read_bytes()).hexdigest() == excluded["sha256"]
    opened = audit_path(monkeypatch, control_path)
    with pytest.raises(ValueError), input_read_scope(value.context):
        if reader == "root":
            load_verified_manifest(value.root, value.manifest, value.sha, selection=value.selection)
        else:
            consume(store, core, value, reader)
    assert opened == []
    assert excluded["relative_path"].startswith("data/shared/objects/")


def test_named_control_pins_exist_without_new_publication_fields(tmp_path):
    value, _ = named_with_excluded_payload(tmp_path)
    handoff = json.loads((value.owner.attempt_root / "handoff.json").read_text())
    refs = {ref["path"]: ref for ref in handoff["artifacts"]}
    paths = control_paths(value)
    binding = paths["binding"].relative_to(value.root).as_posix()
    assert binding in refs
    assert refs[value.receipt["path"]] == value.receipt
    request_bytes = canonical_json({"schema": REQUEST_SCHEMA, "receipt": refs[value.receipt["path"]]})
    assert paths["request"].read_bytes() == request_bytes
    assert sha256(paths["binding"].read_bytes()).hexdigest() == refs[binding]["sha256"]
    with input_read_scope(value.context):
        store, core = readers(value)
        for reader in READERS:
            assert len(consume(store, core, value, reader)) == (0 if reader == "relations" else 1)
    assert set(value.context.upstream_handoffs) == {JOB}


def test_unknown_request_identity_refuses_before_alias_io(tmp_path, monkeypatch):
    value, excluded = named_with_excluded_payload(tmp_path)
    store, core = readers(value)
    unknown = control_paths(value)["request"].with_name("0" * 64 + ".json")
    unknown.write_bytes((value.root / excluded["relative_path"]).read_bytes())
    opened = audit_path(monkeypatch, unknown)
    with pytest.raises(ValueError, match="identity is unavailable before discovery"), input_read_scope(value.context):
        consume(store, core, value, "core")
    assert opened == []


def test_request_discovery_rechecks_the_current_handoff_grant(tmp_path, monkeypatch):
    value = fixture(tmp_path, "named")
    store, core = readers(value)
    pins = dict(value.context.upstream_handoffs)
    value.context.contract = replace(value.context.contract, inputs=tuple(
        item for item in value.context.contract.inputs if item.output_kind != "handoff"))
    opened = audit_path(monkeypatch, control_paths(value)["request"])
    with pytest.raises(ValueError, match="undeclared consumption"), input_read_scope(value.context):
        consume(store, core, value, "core")
    assert opened == []
    assert value.context.upstream_handoffs == pins


@pytest.mark.parametrize("retained", [True, False], ids=["pinned", "reconstructed"])
def test_consumer_receipt_discovery_requires_a_known_identity(tmp_path, monkeypatch, retained):
    value = fixture(tmp_path, "named")
    consumer = publisher(value.root, "attempt_0002")
    receipt = consumer.named("index-shard", value.root / value.identity["relative_path"], computed=False)
    if not retained:
        consumer = SharedArtifacts(consumer.run_root, consumer.attempt_root, consumer.actor)
        assert consumer.named("index-shard", value.root / value.identity["relative_path"], computed=False) == receipt
    opened = audit_path(monkeypatch, value.root / receipt["path"])
    with publication_scope_for_owner(consumer), input_read_scope(value.context):
        store, core = readers(value)
        assert len(consume(store, core, value, "core")) == 1
        assert opened


@pytest.mark.parametrize("retained", [True, False], ids=["pinned", "reconstructed"])
def test_consumer_receipt_alias_is_not_opened_during_discovery(tmp_path, monkeypatch, retained):
    value, excluded = named_with_excluded_payload(tmp_path)
    consumer = publisher(value.root, "attempt_0002")
    receipt = consumer.named("index-shard", value.root / value.identity["relative_path"], computed=False)
    with publication_scope_for_owner(consumer):
        store, core = readers(value)
    path = value.root / receipt["path"]
    path.write_bytes((value.root / excluded["relative_path"]).read_bytes())
    if not retained:
        consumer = SharedArtifacts(consumer.run_root, consumer.attempt_root, consumer.actor)
    opened = audit_path(monkeypatch, path)
    with pytest.raises(ValueError), publication_scope_for_owner(consumer), input_read_scope(value.context):
        consume(store, core, value, "core")
    assert opened == []


@pytest.mark.parametrize("missing", ["grant", "request"])
def test_consumer_reconstruction_cannot_guess_an_unavailable_origin(tmp_path, monkeypatch, missing):
    value = fixture(tmp_path, "named")
    consumer = publisher(value.root, "attempt_0002")
    receipt = consumer.named("index-shard", value.root / value.identity["relative_path"], computed=False)
    with publication_scope_for_owner(consumer):
        store, core = readers(value)
    consumer = SharedArtifacts(consumer.run_root, consumer.attempt_root, consumer.actor)
    if missing == "request":
        control_paths(value)["request"].unlink()
    else:
        value.context.contract = replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != "handoff"))
    opened = audit_path(monkeypatch, value.root / receipt["path"])
    with pytest.raises(ValueError), publication_scope_for_owner(consumer), input_read_scope(value.context):
        consume(store, core, value, "core")
    assert opened == []
