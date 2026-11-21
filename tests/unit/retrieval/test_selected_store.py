"""A retained selected store must check the current claim, not its creator's grant."""
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.retrieval.index import IndexSelection
from appsec_review.indexing.store import shard_summary
from appsec_review.review.scope import accept_manifest
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage.validation import validation_scope
from tests.unit.retrieval.test_selected_manifest import SOURCE, fixture


READERS = ("entities", "coverage", "relations", "entity_ids")


def consume(store, method):
    return (store.entity_ids() if method == "entity_ids"
            else list(getattr(store, method)(store.shards)))


def scope_for(value, *, selected=True):
    selection = IndexSelection(
        SOURCE.producer_indexes, ((value.custody_job, value.custody_output),)) if selected else None
    return accept_manifest(value.root, manifest_path=value.manifest,
                           manifest_sha256=value.sha, selection=selection)


@pytest.mark.parametrize("kind", ["generated", "binary"])
@pytest.mark.parametrize("method", READERS)
def test_retained_store_checks_current_custody_grant(tmp_path, kind, method):
    value = fixture(tmp_path, generated=kind == "generated", binary=kind == "binary")
    narrow = SimpleNamespace(**{
        **vars(value.context), "contract": replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != value.custody_output))})
    assert narrow.upstream_handoffs == value.context.upstream_handoffs
    with validation_scope(value.root):
        with input_read_scope(value.context):
            scope = scope_for(value)
            store = scope.store
            expected = consume(store, method)
        with pytest.raises(ValueError, match=f"undeclared consumption.*{value.custody_output}"), input_read_scope(narrow):
            consume(store, method)
        with input_read_scope(value.context) as reads:
            assert consume(store, method) == expected
        assert value.custody_output in {row["output_kind"] for row in reads.document()["reads"]}
        assert all(row["cited"] is None for row in reads.document()["reads"])


@pytest.mark.parametrize("kind", ["generated", "binary"])
@pytest.mark.parametrize("method", READERS)
def test_retained_store_revalidates_backing_bytes(tmp_path, kind, method):
    value = fixture(tmp_path, generated=kind == "generated", binary=kind == "binary")
    with input_read_scope(value.context):
        store = scope_for(value).store
        consume(store, method)
    backing = json.loads((value.root / value.backing["path"]).read_text())
    path = value.root / backing["source"]["path"]
    path.chmod(0o600)
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="source publication"), input_read_scope(value.context):
        consume(store, method)


@pytest.mark.parametrize("method", ("entities", "relations"))
def test_deferred_store_iteration_uses_the_iteration_claim(tmp_path, method):
    value = fixture(tmp_path, generated=True)
    with input_read_scope(value.context):
        store = scope_for(value).store
        iterator = getattr(store, method)(store.shards)
    narrow = SimpleNamespace(**{
        **vars(value.context), "contract": replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != value.custody_output))})
    with pytest.raises(ValueError, match="undeclared consumption"), input_read_scope(narrow):
        list(iterator)


@pytest.mark.parametrize("kind", ["generated", "binary"])
def test_unselected_store_keeps_default_behavior(tmp_path, kind):
    value = fixture(tmp_path, generated=kind == "generated", binary=kind == "binary")
    with input_read_scope(value.context):
        scope = scope_for(value, selected=False)
        expected = {method: consume(scope.store, method) for method in READERS}
    narrow = SimpleNamespace(**{
        **vars(value.context), "contract": replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != value.custody_output))})
    with input_read_scope(narrow):
        assert {method: consume(scope.store, method) for method in READERS} == expected


@pytest.mark.parametrize("kind", ["generated", "binary"])
def test_selected_summary_cannot_reuse_a_broader_admitted_summary(tmp_path, kind):
    value = fixture(tmp_path, generated=kind == "generated", binary=kind == "binary")
    with input_read_scope(value.context):
        scope = scope_for(value)
    narrow = SimpleNamespace(**{
        **vars(value.context), "contract": replace(value.context.contract, inputs=tuple(
            item for item in value.context.contract.inputs if item.output_kind != value.custody_output))})
    shard = scope.shards[0]
    with validation_scope(value.root) as validation:
        validation.records[("admitted-summary", shard["sha256"], validation.target_snapshot)] = {
            "entity_count": 2, "coverage": []}
        with pytest.raises(ValueError, match="undeclared consumption"), input_read_scope(narrow):
            shard_summary(value.root, shard, selection=scope.selection, manifest=scope._manifest)


@pytest.mark.parametrize("method", ("entities", "coverage", "relations"))
def test_selected_store_does_not_open_other_granted_shards(tmp_path, method):
    value = fixture(tmp_path, generated=True)
    with input_read_scope(value.context):
        scope = scope_for(value)
    from dataclasses import asdict
    other = asdict(value.indexes[1])
    with pytest.raises(ValueError, match="outside the selected store"), input_read_scope(value.context) as reads:
        list(getattr(scope.store, method)((other,)))
    assert reads.document()["reads"] == []
