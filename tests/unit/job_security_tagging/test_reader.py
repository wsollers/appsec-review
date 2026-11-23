from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_security_tagging.job import _publish_shards, _subject_location
from appsec_review.jobs.job_security_tagging.producers import AcceptedIndexes, collect_coverage_gaps
from appsec_review.jobs.job_security_tagging.taxonomy import assignment
from appsec_review.retrieval import EntityKind
from appsec_review.storage import file_sha256

from .helpers import DATA, SNAPSHOT, CannedIndexes, fact, scope, shard, taxonomy, unit_context
from .test_behavioral_tags import collect


def reader(root):
    value = object.__new__(AcceptedIndexes)
    value.run_root = root / "run"
    value.target_snapshot = SNAPSHOT
    value.manifest = {"target_root": str(root / "target")}
    value.identities = [shard()]
    return value


def test_reader_binds_source_bytes_to_accepted_hash_and_path(tmp_path):
    row = fact()
    value = reader(tmp_path)
    source = tmp_path / "target" / row.location["path"]
    source.parent.mkdir(parents=True)
    source.write_bytes(DATA)
    assert value.source_bytes(row.location) == DATA
    source.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        value.source_bytes(row.location)
    with pytest.raises(ValueError):
        value.source_bytes({**row.location, "path": "../outside"})


def test_reader_never_falls_back_to_target_for_generated_backing(tmp_path):
    row = fact()
    value = reader(tmp_path)
    source = tmp_path / "target" / row.location["path"]
    source.parent.mkdir(parents=True)
    source.write_bytes(DATA)
    with pytest.raises(ValueError, match="backing"):
        value.source_bytes({**row.location, "producer_location": {"source_domain": "generated"}})


def test_sql_reader_limits_kinds_and_preserves_exact_graph_location(tmp_path, monkeypatch):
    row = fact()
    value = reader(tmp_path)
    database = sqlite3.connect(":memory:")
    database.row_factory = sqlite3.Row
    database.executescript("""
        CREATE TABLE entities(identity TEXT, kind TEXT, native_id TEXT, name TEXT, payload_json TEXT);
        CREATE TABLE locations(entity_id TEXT, path TEXT, file_sha256 TEXT, start_byte INTEGER,
            end_byte INTEGER, start_line INTEGER, end_line INTEGER, start_column INTEGER, end_column INTEGER,
            target_snapshot TEXT, mapping_method TEXT, confidence REAL, ambiguous INTEGER,
            producer_location_json TEXT);
    """)
    for identity, kind in ((row.identity, row.kind), ("z", row.kind), ("a", "symbol")):
        database.execute("INSERT INTO entities VALUES (?,?,?,?,?)",
                         (identity, kind, identity, kind, json.dumps(row.payload)))
    keys = ("path", "file_sha256", "start_byte", "end_byte", "start_line", "end_line",
            "start_column", "end_column", "target_snapshot", "mapping_method", "confidence")
    database.execute("INSERT INTO locations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (row.identity, *(row.location[key] for key in keys), 0,
                      json.dumps({"source_domain": "target"})))

    @contextmanager
    def opened(identity):
        yield database

    monkeypatch.setattr(value, "_open", opened)
    rows, capped = value.rows(shard(), ("entry_point", "sink_site"), 1)
    assert capped and len(rows) == 1 and rows[0].identity == row.identity
    assert rows[0].location["ambiguous"] is False
    assert rows[0].location["producer_location"] == {"source_domain": "target"}
    assert rows[0].payload == row.payload
    rows, capped = value.rows(shard(), ("sink_site",), 5)
    assert not capped and rows[1].location is None
    source_rows, _ = value.rows(shard("source"), ("sink_site",), 1)
    assert "producer_location" not in source_rows[0].location
    assert "ambiguous" not in source_rows[0].location
    database.close()


def test_open_observes_admitted_shard_and_refuses_tampering(tmp_path, monkeypatch):
    from appsec_review.runtime import inputs
    value = reader(tmp_path)
    value.run_root.mkdir()
    path = value.run_root / "one.sqlite"
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE sample(id INTEGER)")
    identity = {**shard(), "relative_path": path.name, "sha256": file_sha256(path)}
    observed = []
    monkeypatch.setattr(inputs, "observe_shard", lambda root, item: observed.append((root, item)))
    connection = value._open(identity)
    assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
    connection.close()
    assert observed == [(value.run_root, identity)]
    with pytest.raises(ValueError, match="integrity mismatch"):
        value._open({**identity, "sha256": "0" * 64})
    with pytest.raises(ValueError, match="unavailable"):
        value._open({**identity, "relative_path": "../outside"})


def _alternate_coverage(tmp_path, status):
    from appsec_review.jobs.job_code_graph_index.datasets import DATASETS
    from appsec_review.jobs.job_security_tagging.datasets import CONTRACT

    indexes = reader(tmp_path)
    indexes.run_root.mkdir()
    indexes.manifest_sha256 = "b" * 64
    path = indexes.run_root / "alternate.sqlite"
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE coverage(area TEXT, status TEXT, gap TEXT)")
        database.execute("INSERT INTO coverage VALUES (?,?,?)",
                         ("alternate-cpg", status, "fixture alternate gap" if status != "complete" else None))
    identity = {**shard("analysis", "alternate-cpg"), "relative_path": path.name, "sha256": file_sha256(path)}
    indexes.identities = [identity]
    context = SimpleNamespace(
        run_root=indexes.run_root, config=SimpleNamespace(job_id="job_security_tagging"),
        contract=CONTRACT, upstream_handoffs={"job_code_graph_index": "c" * 64})
    handoff = {"job_id": "job_code_graph_index", "attempt_id": "attempt_0001", "target_snapshot": SNAPSHOT,
               "artifacts": [{"path": path.name, "sha256": identity["sha256"], "size_bytes": path.stat().st_size}]}
    return indexes, context, (handoff, DATASETS)


@pytest.mark.parametrize("status", ["partial", "complete"])
def test_alternate_cpg_coverage_uses_the_typed_input_and_records_the_real_read(tmp_path, status):
    from appsec_review.runtime.inputs import input_read_scope

    indexes, context, producer = _alternate_coverage(tmp_path, status)
    vocabulary, rules, _ = taxonomy()
    with input_read_scope(context) as reads:
        # Only the accepted-producer lookup is canned; ownership, authority and SQLite reads are real.
        reads.producers["job_code_graph_index"] = producer
        records, _notes = collect_coverage_gaps(indexes, scope(), vocabulary, rules)
        observed = reads.document()["reads"]
    gaps = [record for record in records if record["tag"].startswith("gap:no-ast")]
    assert len(gaps) == (1 if status == "partial" else 0)
    if gaps:
        assert gaps[0]["basis"] == "reported"
        assert gaps[0]["evidence"][0]["coverage"] == [
            {"area": "alternate-cpg", "status": "partial", "gap": "fixture alternate gap"}]
    assert len(observed) == 1
    assert observed[0]["producer"] == "job_code_graph_index"
    assert observed[0]["output_kind"] == "alternate_cpg_index"
    assert observed[0]["schema"] == "appsec-review/alternate-cpg/1"
    assert observed[0]["read"] is True and observed[0]["cited"] is None


def test_alternate_cpg_coverage_does_not_bypass_a_missing_input_grant(tmp_path):
    from appsec_review.runtime.inputs import input_read_scope

    indexes, context, producer = _alternate_coverage(tmp_path, "partial")
    context.contract = replace(context.contract, inputs=tuple(
        item for item in context.contract.inputs if item.output_kind != "alternate_cpg_index"))
    vocabulary, rules, _ = taxonomy()
    with pytest.raises(ValueError, match="undeclared consumption.*job_code_graph_index/alternate_cpg_index"):
        with input_read_scope(context) as reads:
            reads.producers["job_code_graph_index"] = producer
            collect_coverage_gaps(indexes, scope(), vocabulary, rules)


def test_generated_source_provenance_survives_tag_location_projection():
    row = fact()
    native = {"source_domain": "generated",
              "source_backing": {"path": "data/treesitter/sources/" + "d" * 64 + ".json",
                                 "sha256": "d" * 64, "size_bytes": 100}}
    row = replace(row, location={**row.location, "producer_location": native})
    records, gaps = collect([row])
    assert not gaps
    location = _subject_location(records[0])
    assert location.producer_location == {**native, "assignment_evidence": row.identity}
    assert location.path == row.location["path"]
    assert location.file_sha256 == row.location["file_sha256"]


def test_publication_creates_resolving_site_entity_without_extra_authority(tmp_path, monkeypatch):
    from appsec_review.jobs.job_security_tagging import job
    row = fact()
    records, gaps = collect([row])
    assert not gaps
    records.append(assignment(
        vocabulary=taxonomy()[0], tag="gap:scope-failed", basis="reported",
        subject=scope().project, producer={"name": "fixture"}, evidence=[{"ref": "manifest:fixture"}]))
    entities, relations = [], []

    class Builder:
        def __init__(self, path, **kwargs):
            pass

        def add_entity(self, entity):
            entities.append(entity)

        def add_relation(self, relation):
            relations.append(relation)

        def add_coverage(self, *args):
            pass

        def build(self):
            return "a" * 64

    monkeypatch.setattr(job, "IndexBuilder", Builder)
    indexes = CannedIndexes()
    indexes.manifest_sha256 = "b" * 64
    unit = unit_context(tmp_path, "publication.publish_index")
    identities = {key: value for key, value in unit.job.config.settings["taxonomy"].items()
                  if key.endswith("_sha256")}
    shards = _publish_shards(unit, records, indexes, identities, "c" * 64)
    assert len(shards) == 2 and all(item.name == "tags" for item in shards)
    tag = next(item for item in entities if item.identity.kind == EntityKind.TAG_ASSIGNMENT
               and item.payload["basis"] == "invoked")
    subject = next(item for item in entities if item.identity.kind == EntityKind.SOURCE_SPAN)
    assert tag.payload == records[0]
    assert subject.identity.value == records[0]["subject"]["logical_id"]
    assert subject.location == tag.location
    assert subject.location.producer_location["assignment_evidence"] == row.identity
    assert subject.payload == {"subject": records[0]["subject"]}
    assert tag.payload["family"] == "code_facts" and tag.payload["basis"] == "invoked"
    assert tag.payload["evidence"][0]["ref"] == row.identity
    assert len(relations) == 2 and any(item.target_id == subject.identity.value for item in relations)
    project = next(item for item in entities if item.identity.kind == EntityKind.PROJECT)
    assert project.location is None


def test_empty_graph_and_repeated_source_failure_have_named_gaps():
    assert "missing_site_facts" in collect(indexes=CannedIndexes())[1][0]
    indexes = CannedIndexes([fact(), fact(start=1)], data=ValueError("source missing"))
    records, gaps = collect(indexes=indexes)
    assert not records and len(gaps) == 2
    assert all("source_unresolved" in gap for gap in gaps)
    assert len(indexes.source_reads) == 1


def test_source_cache_uses_custody_identity_not_producer_coordinates():
    rows = [fact(), fact(start=1)]
    rows = [replace(row, location={**row.location, "producer_location": {
        "path": row.location["path"], "start_column": row.location["start_column"]}}) for row in rows]
    indexes = CannedIndexes(rows)
    records, gaps = collect(indexes=indexes)
    assert not gaps and len(records) == 2 and len(indexes.source_reads) == 1
    broken = replace(rows[0], location={**rows[0].location, "producer_location": []})
    records, gaps = collect([broken])
    assert not records and "source_unresolved" in gaps[0]
