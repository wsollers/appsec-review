"""Manual local publication join; never launches tools, containers, models or a job graph.

Prerequisite: explicit operator authorization, then APPSEC_T146_TAGS_INTEGRATION=1 and an
explicit --allow-heavy selection of this file. Fixture pins use this checkout's edited rules.
"""
from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path

import pytest

from appsec_review.jobs.job_security_tagging.job import _publish_shards
from appsec_review.jobs.job_security_tagging.producers import AcceptedIndexes, collect_graph_facts
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore, SourceLocation,
    index_fingerprint, write_manifest,
)
from appsec_review.retrieval.index import INDEX_SCHEMA, load_verified_manifest
from appsec_review.storage import file_sha256
from tests.unit.job_security_tagging.helpers import DATA, SNAPSHOT, fact, scope, taxonomy, unit_context


pytestmark = [
    pytest.mark.time_budget(30, reason="bounded local SQLite/source/tag publication joins"),
    pytest.mark.skipif(os.environ.get("APPSEC_T146_TAGS_INTEGRATION") != "1",
                       reason="manual prerequisite: explicitly authorize and set APPSEC_T146_TAGS_INTEGRATION=1"),
]


def fixture(root: Path):
    unit = unit_context(root, "publication.publish_index")
    run_root = unit.job.run_root
    target = root / "target"
    source_path = target / "src/app.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(DATA)
    rows = [fact(), fact("remote", family="entry_point")]
    identities = []
    for name in ("source", "graph"):
        producer = {"job": "job_code_graph_index" if name == "graph" else "job_target_catalog"}
        fingerprint = index_fingerprint(
            name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"fixture": name}],
            tool_identity=producer, parser_identity="fixture/1", normalizer_identity="fixture/1",
            mapping_identity="fixture/1")
        path = run_root / "data/indices" / name / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint,
                               target_snapshot=SNAPSHOT, shard_id="fixture")
        if name == "graph":
            rows = [replace(row, payload={**row.payload, "upstream": [
                {"index": identities[0].name, "shard_id": identities[0].shard_id,
                 "sha256": identities[0].sha256}]}) for row in rows]
            entities = [EntityRecord(LogicalIdentity.parse(row.identity), row.native_id, row.name, "",
                                     row.payload, SourceLocation(**row.location)) for row in rows]
        else:
            identity = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {
                "path": "src/app.py", "sha256": file_sha256(source_path)})
            entities = [EntityRecord(identity, "src/app.py", "app.py", "", {"language": "Python"},
                                     SourceLocation(**rows[0].location))]
        for entity in entities:
            builder.add_entity(entity)
        builder.add_coverage(name, "complete")
        digest = builder.build()
        identities.append(IndexIdentity(name, INDEX_SCHEMA, digest, fingerprint,
                                        path.relative_to(run_root).as_posix(), producer, (), "fixture"))
    manifest = run_root / "data/indices/manifests/input.json"
    write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=SNAPSHOT,
                   target_root=target, indexes=identities)
    indexes = AcceptedIndexes(run_root, manifest_path=manifest, manifest_sha256=file_sha256(manifest))
    return unit, indexes, rows, identities, target


def test_source_graph_tag_publication_retains_original_evidence_and_resolving_subject(tmp_path):
    unit, indexes, rows, identities, target = fixture(tmp_path)
    vocabulary, rules, _ = taxonomy()
    records, gaps = collect_graph_facts(indexes, scope(), vocabulary, rules, 20)
    assert not gaps and len(records) == 2
    pins = {key: value for key, value in unit.job.config.settings["taxonomy"].items() if key.endswith("_sha256")}
    published = _publish_shards(unit, records, indexes, pins, "e" * 64)
    combined = unit.job.run_root / "data/indices/manifests/tags.json"
    write_manifest(combined, run_id=unit.job.run_id, target_snapshot=SNAPSHOT,
                   target_root=target, indexes=[*identities, *published],
                   upstream_manifests=[{"path": indexes.manifest_path.relative_to(unit.job.run_root).as_posix(),
                                        "sha256": indexes.manifest_sha256}])
    load_verified_manifest(unit.job.run_root, combined, file_sha256(combined))
    core = RetrievalCore(unit.job.run_root.parent, unit.job.run_id,
                         manifest_path=combined, manifest_sha256=file_sha256(combined))
    stored = core.find(kind="tag_assignment", limit=10)["results"]
    assert {item["payload"]["assignment_id"] for item in stored} == {item["assignment_id"] for item in records}
    for record in records:
        original = core.find(identity=record["evidence"][0]["ref"], limit=1)["results"][0]
        assert original["payload"]["producer"] == record["evidence"][0]["graph_producer"]
        assert original["payload"]["scope"] == record["evidence"][0]["graph_scope"]
        subject = core.read_excerpt(identity=record["subject"]["logical_id"], context_lines=0)["results"][0]
        assert subject["excerpt"] == DATA.decode().strip()
        assert record["basis"] == "invoked" and record["family"] == "code_facts"
    assert len({record["subject"]["logical_id"] for record in records}) == 1


def test_changed_source_yields_gap_and_changed_shard_is_integrity_failure(tmp_path):
    unit, indexes, _, identities, target = fixture(tmp_path)
    vocabulary, rules, _ = taxonomy()
    (target / "src/app.py").write_bytes(b"changed")
    records, gaps = collect_graph_facts(indexes, scope(), vocabulary, rules, 20)
    assert not records and all("source_unresolved" in gap for gap in gaps)
    path = unit.job.run_root / next(item.relative_path for item in identities if item.name == "graph")
    path.chmod(0o600)
    with path.open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="integrity mismatch"):
        collect_graph_facts(indexes, scope(), vocabulary, rules, 20)


def test_foreign_snapshot_cannot_enter_accepted_manifest(tmp_path):
    unit, indexes, _, identities, target = fixture(tmp_path)
    foreign = unit.job.run_root / "data/indices/manifests/foreign.json"
    write_manifest(foreign, run_id=unit.job.run_id, target_snapshot="target-sha256:" + "f" * 64,
                   target_root=target, indexes=identities)
    with pytest.raises(ValueError, match="target snapshot mismatch"):
        AcceptedIndexes(unit.job.run_root, manifest_path=foreign, manifest_sha256=file_sha256(foreign))
