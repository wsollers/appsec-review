"""The real evidence view (T-107): bounded reads over real accepted shards and handoffs.

Every test builds its own run under ``tmp_path`` with real SQLite shards (``IndexBuilder``), real
manifests, the producers' real dataset declarations and hash-bound fixture handoffs. Reads run
inside the real ``runtime.inputs.input_read_scope`` over a hand-built context carrying the pins and
a typed contract, so pin resolution, shard ownership, handoff binding and byte checks are the
production code. Claim-time admission (``JobRunner.begin_attempt`` / ``admit_inputs``) is not
exercised here; that belongs to the job's own tests.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import asdict, replace
import hashlib
from importlib import import_module
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, Mapping, Sequence

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind, RelationRecord,
    SourceLocation, write_manifest,
)
from appsec_review.runtime.consume import UpstreamIntegrityError
from appsec_review.runtime.contracts import JobContract, TargetAccess, accepted_inputs
from appsec_review.runtime.datasets import dataset_contract, shard_owner
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.threat_model.contract import (
    JOB_ID, Basis, EvidenceRef, FactKind, InputState, Limits, Publication, SourceSpan, cite, element_id,
)
from appsec_review.threat_model.index_view import DECLARED_INPUTS, IndexEvidenceView
from appsec_review.threat_model.lanes.interactions import interactions
from appsec_review.threat_model.lanes.structure import structure
from appsec_review.threat_model.reference import load_reference
from appsec_review.threat_model.view import Page
from tests.handoff_fixture import write_fixture_handoff

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = "target-sha256:" + "7" * 64
FILE_SHA = "f" * 64
CATALOG, INDEXING, BUILD = "job_target_catalog", "job_artifact_indexing", "job_language_build"
GRAPH = ("job_code_graph_index", "code_graph_facts")
SYNTAX = ("job_tree_sitter_ast", "tree_sitter_ast")
UNIT = "native-cmake-0001"


@pytest.fixture(autouse=True)
def _no_disk_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    """The disk flush is the one faked boundary: building the fixture shards flushes many times,
    which dominates these tests on a busy host and is no part of what they assert."""
    monkeypatch.setattr(os, "fsync", lambda descriptor: None)


def _datasets(producer: str) -> tuple[Any, ...]:
    return import_module(f"appsec_review.jobs.{producer}.datasets").DATASETS


def entity(kind: EntityKind, key: str, payload: Mapping[str, Any] | None = None, *, name: str | None = None,
           text: str = "", line: int | None = None, path: str = "src/net.c") -> EntityRecord:
    location = None if line is None else SourceLocation(
        SNAPSHOT, path, FILE_SHA, 10 * line, 10 * line + 5, line, line, 1, 6, {}, "fixture", 1.0)
    return EntityRecord(LogicalIdentity.derive(kind, SNAPSHOT, {"fixture": key}), key, name or key, text,
                        payload or {}, location)


def call(key: str, written: str, line: int, *, category: str = "call_expression") -> EntityRecord:
    """A tree-sitter node as ``job_tree_sitter_ast`` publishes it (normalize.py:120-133)."""
    return entity(EntityKind.AST_NODE, key, {
        "schema": "appsec-review/tree-sitter-normalizer/1", "grammar_native_type": "call_expression",
        "language": "c", "syntax_only": True, "build_unit_id": UNIT,
        "syntax": {"category": category, "written_name": written, "enclosing_definition": "asr:ast_node:" + "1" * 64,
                   "syntactic_qualifiers": ["serve"], "resolution": "unresolved"}},
        name="call_expression", text=f"call_expression {written}", line=line)


class Run:
    """One tiny accepted run: real shards, one manifest and one fixture handoff per producer."""

    def __init__(self, tmp_path: Path, name: str = "run") -> None:
        self.root = tmp_path / name
        self.root.mkdir()
        self.units = 0
        self.pins: dict[str, str] = {}
        self.handoffs: dict[str, dict[str, Any]] = {}

    def shard(self, producer: str, index: str, shard_id: str, entities: Sequence[EntityRecord] = (),
              relations: Sequence[RelationRecord] = ()) -> IndexIdentity:
        fingerprint = hashlib.sha256(f"{producer}/{index}/{shard_id}".encode()).hexdigest()
        path = self.root / "data" / "indices" / index / f"{producer}-{shard_id}.sqlite"
        builder = IndexBuilder(path, name=index, fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
        for item in entities:
            builder.add_entity(item)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage("fixture", "complete")
        # The producing unit belongs to the step of the declaration that owns the shard, as
        # handoff verification requires of a required dataset.
        self.units += 1
        unit = f"{shard_owner(_datasets(producer), index, shard_id).step}.shard{self.units}"
        return IndexIdentity(index, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
                             path.relative_to(self.root).as_posix(), {"job": producer, "unit": unit}, (), shard_id)

    def accept(self, producer: str, shards: Sequence[IndexIdentity], *, gaps: Sequence[str] = ()) -> str:
        datasets = _datasets(producer)
        manifest = self.root / "data" / "indices" / "manifests" / f"{producer}.json"
        write_manifest(manifest, run_id=self.root.name, target_snapshot=SNAPSHOT,
                       target_root=self.root.parent / "target", indexes=shards)
        attempt = self.root / "data" / "jobs" / producer / "attempts" / "attempt_0001"
        atomic_json(attempt / "claim.json", {"dataset_contract": dataset_contract(
            producer, sorted({item.step for item in datasets}), datasets)})
        outputs: dict[str, dict[str, Any]] = {
            item.producer["unit"]: {"index_identity": asdict(item), "index_manifest": artifact_ref(self.root, manifest)}
            for item in shards}
        if gaps:
            outputs[shards[0].producer["unit"]].update(gaps=list(gaps), terminal_status="COMPLETED_WITH_GAPS")
        handoff = attempt / "handoff.json"
        write_fixture_handoff(self.root, handoff, {
            "job_id": producer, "source_fingerprint": SNAPSHOT, "outputs": outputs,
            "artifacts": [artifact_ref(self.root, self.root / item.relative_path) for item in shards]})
        digest = file_sha256(handoff)
        atomic_json(self.root / "data" / "jobs" / producer / "latest.json", {
            "handoff_path": handoff.relative_to(self.root).as_posix(), "handoff_sha256": digest})
        self.pins[producer] = digest
        self.handoffs[producer] = json.loads(handoff.read_text(encoding="utf-8"))
        return digest

    def accept_catalog(self, **entities: Sequence[EntityRecord]) -> str:
        """The catalog's five required datasets (handoff verification rejects a catalog without them)."""
        return self.accept(CATALOG, [self.shard(CATALOG, index, "default", entities.get(index, ()))
                                     for index in ("analysis", "build", "components", "documents", "source")])

    def view(self) -> IndexEvidenceView:
        return IndexEvidenceView(self.root, self.pins)


@contextmanager
def admitted(run: Run) -> Iterator[Any]:
    """The runner's unit read scope for the threat-model job over this run's pins."""
    inputs = []
    for producer in sorted({producer for producer, _ in DECLARED_INPUTS}):
        kinds = sorted(kind for name, kind in DECLARED_INPUTS if name == producer)
        inputs.extend(accepted_inputs(producer, _datasets(producer), output_kinds=kinds))
    context = SimpleNamespace(
        run_root=run.root, config=SimpleNamespace(job_id=JOB_ID), upstream_handoffs=dict(run.pins),
        contract=JobContract(inputs=tuple(inputs), target_access=TargetAccess.ACCEPTED_EVIDENCE),
        external_input_selection=None)
    with input_read_scope(context) as reads:
        yield reads


def _graph_run(tmp_path: Path, count: int = 2, name: str = "run") -> tuple[Run, list[IndexIdentity]]:
    run = Run(tmp_path, name)
    facts = [entity(EntityKind.ENTRY_POINT, f"entry-{index}", {"family": "entry_point", "exact": True,
                                                              "result": {"source_class": "remote", "score": 0.5}},
                    name=f"entry {index}", line=10 + index) for index in range(count)]
    shards = [run.shard(GRAPH[0], "graph", "graph-s1", facts[::2]), run.shard(GRAPH[0], "graph", "graph-s2", facts[1::2])]
    run.accept(GRAPH[0], shards)
    return run, shards


def _reference(entity_id: str, kind: str, publication: Publication, locator: str | None = None, *,
               ref_kind: str = "index_entity") -> EvidenceRef:
    return EvidenceRef(element_id("ev", [entity_id, publication.sha256, locator]), ref_kind, entity_id, kind,
                       publication, locator, None, Basis.DECLARED, "test.rule")


def test_entities_of_a_declared_output_come_back_in_id_order_with_publication_and_span(tmp_path: Path) -> None:
    run, shards = _graph_run(tmp_path, 4)
    with admitted(run) as reads:
        view = run.view()
        status = view.input_status(*GRAPH)
        page = view.entities(*GRAPH, "entry_point", limit=10)
    assert (status.state, status.handoff_sha256, status.coverage_disposition, status.upstream_gap_count) == (
        InputState.READ, run.pins[GRAPH[0]], "complete", 0)
    assert not page.truncated and len(page.records) == 4
    assert [item.entity_id for item in page.records] == sorted(item.entity_id for item in page.records)
    by_shard = {item.sha256: item for item in shards}
    for record in page.records:
        shard = by_shard[record.publication.sha256]
        assert record.publication == Publication(GRAPH[0], GRAPH[1], "graph", shard.shard_id, shard.sha256)
        assert record.entity_id.startswith("asr:entry_point:") and record.entity_kind == "entry_point"
        assert record.payload["result"] == {"source_class": "remote", "score": 0.5}
        assert record.content_sha256 is None
        line = 10 + int(record.name.split()[-1])
        assert record.span == SourceSpan("src/net.c", FILE_SHA, line, line, 10 * line, 10 * line + 5)
        assert record.span.locator == f"src/net.c:{line}-{line}#b{10 * line}-{10 * line + 5}@{FILE_SHA}"
    observed = {(item["output_kind"], item.get("sha256")) for item in reads.document()["reads"]}
    assert {(GRAPH[1], item.sha256) for item in shards} <= observed


def test_relations_are_returned_as_records_with_source_and_target_ids(tmp_path: Path) -> None:
    run = Run(tmp_path)
    library = entity(EntityKind.LIBRARY, "libnet", {"workspace_path": "build/libnet.a", "build_unit_id": UNIT})
    program = entity(EntityKind.EXECUTABLE, "server", {"workspace_path": "build/server", "build_unit_id": UNIT})
    link = RelationRecord(RelationKind.LINKS_INTO, library.identity.value, program.identity.value, True, 1.0, None,
                          {"build_unit_id": UNIT, "observation_count": 1, "source_id": "payload must not win"})
    catalog = run.shard(INDEXING, "artifacts", f"catalog-{UNIT}-native", [library, program])
    relations = run.shard(INDEXING, "artifacts", f"relations-{UNIT}", relations=[link])
    run.accept(INDEXING, [catalog, relations])
    with admitted(run):
        view = run.view()
        page = view.entities(INDEXING, "artifact_relationships", "LINKS_INTO", limit=10)
        elsewhere = view.entities(INDEXING, "artifact_catalog", "LINKS_INTO", limit=10)
        libraries = view.entities(INDEXING, "artifact_catalog", "library", limit=10)
    assert elsewhere == Page() and [item.entity_id for item in libraries.records] == [library.identity.value]
    (record,) = page.records
    assert record.entity_kind == "LINKS_INTO" and record.entity_id == link.relation_id
    assert record.name == f"{library.identity.value} -> {program.identity.value}"
    assert dict(record.payload) == {"source_id": library.identity.value, "target_id": program.identity.value,
                                    "build_unit_id": UNIT, "observation_count": 1}
    assert record.span is None
    assert record.publication == Publication(INDEXING, "artifact_relationships", "artifacts", f"relations-{UNIT}",
                                             relations.sha256)


def test_limit_truncates_and_reports_it(tmp_path: Path) -> None:
    run, _shards = _graph_run(tmp_path, 5)
    with admitted(run):
        view = run.view()
        everything = view.entities(*GRAPH, "entry_point", limit=5)
        bounded = view.entities(*GRAPH, "entry_point", limit=3)
        with pytest.raises(ValueError, match="positive integer"):
            view.entities(*GRAPH, "entry_point", limit=0)
    assert not everything.truncated and len(everything.records) == 5
    assert bounded.truncated and bounded.records == everything.records[:3]


def test_search_calls_matches_the_written_name_exactly(tmp_path: Path) -> None:
    run = Run(tmp_path)
    longer, exact = call("a", "recv_all", 3), call("b", "recv", 7)
    nodes = [longer, exact, call("c", "recv", 9, category="reference"), call("d", "os.system", 11)]
    run.accept(SYNTAX[0], [run.shard(SYNTAX[0], "analysis", "ts-c", nodes)])
    hostile = ("recv' OR '1'='1", '"; DROP TABLE entities; --', 're"cv', "recv*", "%", "*", "\x00recv", "NEAR(recv",
               "recv AND all", "")
    with admitted(run):
        view = run.view()
        found = view.search_calls("recv", limit=10)
        prefix = view.search_calls("recv_all", limit=10)
        dotted = view.search_calls("os.system", limit=10)
        unmatched = [view.search_calls(name, limit=10) for name in hostile]
        assert view.entities(*SYNTAX, "ast_node", limit=10).records[0].entity_kind == "ast_node"
    assert [item.entity_id for item in found.records] == [exact.identity.value] and not found.truncated
    assert found.records[0].payload["syntax"]["written_name"] == "recv" and found.records[0].span.start_line == 7
    assert [item.entity_id for item in prefix.records] == [longer.identity.value]
    assert [item.payload["syntax"]["written_name"] for item in dotted.records] == ["os.system"]
    assert unmatched == [Page()] * len(hostile)


def test_search_calls_is_bounded_in_id_order(tmp_path: Path) -> None:
    run = Run(tmp_path)
    nodes = [call(f"n{index}", "recv", index + 1) for index in range(4)]
    run.accept(SYNTAX[0], [run.shard(SYNTAX[0], "analysis", "ts-c", nodes[:2]),
                           run.shard(SYNTAX[0], "analysis", "ts-cpp", nodes[2:])])
    with admitted(run):
        page = run.view().search_calls("recv", limit=3)
    assert page.truncated
    assert [item.entity_id for item in page.records] == sorted(item.identity.value for item in nodes)[:3]


def test_absent_producer_is_absent_and_empty_output_is_empty(tmp_path: Path) -> None:
    run = Run(tmp_path)
    binary = entity(EntityKind.EXECUTABLE, "server", {"workspace_path": "build/server", "build_unit_id": UNIT})
    run.accept(INDEXING, [run.shard(INDEXING, "artifacts", f"catalog-{UNIT}-native", [binary])])
    with admitted(run):
        pinned, scoped = run.view(), IndexEvidenceView(run.root)
        for view in (pinned, scoped):
            assert view.input_status(INDEXING, "artifact_catalog").state is InputState.READ
            empty = view.input_status(INDEXING, "artifact_relationships")
            assert (empty.state, empty.handoff_sha256) == (InputState.EMPTY, run.pins[INDEXING])
            absent = view.input_status(BUILD, "build_actions")
            assert (absent.state, absent.handoff_sha256, absent.coverage_disposition) == (InputState.ABSENT, None, None)
            assert view.entities(INDEXING, "artifact_relationships", "LINKS_INTO", limit=5) == Page()
            assert view.entities(BUILD, "build_actions", "executable", limit=5) == Page()
            assert view.search_calls("recv", limit=5) == Page()
            with pytest.raises(ValueError, match="undeclared threat-model input"):
                view.input_status(INDEXING, "archive_members")
    # Outside a runtime scope the verified pointer answers, and an unpinned producer stays absent.
    assert IndexEvidenceView(run.root).input_status(INDEXING, "artifact_catalog").state is InputState.READ
    assert IndexEvidenceView(run.root, {}).input_status(INDEXING, "artifact_catalog").state is InputState.ABSENT
    with pytest.raises(UpstreamIntegrityError, match="not the one this attempt admitted"):
        IndexEvidenceView(run.root, {INDEXING: "0" * 64}).input_status(INDEXING, "artifact_catalog")


def test_producer_disabled_in_the_frozen_configuration_is_disabled(tmp_path: Path) -> None:
    run = Run(tmp_path)
    atomic_json(run.root / "data" / "configuration" / "resolved.json", {"jobs": {
        BUILD: {"settings": {"enabled": False}}, SYNTAX[0]: {"settings": {"enabled": True}}, GRAPH[0]: {}}})
    view = IndexEvidenceView(run.root)
    assert view.input_status(BUILD, "build_actions").state is InputState.DISABLED
    assert view.input_status(*SYNTAX).state is InputState.ABSENT
    assert view.input_status(*GRAPH).state is InputState.ABSENT
    assert IndexEvidenceView(Run(tmp_path, "unconfigured").root).input_status(BUILD, "build_actions").state \
        is InputState.ABSENT


def test_partial_upstream_reports_its_gap_count_and_coverage(tmp_path: Path) -> None:
    run = Run(tmp_path)
    run.accept(SYNTAX[0], [run.shard(SYNTAX[0], "analysis", "ts-c", [call("a", "recv", 3)])],
               gaps=["tree_sitter_ast: one scope was not parsed"])
    coverage = run.handoffs[SYNTAX[0]]["coverage"]
    assert coverage["disposition"] == "partial" and coverage["gap_count"] >= 1
    with admitted(run):
        view = run.view()
        status = view.input_status(*SYNTAX)
        page = view.search_calls("recv", limit=5)
    assert (status.state, status.handoff_sha256, status.coverage_disposition, status.upstream_gap_count) == (
        InputState.PARTIAL, run.pins[SYNTAX[0]], "partial", coverage["gap_count"])
    assert len(page.records) == 1


def test_shard_of_another_output_kind_of_the_same_producer_is_not_returned(tmp_path: Path) -> None:
    run = Run(tmp_path)
    wanted, other = call("a", "recv", 3), call("b", "recv", 5)
    ast = run.shard(SYNTAX[0], "analysis", "ts-c", [wanted])
    coverage = run.shard(SYNTAX[0], "analysis", "tree-sitter-coverage-attempt_0001", [other])
    run.accept(SYNTAX[0], [ast, coverage])
    run.accept_catalog(analysis=[call("c", "recv", 7)])  # another producer's shard of the same index
    with admitted(run) as reads:
        view = run.view()
        listed = view.entities(*SYNTAX, "ast_node", limit=10)
        searched = view.search_calls("recv", limit=10)
        assert view.entities(CATALOG, "source_files", "ast_node", limit=10) == Page()
    for page in (listed, searched):
        assert [(item.entity_id, item.publication.shard_id) for item in page.records] == [(wanted.identity.value, "ts-c")]
    opened = {item["sha256"] for item in reads.document()["reads"] if "path" in item}
    assert ast.sha256 in opened and coverage.sha256 not in opened


def test_changed_shard_bytes_are_refused(tmp_path: Path) -> None:
    run, shards = _graph_run(tmp_path, 2)
    with pytest.raises(UpstreamIntegrityError, match="bytes changed after acceptance"):
        with admitted(run):
            view = run.view()
            assert len(view.entities(*GRAPH, "entry_point", limit=5).records) == 2
            (run.root / shards[0].relative_path).write_bytes(b"changed")
            view.entities(*GRAPH, "entry_point", limit=5)
    with pytest.raises(ValueError):  # a fresh view fails while verifying the handoff or its manifest
        run.view().entities(*GRAPH, "entry_point", limit=5)


def test_resolves_accepts_a_cited_record_and_rejects_a_changed_or_foreign_one(tmp_path: Path) -> None:
    run, shards = _graph_run(tmp_path, 2)
    foreign, _ = _graph_run(tmp_path, 4, "other")  # same ids, other shard bytes
    library = entity(EntityKind.LIBRARY, "libnet", {"workspace_path": "build/libnet.a", "build_unit_id": UNIT})
    program = entity(EntityKind.EXECUTABLE, "server", {"workspace_path": "build/server", "build_unit_id": UNIT})
    link = RelationRecord(RelationKind.LINKS_INTO, library.identity.value, program.identity.value, True, 1.0)
    run.accept(INDEXING, [run.shard(INDEXING, "artifacts", f"catalog-{UNIT}-native", [library, program]),
                          run.shard(INDEXING, "artifacts", f"relations-{UNIT}", relations=[link])])
    with admitted(foreign):
        elsewhere = foreign.view().entities(*GRAPH, "entry_point", limit=5).records[0]
    with admitted(run):
        view = run.view()
        record = view.entities(*GRAPH, "entry_point", limit=5).records[0]
        (relation,) = view.entities(INDEXING, "artifact_relationships", "LINKS_INTO", limit=5).records
        (artifact,) = view.entities(INDEXING, "artifact_catalog", "library", limit=5).records
        good = cite(record, Basis.VERIFIED_SEMANTIC, "graph.entry_point.remote")
        publication, locator = record.publication, record.span.locator
        moved = replace(record.span, start_line=record.span.start_line + 1, end_line=record.span.end_line + 1)
        bound = Publication(GRAPH[0], "handoff", None, None, shards[0].sha256)
        assert view.resolves(good)
        assert view.resolves(cite(relation, Basis.DECLARED, "structure.link_relation"))
        assert view.resolves(cite(artifact, Basis.DECLARED, "structure.built_artifact"))
        assert view.resolves(_reference(record.entity_id, "entry_point", publication))  # no locator to compare
        assert view.resolves(_reference(shards[0].relative_path, "index_shard", bound, ref_kind="run_artifact"))
        rejected = [
            cite(replace(record, span=moved), Basis.DECLARED, "test.rule"),
            cite(replace(record, entity_kind="sink_site"), Basis.DECLARED, "test.rule"),
            cite(replace(record, entity_id="asr:entry_point:" + "0" * 64), Basis.DECLARED, "test.rule"),
            cite(replace(record, publication=replace(publication, sha256="0" * 64)), Basis.DECLARED, "test.rule"),
            cite(replace(record, publication=replace(publication, shard_id="graph-zz")), Basis.DECLARED, "test.rule"),
            cite(replace(record, publication=replace(publication, output_kind="graph_coverage")), Basis.DECLARED,
                 "test.rule"),
            cite(replace(record, publication=replace(publication, job="job_other")), Basis.DECLARED, "test.rule"),
            cite(replace(record, content_sha256="a" * 64), Basis.DECLARED, "test.rule"),
            cite(replace(relation, span=record.span), Basis.DECLARED, "test.rule"),
            cite(elsewhere, Basis.DECLARED, "test.rule"),
            _reference(record.entity_id, "entry_point", publication, locator + "0"),
            _reference(shards[0].relative_path, "index_shard", replace(bound, sha256="0" * 64), ref_kind="run_artifact"),
            _reference("data/jobs/unbound.json", "index_shard", bound, ref_kind="run_artifact"),
            _reference(shards[0].relative_path, "index_shard", replace(bound, job="job_other"), ref_kind="run_artifact"),
        ]
        assert [view.resolves(item) for item in rejected] == [False] * len(rejected)
        assert view.resolves("not a reference") is False  # type: ignore[arg-type]


def test_the_real_lanes_run_over_the_view(tmp_path: Path) -> None:
    run = Run(tmp_path)
    point = {"name": "server", "kind": "executable", "evidence": "CMakeLists.txt:3", "sources": ["src/net.c"],
             "include_dirs": []}
    unit = entity(EntityKind.BUILD_ACTION, UNIT, {
        "build_unit_id": UNIT, "root": ".", "family": "native", "build_system": "cmake", "build_points": [point]},
        name="cmake")
    binary = entity(EntityKind.EXECUTABLE, "server", {
        "workspace_path": "build/server", "sha256": "e" * 64, "size_bytes": 4096, "kind": "executable",
        "build_unit_id": UNIT, "artifact_origin": "build-output"})
    run.accept_catalog(build=[unit])
    run.accept(INDEXING, [run.shard(INDEXING, "artifacts", f"catalog-{UNIT}-native", [binary])])
    run.accept(SYNTAX[0], [run.shard(SYNTAX[0], "analysis", "ts-c", [call("a", "recv", 42)])])
    rules = load_reference(ROOT)
    assert "recv" in rules.callee_names()
    with admitted(run):
        view = run.view()
        built = structure(view, Limits())
        observed = interactions(view, rules, Limits())
        (process,) = [fact for fact in built.facts if fact.kind is FactKind.PROCESS]
        (interaction,) = [fact for fact in observed.facts if fact.kind is FactKind.INTERACTION]
        assert len(process.evidence) == 2 and all(view.resolves(item) for item in process.evidence)
        assert len(interaction.evidence) == 1 and all(view.resolves(item) for item in interaction.evidence)
    assert process.name == "server" and process.attributes["built"] is True
    assert process.attributes["build_unit_id"] == UNIT and process.attributes["artifact_path"] == "build/server"
    assert process.attributes["source_paths"] == ("src/net.c",)
    assert interaction.attributes["interaction"] == rules.interaction_for_callee("recv").value
    assert (interaction.attributes["callee"], interaction.attributes["path"], interaction.attributes["build_unit_id"],
            interaction.attributes["enclosing_symbol"]) == ("recv", "src/net.c", UNIT, "serve")
    states = {(row.producer, row.output_kind): (row.state, row.records_read) for row in (*built.ledger, *observed.ledger)}
    assert states[(CATALOG, "build_units")] == (InputState.READ, 1)
    assert states[(CATALOG, "components")] == (InputState.READ, 0)
    assert states[(INDEXING, "artifact_catalog")] == (InputState.READ, 1)
    assert states[(BUILD, "build_actions")] == (InputState.ABSENT, 0)
    assert states[SYNTAX] == (InputState.READ, 1)
    assert states[GRAPH] == (InputState.ABSENT, 0)
