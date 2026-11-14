"""Generated-map projection and bounded artifact reader with only admission/retrieval faked."""
from copy import deepcopy
from types import SimpleNamespace
import json

import pytest

from appsec_review.review.behavior import MODEL_JOB, graph_operations, load_model, project_model
from appsec_review.review.models import IntegrityError
from appsec_review.storage import file_sha256
from appsec_review.threat_model.assemble import Assembly
from appsec_review.threat_model.contract import (
    Basis, Boundary, BoundaryKind, Element, ElementKind, EvidenceRef, Flow, Interaction,
    Mitigation, MitigationState, NameBasis, Origin, Publication, Stride, Threat, ThreatState,
    UnknownKind, canonical, element_id, unknown,
)
from appsec_review.threat_model.documents import build_documents, plain

from .support import ENTRY, SHA, SINK, SNAPSHOT, Scope, graph_row


def model_documents(count=1, *, threat_count=0, with_unknown=False, split_anchors=False):
    publication = Publication("job_code_graph_index", "code_graph_facts", "graph", "facts", SHA)
    ref = EvidenceRef(element_id("ev", [SINK, SHA, None]), "index_entity", SINK, "sink_site",
                      publication, None, "c" * 64, Basis.VERIFIED_SEMANTIC, "fixture/1")
    entry_ref = EvidenceRef(element_id("ev", [ENTRY, SHA, None]), "index_entity", ENTRY, "entry_point",
                            publication, None, "c" * 64, Basis.VERIFIED_SEMANTIC, "fixture/1")
    process, external, boundary = "proc:" + "1" * 16, "ext:" + "2" * 16, "tb:" + "3" * 16
    assembly = Assembly(elements=(
        Element(process, ElementKind.PROCESS, "service", NameBasis.DECLARED_NAME, Basis.DECLARED, (ref,)),
        Element(external, ElementKind.EXTERNAL_ENTITY, "peer", NameBasis.DERIVED, Basis.DERIVED, (ref,))),
        flows=tuple(Flow("flow:" + f"{number:016x}", external, process, Interaction.NETWORK_RECEIVE,
                         Basis.DERIVED, (entry_ref if split_anchors and number else ref,), (boundary,))
                    for number in range(count)),
        boundaries=(Boundary(boundary, BoundaryKind.NETWORK, (process,), Basis.DERIVED, (ref,)),),
        unknowns=(unknown(UnknownKind.DEPLOYMENT_NOT_DESCRIBED, "Deployment is not established"),)
        if with_unknown else ())
    origin = Origin("fixture", "attempt_0001", SNAPSHOT, {})
    threats = tuple(Threat("threat:" + f"{number:016x}", ThreatState.CANDIDATE, Stride.TAMPERING,
                           "test-template", "Candidate", "Can input cross the boundary?", (process,),
                           (assembly.flows[0].id,), (boundary,), (ref,), ("input_control",),
                           Mitigation(MitigationState.NOT_EXAMINED)) for number in range(threat_count))
    documents = build_documents(origin, assembly, threats, (), ())
    return tuple(plain(value) for value in (documents.dfd, documents.threat_model,
                                           documents.evidence, documents.result))


def project(docs=None, *, resolve=lambda _: True, limit=8):
    operations, _ = graph_operations(Scope(graph=[graph_row()]), limit=8)
    return project_model(*(docs or model_documents()), run_id="fixture", snapshot=SNAPSHOT,
                         operations=operations, resolve=resolve, limit=limit)


def test_original_anchor_join_retains_generated_authority_and_boundary():
    docs = model_documents()
    before = deepcopy(docs)
    seen = []
    joined, gaps = project(docs, resolve=lambda ref: seen.append(ref["entity_id"]) or True)
    assert not gaps and seen == [SINK] and docs == before
    context, = next(iter(joined.values()))
    assert context["authority"] == "routing_context" and context["basis"] == "derived"
    assert context["boundary_ids"] == ["tb:" + "3" * 16]
    assert context["interaction"] == "network_receive"


def test_no_similarity_join_for_unrelated_original_identity():
    docs = model_documents()
    operations, _ = graph_operations(Scope(graph=[graph_row(identity="asr:sink_site:" + "8" * 64)]), limit=8)
    joined, gaps = project_model(*docs, run_id="fixture", snapshot=SNAPSHOT, operations=operations,
                                resolve=lambda _: pytest.fail("unrelated identity must not be resolved"), limit=8)
    assert not gaps and list(joined.values()) == [()]


@pytest.mark.parametrize("field,value", [("run_id", "foreign"), ("target_snapshot", "foreign")])
def test_foreign_model_fails_before_context_projection(field, value):
    docs = model_documents()
    for document in docs:
        document["origin"][field] = value
    with pytest.raises(IntegrityError, match="another review scope"):
        project(docs)


def test_source_reference_must_resolve_in_the_accepted_scope():
    with pytest.raises(IntegrityError, match="accepted evidence"):
        project(resolve=lambda _: False)


def test_inline_reference_cannot_disagree_with_registry():
    docs = model_documents()
    docs[0]["flows"][0]["evidence"][0]["content_sha256"] = "d" * 64
    with pytest.raises(IntegrityError, match="evidence registry"):
        project(docs)


def test_context_cap_and_reference_resolution_are_bounded():
    seen = []
    joined, gaps = project(model_documents(3), resolve=lambda ref: seen.append(ref) or True, limit=1)
    assert len(next(iter(joined.values()))) == 1
    assert len(seen) == 1
    assert all(gap.state == "truncated" for gap in gaps) and gaps


def test_invalid_context_limit_fails():
    with pytest.raises(ValueError, match="positive"):
        project(limit=0)


def test_candidate_threat_cap_counts_omitted_questions_not_findings():
    joined, gaps = project(model_documents(threat_count=3), limit=1)
    assert len(next(iter(joined.values()))[0]["threat_ids"]) == 1
    assert any("2 candidate threat references omitted" in gap.reason for gap in gaps)


def test_context_union_is_bounded_across_original_anchors():
    operations, _ = graph_operations(Scope(graph=[graph_row(), graph_row(ENTRY, "entry_point", "remote")]), limit=8)
    joined, gaps = project_model(*model_documents(2, split_anchors=True), run_id="fixture", snapshot=SNAPSHOT,
                                operations=operations, resolve=lambda _: True, limit=1)
    assert len(next(iter(joined.values()))) == 1
    assert any("1 generated contexts omitted" in gap.reason for gap in gaps)


def test_generated_unknowns_remain_explicit_coverage_limits():
    joined, gaps = project(model_documents(with_unknown=True))
    assert joined and any(gap.state == "partial" and "unknowns" in gap.reason for gap in gaps)


def reader_fixture(tmp_path, monkeypatch):
    from appsec_review.runtime import consume, inputs
    scope = Scope(graph=[graph_row()])
    scope.run_root = tmp_path
    scope.shards = ({"name": "graph", "shard_id": "facts", "sha256": SHA},)
    docs = model_documents()
    references = {}
    for name, document in zip(("dfd.json", "threat-model.json", "evidence.json"), docs[:3]):
        path = tmp_path / name
        path.write_bytes(canonical(document))
        references[name] = {"path": name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
    result = {**docs[3], "artifacts": references}
    path = tmp_path / "result.json"
    path.write_bytes(canonical(result))
    result_ref = {"path": path.name, "sha256": file_sha256(path), "size_bytes": path.stat().st_size}
    handoff = {"outputs": {"publication.publish_handoff": {"artifact": result_ref}},
               "artifacts": [result_ref, *references.values()]}
    accepted = SimpleNamespace(handoff=handoff, identity={"path": "handoff.json", "sha256": SHA})
    calls = []

    def upstream(root, job_id, *, required):
        assert root == tmp_path and job_id == MODEL_JOB and required is False
        return accepted

    monkeypatch.setattr(consume, "accepted_upstream", upstream)
    monkeypatch.setattr(inputs, "observe_output",
                        lambda root, job, kind, ref: calls.append((root, job, kind, ref)))
    core = SimpleNamespace(find=lambda **_: {"truncated": False, "results": [graph_row()]})
    operations, _ = graph_operations(scope, limit=8)
    return scope, core, operations, calls, handoff


def test_reader_binds_hashes_and_records_each_declared_read(tmp_path, monkeypatch):
    scope, core, operations, calls, _ = reader_fixture(tmp_path, monkeypatch)
    joined, gaps, identity = load_model(scope, operations, core=core, max_bytes=100_000, limit=8)
    assert joined and not gaps and identity["handoff"]["sha256"] == SHA
    assert [call[2] for call in calls] == [
        "threat_model_documents", "generated_dfd", "generated_threat_model", "generated_model_evidence"]


def test_absent_optional_model_is_a_gap(tmp_path, monkeypatch):
    from appsec_review.runtime import consume
    scope = Scope()
    scope.run_root = tmp_path
    monkeypatch.setattr(consume, "accepted_upstream", lambda *a, **k: None)
    joined, gaps, identity = load_model(scope, (), core=None, max_bytes=100, limit=1)
    assert joined == {} and identity is None and gaps[0].state == "missing"


def test_read_budget_is_a_named_gap_not_partial_model_context(tmp_path, monkeypatch):
    scope, core, operations, calls, _ = reader_fixture(tmp_path, monkeypatch)
    joined, gaps, identity = load_model(scope, operations, core=core, max_bytes=1, limit=8)
    assert not joined and identity is None and gaps[0].state == "truncated" and calls == []


@pytest.mark.parametrize("fault", ["changed", "unbound", "foreign-shard", "unresolved", "wrong-kind"])
def test_corrupt_supplied_model_cannot_degrade_to_a_clean_result(tmp_path, monkeypatch, fault):
    scope, core, operations, _, handoff = reader_fixture(tmp_path, monkeypatch)
    if fault == "changed":
        (tmp_path / "dfd.json").write_text("{}")
    elif fault == "unbound":
        handoff["artifacts"] = handoff["artifacts"][:1]
    elif fault == "foreign-shard":
        scope.shards = ()
    elif fault == "unresolved":
        core.find = lambda **_: {"truncated": False, "results": []}
    else:
        core.find = lambda **_: {"truncated": False, "results": [{**graph_row(), "kind": "source_file"}]}
    with pytest.raises((IntegrityError, ValueError)):
        load_model(scope, operations, core=core, max_bytes=100_000, limit=8)
