from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RelationKind as IndexRelation,
    RelationRecord, RetrievalCore, RetrievalLimits, SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.evidence import (
    DIRECT_KINDS, INDIRECT_KINDS, MAPPED_KINDS, classify, make_gap, resolve_relation, satisfies,
)
from appsec_review.review.models import (
    Admissibility, EvidenceRelation, Gap, GapClass, Predicate, RelationKind,
)
from appsec_review.storage import atomic_json, file_sha256

RUN_ID = "2026-10-12-0001"
SNAPSHOT = "target-sha256:" + "2" * 64
CLAIM = "claim-" + "c" * 64
CELL = "cell-" + "d" * 64
RECEIPT = "e" * 64


def _ident(kind: EntityKind, native: str) -> str:
    return LogicalIdentity.derive(kind, SNAPSHOT, {"native": native}).value


def _accepted_fixture(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    """Build a minimal accepted index set: analysis, observations, and priority shards."""
    runs = tmp_path / "runs"
    run_root = runs / RUN_ID
    attempt = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    source = target / "src" / "copy.c"
    source.write_text("void copy(char *in) {\n  char buf[8];\n  strcpy(buf, in);\n}\n", encoding="utf-8")
    sha = file_sha256(source)
    span = SourceLocation(SNAPSHOT, "src/copy.c", sha, 23, 55, 3, 3, 3, 19, {}, "fixture-exact", 1.0)
    whole = SourceLocation(SNAPSHOT, "src/copy.c", sha, 0, source.stat().st_size, 1, 4, 1, 1, {},
                           "fixture-exact", 1.0)
    ids = {
        "span": _ident(EntityKind.SOURCE_SPAN, "copy.c:3"),
        "symbol": _ident(EntityKind.SYMBOL, "copy"),
        "observation": _ident(EntityKind.TOOL_OBSERVATION, "semgrep:strcpy"),
        "ambiguous_observation": _ident(EntityKind.TOOL_OBSERVATION, "semgrep:maybe"),
        "artifact": _ident(EntityKind.EVIDENCE_ARTIFACT, "sarif:1"),
        "priority": _ident(EntityKind.PRIORITY_ITEM, "copy-priority"),
        "absent": _ident(EntityKind.SOURCE_SPAN, "never-indexed"),
    }
    identities: list[IndexIdentity] = []

    def build(name: str, entities: list[EntityRecord], relations: list[RelationRecord]) -> None:
        fingerprint = index_fingerprint(
            name=name, target_snapshot=SNAPSHOT, producer_artifacts=[{"sha256": "a" * 64}],
            tool_identity={"tool": "fixture"}, parser_identity="p/1", normalizer_identity="n/1",
            mapping_identity="m/1")
        path = run_root / "data" / "indices" / name / "default" / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint, target_snapshot=SNAPSHOT)
        for entity in entities:
            builder.add_entity(entity)
        for relation in relations:
            builder.add_relation(relation)
        builder.add_coverage(name, "complete", None)
        digest = builder.build()
        identities.append(IndexIdentity(name, "appsec-review/retrieval-index/2", digest, fingerprint,
                                        path.relative_to(run_root).as_posix(), {"fixture": name}))

    build("analysis", [
        EntityRecord(LogicalIdentity.parse(ids["span"]), "copy.c:3", "strcpy call", "strcpy(buf, in)", {}, span),
        EntityRecord(LogicalIdentity.parse(ids["symbol"]), "copy", "copy", "function copy", {}, whole),
    ], [])
    build("observations", [
        EntityRecord(LogicalIdentity.parse(ids["observation"]), "semgrep:strcpy", "c.strcpy",
                     "unbounded strcpy", {"rule": "c.strcpy"}, span),
        EntityRecord(LogicalIdentity.parse(ids["ambiguous_observation"]), "semgrep:maybe", "c.maybe",
                     "maybe", {"rule": "c.maybe"}),
        EntityRecord(LogicalIdentity.parse(ids["artifact"]), "sarif:1", "sarif", "sarif", {"sha256": "b" * 64}),
    ], [
        RelationRecord(IndexRelation.DERIVED_FROM, ids["observation"], ids["artifact"], True, 1.0),
        RelationRecord(IndexRelation.SUPPORTS, ids["ambiguous_observation"], ids["span"], False, 0.4,
                       "two candidate spans"),
    ])
    build("priority", [
        EntityRecord(LogicalIdentity.parse(ids["priority"]), "copy-priority", "copy", "hot", {"rank": 1}),
    ], [])
    manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=SNAPSHOT, target_root=target, indexes=identities)
    artifact = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    handoff = attempt / "handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(run_root, handoff, {"source_fingerprint": SNAPSHOT, "status": "ACCEPTED", "job_id": "fixture",
                          "attempt_id": "attempt_0001", "artifacts": [artifact], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"]})
    return runs, ids, source


@pytest.fixture()
def accepted(tmp_path: Path) -> tuple[Path, dict[str, str], Path]:
    return _accepted_fixture(tmp_path)


def _resolve(core: RetrievalCore, entity_id: str, predicate: Predicate = Predicate.AFFECTED_CONSTRUCT,
             kind: RelationKind = RelationKind.SUPPORTS, rule_predicates=()) -> EvidenceRelation | Gap:
    return resolve_relation(core, claim_id=CLAIM, predicate=predicate, kind=kind, entity_id=entity_id,
                            producing_cell_id=CELL, retrieval_receipt_sha256=RECEIPT,
                            rule_predicates=rule_predicates)


# Classification (R3 table)

@pytest.mark.parametrize("kind", sorted(DIRECT_KINDS))
def test_every_structured_content_kind_is_direct_for_the_construct_and_never_for_impact(kind: EntityKind) -> None:
    """Deliberately changed from "every DIRECT kind is direct for every predicate": relevance is per
    (kind, predicate) under ``predicate-admission/1`` (the full table is in test_predicate_admission.py)."""
    assert classify(kind, Predicate.AFFECTED_CONSTRUCT) is Admissibility.DIRECT
    assert classify(kind, Predicate.SECURITY_IMPACT) is not Admissibility.DIRECT
    assert {classify(kind, predicate) for predicate in Predicate} <= {
        Admissibility.DIRECT, Admissibility.ANALYST_ASSESSED, Admissibility.INDIRECT}


@pytest.mark.parametrize("kind", sorted(set(EntityKind) - DIRECT_KINDS - MAPPED_KINDS))
def test_indirect_and_unlisted_kinds_never_satisfy(kind: EntityKind) -> None:
    every = tuple(Predicate)
    assert {classify(kind, predicate, every) for predicate in Predicate} == {Admissibility.INDIRECT}


def test_r3_indirect_kinds_are_exactly_listed() -> None:
    assert {kind.value for kind in INDIRECT_KINDS} == {
        "hotspot", "priority_item", "history_signal", "change", "change_context_signal", "review_signal",
        "tag_assignment", "review_unit", "advisory", "dependency_package", "precomputed_fact"}
    assert not (INDIRECT_KINDS & DIRECT_KINDS) and not (MAPPED_KINDS & DIRECT_KINDS)
    assert {EntityKind.BUILD_ACTION, EntityKind.WASM_MODULE, EntityKind.EVIDENCE_ARTIFACT} <= DIRECT_KINDS
    assert Admissibility.ANALYST_ASSESSED not in {classify(kind, predicate, tuple(Predicate))
                                                  for kind in INDIRECT_KINDS | MAPPED_KINDS for predicate in Predicate}


def test_tool_observation_is_direct_only_for_its_mapped_predicate() -> None:
    mapped = {Predicate.SOURCE_TO_SINK_REACHABILITY}
    for predicate in Predicate:
        expected = (Admissibility.DIRECT_FOR_MAPPED_PREDICATE if predicate in mapped else Admissibility.INDIRECT)
        assert classify("tool_observation", predicate, mapped) is expected
    assert classify(EntityKind.TOOL_OBSERVATION, Predicate.SECURITY_IMPACT) is Admissibility.INDIRECT
    with pytest.raises(ValueError):
        classify("model_prose", Predicate.SECURITY_IMPACT)


def test_gap_identity_is_deterministic_and_bounded() -> None:
    first = make_gap(GapClass.EVIDENCE_GAP, CLAIM, "x  " * 400, predicate=Predicate.SECURITY_IMPACT)
    again = make_gap(GapClass.EVIDENCE_GAP, CLAIM, "x  " * 400, predicate=Predicate.SECURITY_IMPACT)
    other = make_gap(GapClass.EVIDENCE_GAP, CLAIM, "x  " * 400, predicate=Predicate.AFFECTED_CONSTRUCT)
    assert first == again and first.gap_id != other.gap_id and len(first.reason) <= 256
    assert first.gap_id.startswith("gap-")


# Resolution against an accepted manifest

def test_source_span_resolves_to_complete_direct_relation(accepted) -> None:
    runs, ids, _ = accepted
    core = RetrievalCore(runs, RUN_ID)
    relation = _resolve(core, ids["span"])
    assert isinstance(relation, EvidenceRelation)
    assert relation.admissibility is Admissibility.DIRECT and relation.complete and satisfies(relation)
    assert relation.shard_id == "analysis/default" and relation.entity_kind == "source_span"
    assert relation.locator.startswith("src/copy.c:3-3#b23-55@")
    assert relation.relation_id.startswith("evrel-") and len(relation.content_sha256) == 64
    assert relation.retrieval_receipt_sha256 == RECEIPT and relation.producing_cell_id == CELL
    again = _resolve(core, ids["span"])
    assert again == relation
    contra = _resolve(core, ids["span"], kind=RelationKind.CONTRADICTS)
    assert isinstance(contra, EvidenceRelation) and contra.relation_id != relation.relation_id


def test_tool_observation_resolves_through_resolve_evidence_with_rule_mapping(accepted) -> None:
    runs, ids, _ = accepted
    core = RetrievalCore(runs, RUN_ID)
    mapped = _resolve(core, ids["observation"], Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                      rule_predicates=[Predicate.MISSING_OR_INEFFECTIVE_GUARD])
    assert isinstance(mapped, EvidenceRelation)
    assert mapped.admissibility is Admissibility.DIRECT_FOR_MAPPED_PREDICATE and mapped.complete
    assert mapped.shard_id == "observations/default"
    unmapped = _resolve(core, ids["observation"], Predicate.SECURITY_IMPACT,
                        rule_predicates=[Predicate.MISSING_OR_INEFFECTIVE_GUARD])
    assert isinstance(unmapped, EvidenceRelation) and not satisfies(unmapped)
    artifact = _resolve(core, ids["artifact"])
    assert isinstance(artifact, EvidenceRelation) and artifact.locator.startswith("observations/default:")
    assert satisfies(artifact)


def test_ambiguous_evidence_trace_is_incomplete(accepted) -> None:
    runs, ids, _ = accepted
    core = RetrievalCore(runs, RUN_ID)
    relation = _resolve(core, ids["ambiguous_observation"], Predicate.AFFECTED_CONSTRUCT,
                        rule_predicates=[Predicate.AFFECTED_CONSTRUCT])
    assert isinstance(relation, EvidenceRelation)
    assert relation.admissibility is Admissibility.DIRECT_FOR_MAPPED_PREDICATE
    assert relation.complete is False and not satisfies(relation)


def test_truncated_excerpt_is_recorded_incomplete(accepted) -> None:
    runs, ids, _ = accepted
    core = RetrievalCore(runs, RUN_ID, limits=RetrievalLimits(max_excerpt_bytes=4))
    relation = _resolve(core, ids["symbol"])
    assert isinstance(relation, EvidenceRelation)
    assert relation.admissibility is Admissibility.DIRECT and relation.complete is False
    assert not satisfies(relation)


def test_indirect_entity_resolves_but_never_satisfies(accepted) -> None:
    runs, ids, _ = accepted
    relation = _resolve(RetrievalCore(runs, RUN_ID), ids["priority"])
    assert isinstance(relation, EvidenceRelation)
    assert relation.admissibility is Admissibility.INDIRECT and relation.complete and not satisfies(relation)


@pytest.mark.parametrize("entity", ["absent", "garbage"])
def test_unresolvable_citation_is_an_evidence_gap(accepted, entity: str) -> None:
    runs, ids, _ = accepted
    gap = _resolve(RetrievalCore(runs, RUN_ID), ids.get(entity, "asr:source_span:not-a-hash"),
                   Predicate.SECURITY_IMPACT)
    assert isinstance(gap, Gap)
    assert gap.gap_class is GapClass.EVIDENCE_GAP and gap.subject_id == CLAIM
    assert gap.predicate is Predicate.SECURITY_IMPACT


def test_changed_source_after_indexing_is_an_evidence_gap(accepted) -> None:
    runs, ids, source = accepted
    source.write_text("void copy(char *in) { /* edited */ }\n", encoding="utf-8")
    gap = _resolve(RetrievalCore(runs, RUN_ID), ids["span"])
    assert isinstance(gap, Gap) and gap.gap_class is GapClass.EVIDENCE_GAP


def test_relation_kind_must_be_evidence_bearing(accepted) -> None:
    runs, ids, _ = accepted
    with pytest.raises(ValueError):
        _resolve(RetrievalCore(runs, RUN_ID), ids["span"], kind=RelationKind.DUPLICATES)


@pytest.mark.parametrize("kind", ["advisory", "dependency_package", "precomputed_fact"])
def test_reference_context_kinds_are_indirect_for_every_predicate_even_when_mapped(kind: str) -> None:
    """NVD/KEV/EPSS/OSV reference records never satisfy an obligation alone (design R3)."""
    from appsec_review.review.evidence import REFERENCE_KINDS
    assert EntityKind(kind) in REFERENCE_KINDS and EntityKind(kind) not in DIRECT_KINDS
    every = tuple(Predicate)
    assert {classify(kind, predicate, every) for predicate in Predicate} == {Admissibility.INDIRECT}
    # Target evidence of the resolved package (SBOM/lockfile/artifact inventory) stays direct.
    assert classify("package", Predicate.AFFECTED_CONSTRUCT) is Admissibility.DIRECT
    assert classify("archive_member", Predicate.AFFECTED_CONSTRUCT) is Admissibility.DIRECT
