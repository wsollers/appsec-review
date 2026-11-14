"""Pure contract behavior: no jobs, providers, storage readers, or target execution."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, is_dataclass, replace
from enum import StrEnum
import hashlib
import itertools
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from appsec_review.review.adjudication import DecidingRow
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.models import Admissibility, CellStatus, IntegrityError, Predicate, RelationKind, Role
from appsec_review.storage.atomic import canonical_json


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def link(value: str | None = None, reason: c.AbsenceReason = c.AbsenceReason.NOT_APPLICABLE) -> c.Link:
    return c.Link(value, None if value is not None else reason)


def check(value: bool | None) -> c.Check:
    return c.Check(value, c.AbsenceReason.LEGACY_UNRECORDED if value is None else None)


def origin() -> c.Origin:
    return c.Origin("run-1", "attempt-1", "target-1", digest("accepted"), digest("handoff"),
                    digest("ledger"), digest("projection"), digest("hunt"),
                    c.HashLink(digest("lead"), None), digest("configuration"),
                    c.HashLink(digest("guidance"), None), c.HashLink(digest("implementation"), None),
                    "decision-projection/1", digest("policy"))


def source(identity: str = "claim-1", *, uses: tuple[c.EvidenceUse, ...] = (c.EvidenceUse.READ,),
           path: str = "jobs/review/attempts/attempt-1/ledger.jsonl") -> c.SourceRef:
    return c.SourceRef("run-1", path, digest(path), link(identity), uses)


def subject(*, preclaim: bool = False) -> c.Subject:
    return c.Subject(link("lead-1"), link("proposal-1"),
                     link(None, c.AbsenceReason.PRE_CLAIM) if preclaim else link("claim-1"),
                     link() if preclaim else link("adjudication-1"),
                     link() if preclaim else link("finding-1"),
                     link("package-1"), link(None, c.AbsenceReason.LEGACY_UNRECORDED),
                     link("component-1"), link("build-1"), link("cell-1"), c.Round(1, None))


def context(*, preclaim: bool = False, relations: tuple[c.RelationRef, ...] = ()) -> c.Context:
    absent = c.OptionalSources((), c.AbsenceReason.NOT_COMMISSIONED)
    return c.Context(origin(), subject(preclaim=preclaim), (source("lead-1"),), relations,
                     (source("proposal-1"),), (), c.FutureReferences(absent, absent, absent),
                     c.Explanation(None, c.AbsenceReason.LEGACY_UNRECORDED, link()), ())


def relation(identity: str = "relation-1", *, role: Role = Role.INDEPENDENT_VERIFIER,
             kind: RelationKind = RelationKind.SUPPORTS, counted: bool = True) -> c.RelationRef:
    return c.RelationRef(identity, "claim-1", Predicate.AFFECTED_CONSTRUCT, kind, "cell-1", role,
                         Admissibility.DIRECT, counted, None if counted else c.NoncountedReason.NOT_EVALUATED,
                         source(identity))


def decision(*, preclaim: bool = False) -> c.DecisionRecord:
    return c.DecisionRecord(context(preclaim=preclaim), c.Stage.ADMISSION, "admitted",
                            link(), c.OptionalSource(None, c.AbsenceReason.NOT_APPLICABLE),
                            c.ReasonCode.ADMISSION_POLICY, c.BasisStatus.EXISTING_POLICY,
                            None, c.AbsenceReason.NOT_APPLICABLE, (), (), ())


def verification(*, kind: RelationKind = RelationKind.SUPPORTS) -> c.VerificationRecord:
    rel = relation(kind=kind)
    supports = (rel.relation_id,) if kind == RelationKind.SUPPORTS else ()
    contra = (rel.relation_id,) if kind == RelationKind.CONTRADICTS else ()
    pred = c.PredicateCoverage(Predicate.AFFECTED_CONSTRUCT, True, (source("read-1"),),
                               supports, contra, (), c.SupportCoverage.SUPPORTED if supports
                               else c.SupportCoverage.CONTRADICTED, None)
    blind = c.Blindness(check(True), check(True), check(True), check(True),
                        c.OptionalSource(source("request-check"), None), check(True))
    return c.VerificationRecord(
        context(relations=(rel,)), CellStatus.SUCCEEDED, c.OptionalSource(source("receipt"), None),
        blind, c.Diversity(check(False), check(False), link(None, c.AbsenceReason.UNKNOWN_MODEL_REVISION)),
        (pred,), c.EvidenceOverlap(("artifact-1",), (), check(True)), check(bool(supports)),
        check(bool(supports)))


def basis(dec: c.DecisionRecord | None = None, ver: c.VerificationRecord | None = None) -> c.DecisionBasisRecord:
    dec = dec or decision()
    return c.DecisionBasisRecord(context(), source("claim-1"), source("finding-1"),
                                 source("adjudication-1"), (c.RecordRef.of(dec),),
                                 c.OptionalRecord(c.RecordRef.of(ver), None) if ver else
                                 c.OptionalRecord(None, c.AbsenceReason.NOT_PRODUCED),
                                 (Predicate.AFFECTED_CONSTRUCT,), (), (source("judge-1"),),
                                 (source("score-1"),))


def coverage(shards: tuple[c.ShardRef, ...]) -> tuple[c.CoverageCount, ...]:
    result = []
    for pop in c.Population:
        emitted = sum(shard.record_count for shard in shards if shard.kind == pop)
        result.append(c.CoverageCount(pop, emitted, emitted, 0, 0, None))
    return tuple(result)


def bundle() -> tuple[c.AuditManifest, dict[str, tuple[c.Product, ...]]]:
    dec, ver = decision(), verification()
    rows = {"audit/decisions-1.jsonl": (dec,),
            "audit/verifications-1.jsonl": (ver,),
            "audit/bases-1.jsonl": (basis(dec, ver),)}
    shards = tuple(c.make_shard(path, records) for path, records in rows.items())
    return c.AuditManifest(origin(), shards, coverage(shards)), rows


def document_validator() -> Draft202012Validator:
    root = Path(__file__).resolve().parents[3]
    schema = json.loads((root / "docs/schemas" / c.SCHEMA_FILE).read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def assert_typed_tree(expected: object, actual: object) -> None:
    assert type(actual) is type(expected)
    if is_dataclass(expected):
        for field in fields(expected):
            assert_typed_tree(getattr(expected, field.name), getattr(actual, field.name))
    elif isinstance(expected, tuple):
        assert len(actual) == len(expected)
        for left, right in zip(expected, actual):
            assert_typed_tree(left, right)
    elif isinstance(expected, StrEnum):
        assert actual is expected
    else:
        assert actual == expected


@pytest.mark.parametrize("kind", ["decision", "verification", "basis", "manifest"])
def test_round_trip_has_one_validated_representation(kind: str) -> None:
    manifest, rows = bundle()
    record = {"decision": rows["audit/decisions-1.jsonl"][0],
              "verification": rows["audit/verifications-1.jsonl"][0],
              "basis": rows["audit/bases-1.jsonl"][0], "manifest": manifest}[kind]
    data = record.to_dict()
    document_validator().validate(data)
    restored = c.from_document(json.loads(c.canonical_bytes(record)), expected_origin=origin())
    assert restored == record
    assert_typed_tree(record, restored)
    assert c.canonical_bytes(restored) == c.canonical_bytes(record)
    assert record.sha256 == hashlib.sha256(c.canonical_bytes(record)).hexdigest()
    assert record.record_id.endswith(hashlib.sha256(canonical_json({
        key: value for key, value in data.items() if key != "record_id"})).hexdigest())
    with pytest.raises(FrozenInstanceError):
        setattr(record, "origin" if kind == "manifest" else "context", None)
    data.clear()
    assert record.to_dict()["schema"]
    c.validate_bundle(manifest, rows, expected_origin=origin(),
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


def test_normalization_is_permutation_invariant_but_role_scope_round_and_source_matter() -> None:
    refs = (source("a"), source("b"), source("c"))
    dec = replace(decision(), context=replace(context(), sources=refs, gap_ids=("gap-b", "gap-a")))
    for ordered in itertools.permutations(refs):
        shuffled = replace(dec, context=replace(dec.context, sources=ordered, gap_ids=("gap-a", "gap-b")))
        assert c.canonical_bytes(shuffled) == c.canonical_bytes(dec)
    changes = (
        replace(dec.context, subject=replace(dec.context.subject, build_scope_id=link("other-build"))),
        replace(dec.context, subject=replace(dec.context.subject, round=c.Round(2, None))),
        replace(dec.context, sources=(replace(source("a"), uses=(c.EvidenceUse.SUPPLIED,)),)),
        replace(dec.context, relations=(relation(role=Role.BLUE_TEAM_REFUTER, counted=False),)),
        replace(dec.context, relations=(relation(role=Role.RED_TEAM_ANALYST, counted=False),)),
    )
    assert len({replace(dec, context=ctx).record_id for ctx in changes}) == len(changes)
    assert dec.record_id not in {replace(dec, context=ctx).record_id for ctx in changes}
    assert source(uses=(c.EvidenceUse.CITED, c.EvidenceUse.READ)).uses == (
        c.EvidenceUse.CITED, c.EvidenceUse.READ)
    assert source(uses=(c.EvidenceUse.SUPPLIED,)).uses == (c.EvidenceUse.SUPPLIED,)


def test_manifest_normalizes_shard_order_but_never_jsonl_record_order() -> None:
    first, second = decision(), replace(decision(), outcome="not_admitted")
    forward = c.make_shard("audit/rows.jsonl", (first, second))
    backward = c.make_shard("audit/rows.jsonl", (second, first))
    assert forward.sha256 != backward.sha256
    assert forward.records == (c.RecordRef.of(first), c.RecordRef.of(second))
    manifest, rows = bundle()
    assert replace(manifest, shards=manifest.shards[::-1], coverage=manifest.coverage[::-1]) == manifest
    changed = dict(rows)
    changed["audit/decisions-1.jsonl"] = (second,)
    with pytest.raises(IntegrityError, match="shard bytes"):
        c.validate_bundle(manifest, changed, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


@pytest.mark.parametrize("path", [
    "../secret", "/absolute", "a/../secret", "a/./b", "./a", "a//b", "a/", ".",
    "..", "C:/file", "a\\b", "a/%2e%2e/b", "a/\x00b", "a/\nb", "//server/file",
])
def test_source_and_continuation_paths_reject_escapes_and_aliases(path: str) -> None:
    with pytest.raises(IntegrityError):
        source(path=path)
    with pytest.raises(IntegrityError):
        c.ContinuationRef(c.ReferenceField.RELATIONS, path, digest("x"), 1, 20)


@pytest.mark.parametrize("bad_hash", ["F" * 64, "sha256:" + "a" * 64, "a" * 63, "a" * 65, "g" * 64, True, None])
def test_hashes_are_exact_lowercase_sha256(bad_hash: object) -> None:
    with pytest.raises(IntegrityError):
        replace(source(), sha256=bad_hash)
    with pytest.raises(IntegrityError):
        replace(origin(), review_handoff_sha256=bad_hash)


@pytest.mark.parametrize(("path", "replacement"), [
    ((), {"model_confidence": 0.9}),
    (("context",), {"prompt": "not permitted"}),
    (("context", "subject"), {"synthetic_claim_id": "invented"}),
    (("context", "origin"), {"audit_manifest_sha256": "a" * 64}),
    (("context", "future"), {"warrant_result": "established"}),
    (("context", "explanation"), {"evidence": True}),
])
def test_unknown_fields_are_rejected_at_every_projection_boundary(path: tuple[str, ...], replacement: dict) -> None:
    doc = decision().to_dict()
    node = doc
    for part in path:
        node = node[part]
    node.update(replacement)
    assert list(document_validator().iter_errors(doc))
    with pytest.raises(IntegrityError):
        c.from_document(doc, expected_origin=origin())


@pytest.mark.parametrize(("field", "value"), [
    ("stage", "new_stage"), ("stage", True), ("outcome", "confirmed"), ("reason_code", "sure"),
    ("basis_status", "scoped_warrant"), ("visibility", "public"), ("authority", "evidence"),
    ("schema", "appsec-review/review-decision/0"), ("record_id", "decision-" + "0" * 64),
    ("required_predicates", [True]), ("deciding_actor_roles", ["new_role"]),
    ("missing_predicates", ["attacker_input_control"]),
])
def test_reader_rejects_malformed_or_wrong_semantics(field: str, value: object) -> None:
    doc = decision().to_dict()
    doc[field] = value
    with pytest.raises(IntegrityError):
        c.from_document(doc, expected_origin=origin())


@pytest.mark.parametrize("field", [
    "schema", "record_id", "context", "reason_code", "missing_predicates",
    "actor_role", "actor_role_absence_reason",
])
def test_legacy_missing_fields_are_not_defaults(field: str) -> None:
    doc = decision().to_dict()
    del doc[field]
    with pytest.raises(IntegrityError):
        c.from_document(doc, expected_origin=origin())


@pytest.mark.parametrize("value", [True, -1, 1.0, "1"])
def test_integer_guards_do_not_accept_boolean_or_coerce_types(value: object) -> None:
    with pytest.raises(IntegrityError):
        c.Round(value, None)
    with pytest.raises(IntegrityError):
        c.CoverageCount(c.Population.LEADS, value, 0, 0, 0, None)
    with pytest.raises(IntegrityError):
        c.ContinuationRef(c.ReferenceField.SOURCES, "audit/refs.jsonl", digest("refs"), value, 20)


@pytest.mark.parametrize("factory", [
    lambda: c.Link(None, None),
    lambda: c.Link("original", c.AbsenceReason.PRE_CLAIM),
    lambda: c.Check(1, None),
    lambda: c.Check(None, None),
    lambda: c.Round(None, None),
    lambda: c.HashLink("not-a-hash", None),
    lambda: c.OptionalSource(None, None),
    lambda: c.OptionalSources((), None),
    lambda: c.OptionalSources((source(),), c.AbsenceReason.NOT_PRODUCED),
    lambda: c.OptionalRecord(None, None),
])
def test_absence_requires_a_closed_reason_and_never_fabricates_success(factory) -> None:
    with pytest.raises(IntegrityError):
        factory()


def test_preclaim_and_no_claim_are_not_fabricated_claims_or_refutations() -> None:
    dec = decision(preclaim=True)
    assert dec.context.subject.claim_id == c.Link(None, c.AbsenceReason.PRE_CLAIM)
    assert c.from_document(dec.to_dict(), expected_origin=origin()) == dec
    no_claim = replace(dec, stage=c.Stage.RED_DISCOVERY, outcome="explicit_no_claim",
                       reason_code=c.ReasonCode.UNSTATED, basis_status=c.BasisStatus.UNSTATED)
    assert no_claim.context.explanation.text is None
    for bad in ({"outcome": "contradicted"}, {"basis_status": c.BasisStatus.EXISTING_POLICY}):
        with pytest.raises(IntegrityError):
            replace(no_claim, **bad)
    with pytest.raises(IntegrityError, match="pre-claim"):
        replace(dec.context.subject, finding_package_id=link("fabricated-finding"))
    with pytest.raises(IntegrityError, match="no original identity"):
        replace(subject(preclaim=True), lead_id=link(), proposal_ref=link(), package_id=link(), cell_id=link())
    with pytest.raises(IntegrityError, match="original claim"):
        replace(dec, stage=c.Stage.ADJUDICATION, outcome="insufficient_evidence")


@pytest.mark.parametrize(("stage", "outcome"), [
    (c.Stage.COLLECTION, "collected"), (c.Stage.SEVERITY_TRIAGE, "unknown"),
    (c.Stage.PACKAGE_ASSEMBLY, "omitted"), (c.Stage.RED_DISCOVERY, "blocked"),
    (c.Stage.PROPOSAL_NORMALIZATION, "merged"), (c.Stage.CLAIM_CAP, "capped"),
    (c.Stage.BLUE_REVIEW, "failed"), (c.Stage.INDEPENDENT_VERIFICATION, "not_launched"),
    (c.Stage.JUDGE_REVIEW, "unresolved"), (c.Stage.ADJUDICATION, "confirmed"),
    (c.Stage.SCORING, "unrated"), (c.Stage.PUBLICATION, "verification_backlog"),
])
def test_stage_specific_outcomes_do_not_create_new_claim_states(stage: c.Stage, outcome: str) -> None:
    dec = replace(decision(), stage=stage, outcome=outcome)
    assert c.from_document(dec.to_dict(), expected_origin=origin()) == dec
    with pytest.raises(IntegrityError):
        replace(dec, outcome="SUCCEEDED")


def test_deciding_roles_keep_joint_support_and_contradiction_provenance() -> None:
    relations = (relation("red-support", role=Role.RED_TEAM_ANALYST),
                 relation("blue-contra", role=Role.BLUE_TEAM_REFUTER, kind=RelationKind.CONTRADICTS),
                 relation("verify-contra", kind=RelationKind.CONTRADICTS))
    ctx = context(relations=relations)
    roles = (Role.RED_TEAM_ANALYST, Role.BLUE_TEAM_REFUTER, Role.INDEPENDENT_VERIFIER)
    dec = replace(decision(), context=ctx, stage=c.Stage.ADJUDICATION, outcome="insufficient_evidence",
                  deciding_row=DecidingRow.UNRESOLVED_CONTRADICTION, deciding_row_absence_reason=None,
                  deciding_actor_roles=roles, required_predicates=(Predicate.AFFECTED_CONSTRUCT,))
    assert set(dec.deciding_actor_roles) == set(roles)
    assert c.from_document(dec.to_dict(), expected_origin=origin()) == dec
    with pytest.raises(IntegrityError, match="recorded row"):
        replace(dec, deciding_actor_roles=(Role.BLUE_TEAM_REFUTER,))
    with pytest.raises(IntegrityError, match="judge"):
        replace(dec, deciding_actor_roles=(*roles, Role.ADJUDICATION_JUDGE))
    with pytest.raises(IntegrityError):
        replace(dec, deciding_row_absence_reason=c.AbsenceReason.LEGACY_UNRECORDED)


@pytest.mark.parametrize("change", [
    {"actor_role": Role.ADJUDICATION_JUDGE}, {"kind": RelationKind.QUALIFIES},
    {"admissibility": Admissibility.ANALYST_ASSESSED}, {"admissibility": Admissibility.INDIRECT},
    {"source": source("other-relation")},
    {"actor_role": Role.RED_TEAM_ANALYST, "kind": RelationKind.CONTRADICTS},
    {"actor_role": Role.HYPOTHESIS_HUNTER, "kind": RelationKind.CONTRADICTS},
])
def test_nondeciding_relations_cannot_gain_authority(change: dict) -> None:
    with pytest.raises(IntegrityError):
        replace(relation(), **change)
    judge = replace(relation(counted=False), actor_role=Role.ADJUDICATION_JUDGE,
                    noncounted_reason=c.NoncountedReason.JUDGE_NONDECIDING)
    assert not judge.counted


def test_blindness_diversity_and_evidence_support_are_independent_axes() -> None:
    refutation = verification(kind=RelationKind.CONTRADICTS)
    assert refutation.blindness.passed.value is True
    assert refutation.confirmation_eligible.value is False
    assert refutation.existing_r6_passed.value is False
    assert refutation.diversity.model_profile_distinct.value is False
    assert refutation.diversity.resolved_model_revision.absence_reason == c.AbsenceReason.UNKNOWN_MODEL_REVISION
    assert c.from_document(refutation.to_dict(), expected_origin=origin()) == refutation
    same_model_support = verification()
    assert same_model_support.confirmation_eligible.value is True
    assert same_model_support.evidence_overlap.distinct_upstream_producer_ids == ()
    with pytest.raises(IntegrityError, match="eligibility"):
        replace(refutation, confirmation_eligible=check(True))


@pytest.mark.parametrize("change", [
    {"actor_distinct": check(False)}, {"conversation_fresh": check(None)},
    {"prior_response_absent": check(False)}, {"shared_actor_cache_absent": check(False)},
    {"request_check": c.OptionalSource(None, c.AbsenceReason.UNAVAILABLE)},
])
def test_blindness_pass_requires_observed_structural_checks(change: dict) -> None:
    with pytest.raises(IntegrityError, match="observed checks"):
        replace(verification().blindness, **change)
    assert replace(verification().blindness, passed=check(None), **change).passed.value is None


def test_failed_verifier_and_unknown_coverage_remain_explicit() -> None:
    ver = verification()
    unknown = c.PredicateCoverage(Predicate.AFFECTED_CONSTRUCT, True, (), (), (), (),
                                  c.SupportCoverage.UNKNOWN, c.AbsenceReason.LEGACY_UNRECORDED)
    absent = c.OptionalSource(None, c.AbsenceReason.NOT_PRODUCED)
    failed = replace(ver, context=context(), status=CellStatus.TIMED_OUT, receipt=absent,
                     predicates=(unknown,), blindness=c.Blindness(
                         check(None), check(None), check(None), check(None), absent, check(None)),
                     evidence_overlap=c.EvidenceOverlap((), (), check(None)),
                     confirmation_eligible=check(None), existing_r6_passed=check(None))
    assert c.from_document(failed.to_dict(), expected_origin=origin()) == failed
    with pytest.raises(IntegrityError, match="eligibility"):
        replace(failed, confirmation_eligible=check(True))


@pytest.mark.parametrize("coverage_kind", list(c.SupportCoverage))
def test_predicate_coverage_matches_its_observed_reference_sets(coverage_kind: c.SupportCoverage) -> None:
    supports = ("support-1",) if coverage_kind in (c.SupportCoverage.SUPPORTED, c.SupportCoverage.CONFLICTED) else ()
    contra = ("contra-1",) if coverage_kind in (c.SupportCoverage.CONTRADICTED, c.SupportCoverage.CONFLICTED) else ()
    own = (source("read"),) if supports or contra else ()
    item = c.PredicateCoverage(Predicate.AFFECTED_CONSTRUCT, True, own, supports, contra, (),
                               coverage_kind, c.AbsenceReason.UNAVAILABLE
                               if coverage_kind == c.SupportCoverage.UNKNOWN else None)
    assert item.coverage == coverage_kind
    if coverage_kind != c.SupportCoverage.UNKNOWN:
        with pytest.raises(IntegrityError):
            replace(item, coverage=c.SupportCoverage.MISSING if supports or contra else c.SupportCoverage.SUPPORTED)


@pytest.mark.parametrize("change", [
    {"own_read_refs": (source(uses=(c.EvidenceUse.SUPPLIED,)),)},
    {"own_read_refs": ()},
    {"contradicting_relation_ids": ("relation-1",)},
    {"unknown_reason": c.AbsenceReason.UNAVAILABLE},
])
def test_verifier_coverage_does_not_infer_reads_or_duplicate_relation_kinds(change: dict) -> None:
    with pytest.raises(IntegrityError):
        replace(verification().predicates[0], **change)


@pytest.mark.parametrize("change", [
    {"producing_cell_id": "other-cell"},
    {"actor_role": Role.BLUE_TEAM_REFUTER},
    {"predicate": Predicate.ATTACKER_INPUT_CONTROL},
    {"kind": RelationKind.CONTRADICTS},
])
def test_verifier_cannot_claim_another_role_cell_or_predicates_relations(change: dict) -> None:
    ver = verification()
    with pytest.raises(IntegrityError, match="mismatched relation"):
        replace(ver, context=replace(ver.context, relations=(replace(relation(), **change),)))


def test_missing_expected_cell_or_claim_is_not_a_verification_record() -> None:
    ver = verification()
    with pytest.raises(IntegrityError, match="expected cell"):
        replace(ver, context=replace(ver.context, subject=replace(subject(), cell_id=link())))
    with pytest.raises(IntegrityError, match="expected cell"):
        replace(ver, context=context(preclaim=True))
    with pytest.raises(IntegrityError, match="mismatched relation"):
        replace(ver, context=context())
    with pytest.raises(IntegrityError, match="coverage predicates"):
        replace(ver, predicates=(ver.predicates[0], replace(ver.predicates[0], required=False)))
    with pytest.raises(IntegrityError, match="comparison"):
        c.EvidenceOverlap(("artifact-1",), (), check(None))


@pytest.mark.parametrize("change", [
    {"run_id": "other-run"}, {"review_attempt_id": "other-attempt"}, {"target_snapshot": "other-target"},
    {"accepted_manifest_sha256": digest("other-manifest")},
    {"review_handoff_sha256": digest("other-review")}, {"ledger_head_sha256": digest("other-ledger")},
    {"projection_sha256": digest("other-projection")}, {"configuration_sha256": digest("other-config")},
    {"projection_policy_sha256": digest("other-policy")}, {"projection_policy_version": "policy/2"},
    {"guidance_sha256": c.HashLink(digest("other-guidance"), None)},
    {"implementation_sha256": c.HashLink(digest("other-implementation"), None)},
])
def test_readers_require_exact_accepted_origin(change: dict) -> None:
    with pytest.raises(IntegrityError, match="accepted origin"):
        c.from_document(decision().to_dict(), expected_origin=replace(origin(), **change))
    manifest, rows = bundle()
    with pytest.raises(IntegrityError, match="accepted origin"):
        c.validate_bundle(manifest, rows, expected_origin=replace(origin(), **change),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


def test_source_reference_collisions_and_foreign_bindings_fail_closed() -> None:
    with pytest.raises(IntegrityError, match="foreign run"):
        replace(context(), sources=(replace(source(), run_id="foreign"),))
    with pytest.raises(IntegrityError, match="conflicting hash"):
        replace(context(), sources=(source("a"), replace(source("b"), sha256=digest("changed"))))
    with pytest.raises(IntegrityError, match="foreign claim"):
        context(relations=(replace(relation(), claim_id="foreign"),))
    with pytest.raises(IntegrityError, match="relation identities"):
        context(relations=(relation(), replace(relation(), actor_role=Role.BLUE_TEAM_REFUTER)))
    with pytest.raises(IntegrityError, match="proposal identities"):
        replace(context(), origin_proposals=(replace(source(), record_id=link()),))
    with pytest.raises(IntegrityError, match="source record references"):
        replace(context(), origin_proposals=(
            source("same"), source("same", uses=(c.EvidenceUse.AVAILABLE,))))
    with pytest.raises(IntegrityError, match="duplicate"):
        replace(context(), sources=(source(), source()))


def test_reference_and_explanation_bounds_are_real_and_continuations_are_hash_bound() -> None:
    refs = tuple(source(f"ref-{number}") for number in range(c.MAX_INLINE_REFERENCES))
    ctx = replace(context(), sources=refs, origin_proposals=())
    assert len(ctx.sources) == c.MAX_INLINE_REFERENCES
    with pytest.raises(IntegrityError, match="inline reference limit"):
        replace(ctx, origin_proposals=(source("overflow"),))
    with pytest.raises(IntegrityError):
        replace(ctx, sources=(*refs, source("overflow")))
    continuation = c.ContinuationRef(c.ReferenceField.RELATIONS, "audit/relations-1.jsonl",
                                    digest("continuation"), c.MAX_SHARD_RECORDS, c.MAX_SHARD_BYTES)
    continued = replace(ctx, continuations=(continuation,))
    assert continued.continuations[0].record_count == 5000
    continued_record = replace(decision(), context=continued)
    assert_typed_tree(continued_record, c.from_document(continued_record.to_dict(), expected_origin=origin()))
    for change in ({"record_count": 5001}, {"byte_count": 8388609}, {"record_count": 0}, {"byte_count": 0}):
        with pytest.raises(IntegrityError):
            replace(continuation, **change)
    with pytest.raises(IntegrityError, match="continuation paths"):
        replace(ctx, continuations=(continuation, replace(continuation, field=c.ReferenceField.SOURCES)))
    explanation = c.Explanation("x" * c.MAX_EXPLANATION, None, link())
    assert explanation.authority == "non_evidentiary"
    with pytest.raises(IntegrityError):
        replace(explanation, text="x" * (c.MAX_EXPLANATION + 1))
    with pytest.raises(IntegrityError):
        replace(explanation, authority="direct_evidence")


@pytest.mark.parametrize(("expected", "emitted", "omitted", "unavailable", "reason"), [
    (5, 3, 0, 0, None), (None, 0, 0, 0, c.CoverageReason.LEGACY_UNAVAILABLE),
    (1, 0, 0, None, c.CoverageReason.INPUT_UNAVAILABLE), (1, 0, 1, 0, None),
    (1, 0, 0, 1, None), (0, 0, 0, 0, c.CoverageReason.BOUNDED_OMISSION),
])
def test_coverage_counts_do_not_hide_missing_unknown_or_omitted_rows(
        expected, emitted, omitted, unavailable, reason) -> None:
    with pytest.raises(IntegrityError):
        c.CoverageCount(c.Population.LEADS, expected, emitted, omitted, unavailable, reason)


def test_lawful_unknown_and_partial_coverage_do_not_mean_zero() -> None:
    unknown = c.CoverageCount(c.Population.LEADS, None, 2, 0, None, c.CoverageReason.LEGACY_UNAVAILABLE)
    assert unknown.expected is None and unknown.unavailable is None
    partial = c.CoverageCount(c.Population.CELLS, 5, 2, 1, 2, c.CoverageReason.PARTIAL_INPUT)
    assert partial.expected == partial.emitted + partial.omitted + partial.unavailable
    manifest = c.AuditManifest(origin(), (), tuple(
        c.CoverageCount(pop, None, 0, 0, None, c.CoverageReason.LEGACY_UNAVAILABLE) for pop in c.Population))
    assert c.from_document(manifest.to_dict(), expected_origin=origin()) == manifest
    c.validate_bundle(manifest, {}, expected_origin=origin(),
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


def test_basis_requires_exact_original_accepted_claim_finding_and_adjudication() -> None:
    base = basis()
    for name in ("claim", "finding", "adjudication"):
        with pytest.raises(IntegrityError, match="exact accepted"):
            replace(base, **{name: source("foreign")})
    with pytest.raises(IntegrityError, match="exact accepted"):
        replace(base, context=context(preclaim=True))
    with pytest.raises(IntegrityError, match="foreign run"):
        replace(base, finding=replace(base.finding, run_id="foreign"))
    with pytest.raises(IntegrityError, match="required predicates"):
        replace(base, missing_predicates=(Predicate.SECURITY_IMPACT,))
    with pytest.raises(IntegrityError):
        replace(base, decisions=(c.RecordRef.of(verification()),))
    with pytest.raises(IntegrityError):
        replace(base, verification=c.OptionalRecord(c.RecordRef.of(decision()), None))
    with pytest.raises(IntegrityError, match="basis record identities"):
        replace(base, decisions=(*base.decisions, replace(base.decisions[0], sha256=digest("changed"))))


def test_manifest_enforces_count_kind_path_and_identity_membership() -> None:
    manifest, rows = bundle()
    shard = manifest.shards[0]
    with pytest.raises(IntegrityError, match="count or record kind"):
        replace(shard, record_count=2)
    with pytest.raises(IntegrityError, match="count or record kind"):
        replace(shard, kind=c.ProductKind.VERIFICATION if shard.kind != c.ProductKind.VERIFICATION else c.ProductKind.BASIS)
    with pytest.raises(IntegrityError, match="shard record identities"):
        replace(shard, record_count=2, records=(*shard.records, replace(shard.records[0], sha256=digest("changed"))))
    with pytest.raises(IntegrityError, match="shard paths"):
        replace(manifest, shards=(*manifest.shards, replace(shard, sha256=digest("different"))))
    with pytest.raises(IntegrityError, match="manifest record identities"):
        replace(manifest, shards=(*manifest.shards, replace(shard, path="audit/duplicate.jsonl")))
    with pytest.raises(IntegrityError, match="emitted coverage"):
        replace(manifest, coverage=tuple(replace(item, expected=8, emitted=8)
                                        if item.population == shard.kind else item for item in manifest.coverage))
    with pytest.raises(IntegrityError, match="coverage populations"):
        replace(manifest, coverage=(*manifest.coverage[:-1],
                                    replace(manifest.coverage[0], expected=None, unavailable=None,
                                            reason=c.CoverageReason.LEGACY_UNAVAILABLE)))
    with pytest.raises(IntegrityError):
        replace(manifest, coverage=manifest.coverage[:-1])
    with pytest.raises(IntegrityError, match="supplied shards"):
        c.validate_bundle(manifest, {}, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


def test_bundle_rejects_foreign_records_and_missing_or_foreign_basis_links() -> None:
    manifest, rows = bundle()
    bad_dec = replace(decision(), context=replace(context(), origin=replace(origin(), target_snapshot="foreign")))
    changed = {**rows, "audit/decisions-1.jsonl": (bad_dec,)}
    shards = tuple(c.make_shard(path, records) for path, records in changed.items())
    changed_manifest = c.AuditManifest(origin(), shards, coverage(shards))
    with pytest.raises(IntegrityError, match="foreign audit origin"):
        c.validate_bundle(changed_manifest, changed, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", changed_manifest))
    for changed_basis in (
        replace(basis(), decisions=(replace(c.RecordRef.of(decision()), sha256=digest("changed")),)),
        basis(replace(decision(), outcome="not_admitted")),
    ):
        changed = {**rows, "audit/bases-1.jsonl": (changed_basis,)}
        shards = tuple(c.make_shard(path, records) for path, records in changed.items())
        changed_manifest = c.AuditManifest(origin(), shards, coverage(shards))
        with pytest.raises(IntegrityError, match="absent or changed"):
            c.validate_bundle(changed_manifest, changed, expected_origin=origin(),
                              manifest_reference=c.ManifestRef.of("audit/manifest.json", changed_manifest))
    foreign = replace(decision(), context=replace(context(), subject=replace(subject(), claim_id=link("foreign"))))
    changed = {"audit/decisions-1.jsonl": (foreign,), "audit/bases-1.jsonl": (basis(foreign),)}
    shards = tuple(c.make_shard(path, records) for path, records in changed.items())
    changed_manifest = c.AuditManifest(origin(), shards, coverage(shards))
    with pytest.raises(IntegrityError, match="foreign claim"):
        c.validate_bundle(changed_manifest, changed, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", changed_manifest))


def test_future_references_are_optional_non_authoritative_and_allowlisted() -> None:
    refs = c.OptionalSources((source("future-original"),), None)
    ctx = replace(context(), future=c.FutureReferences(refs, refs, refs))
    dec = replace(decision(), context=ctx)
    assert c.from_document(dec.to_dict(), expected_origin=origin()) == dec
    assert dec.context.future.authority == "non_authoritative_reference"
    with pytest.raises(IntegrityError):
        replace(ctx.future, authority="semantic_resolution")
    doc = dec.to_dict()
    doc["context"]["future"]["request_resolutions"]["satisfied"] = True
    with pytest.raises(IntegrityError):
        c.from_document(doc, expected_origin=origin())


def test_public_api_rejects_mutable_or_non_json_inputs_without_passthrough() -> None:
    for value in (None, [], "{}", {1: "not-string-key"}):
        with pytest.raises(IntegrityError):
            c.from_document(value, expected_origin=origin())
    with pytest.raises(IntegrityError, match="immutable tuple"):
        replace(context(), sources=[source()])
    with pytest.raises(IntegrityError, match="typed immutable"):
        replace(origin(), guidance_sha256={"value": digest("x"), "absence_reason": None})
    with pytest.raises(IntegrityError, match="empty shards"):
        c.make_shard("audit/empty.jsonl", ())
    with pytest.raises(IntegrityError, match="not a decision-audit product"):
        c.RecordRef.of(origin())
    with pytest.raises(IntegrityError, match="canonical bytes require"):
        c.canonical_bytes(origin())
    with pytest.raises(IntegrityError, match="JSON array"):
        c._array({"not": "an array"})


def test_manifest_reference_binds_accepted_origin_identity_and_bytes_without_a_cycle() -> None:
    manifest, _ = bundle()
    reference = c.ManifestRef.of("audit/manifest.json", manifest)
    assert c.ManifestRef.from_document(reference.to_dict(), expected_origin=origin()) == reference
    reference.verify(manifest, expected_origin=origin())
    assert reference.sha256 == manifest.sha256
    assert reference.record_id == manifest.record_id
    assert "manifest_ref" not in manifest.to_dict()
    assert manifest.origin.review_handoff_sha256 == digest("handoff")
    for changed in (replace(reference, sha256=digest("tampered")),
                    replace(reference, record_id="audit-manifest-" + "0" * 64)):
        with pytest.raises(IntegrityError, match="changed identity or hash"):
            changed.verify(manifest, expected_origin=origin())
    foreign_origin = replace(origin(), review_attempt_id="foreign")
    with pytest.raises(IntegrityError, match="accepted origin"):
        c.ManifestRef.from_document(reference.to_dict(), expected_origin=foreign_origin)
    with pytest.raises(IntegrityError, match="accepted origin"):
        reference.verify(manifest, expected_origin=foreign_origin)
    with pytest.raises(IntegrityError, match="accepted origin"):
        reference.verify(replace(manifest, origin=foreign_origin), expected_origin=origin())
    invalid = reference.to_dict()
    invalid["raw_worker_output"] = {}
    with pytest.raises(IntegrityError):
        c.ManifestRef.from_document(invalid, expected_origin=origin())


def test_original_cell_outcome_and_receipt_are_preserved_without_reinterpreting_no_claim() -> None:
    record = replace(decision(preclaim=True), stage=c.Stage.RED_DISCOVERY, outcome="explicit_no_claim",
                     original_outcome=link("no_claim"), basis_status=c.BasisStatus.UNSTATED,
                     reason_code=c.ReasonCode.UNSTATED,
                     cell_receipt=c.OptionalSource(source("cell-1"), None))
    restored = c.from_document(record.to_dict(), expected_origin=origin())
    assert restored.original_outcome.value == "no_claim"
    assert restored.cell_receipt.value == source("cell-1")
    assert restored.context.subject.claim_id.value is None
    with pytest.raises(IntegrityError, match="original cell"):
        replace(record, context=replace(record.context, subject=replace(record.context.subject, cell_id=link())))
    with pytest.raises(IntegrityError, match="foreign run"):
        replace(record, cell_receipt=c.OptionalSource(replace(source("cell-1"), run_id="foreign"), None))


def test_duplicate_source_records_cannot_hide_behind_different_usage_labels() -> None:
    first = source()
    second = replace(first, uses=(c.EvidenceUse.SUPPLIED,))
    for constructor in (
        lambda: replace(context(), sources=(first, second)),
        lambda: c.OptionalSources((first, second), None),
        lambda: replace(verification().predicates[0], own_read_refs=(
            first, replace(first, uses=(c.EvidenceUse.READ, c.EvidenceUse.CITED)))),
        lambda: replace(basis(), score_refs=(first, second)),
    ):
        with pytest.raises(IntegrityError, match="source record references"):
            constructor()


def test_cross_section_source_and_continuation_hash_conflicts_are_rejected() -> None:
    ctx = context(relations=(relation(),))
    wrong = replace(source("read-1"), sha256=digest("tampered"))
    with pytest.raises(IntegrityError, match="conflicting hash"):
        replace(verification(), context=ctx, receipt=c.OptionalSource(wrong, None))
    with pytest.raises(IntegrityError, match="conflicting hash"):
        replace(basis(), context=ctx, score_refs=(wrong,))
    continuation = c.ContinuationRef(c.ReferenceField.SOURCES, source().path, digest("changed"), 1, 200)
    with pytest.raises(IntegrityError, match="conflicting hash"):
        replace(context(), continuations=(continuation,))


def test_indirect_own_support_cannot_be_confirmation_eligible() -> None:
    ver = verification()
    nondeciding = replace(relation(counted=False), admissibility=Admissibility.ANALYST_ASSESSED,
                          noncounted_reason=c.NoncountedReason.ANALYST_ASSESSED)
    with pytest.raises(IntegrityError, match="eligibility"):
        replace(ver, context=context(relations=(nondeciding,)))
    recorded = replace(ver, context=context(relations=(nondeciding,)), confirmation_eligible=check(False))
    assert recorded.context.relations[0].admissibility == Admissibility.ANALYST_ASSESSED
    assert_typed_tree(recorded, c.from_document(recorded.to_dict(), expected_origin=origin()))
    with pytest.raises(IntegrityError):
        replace(ver.diversity, resolved_model_revision=link(None, c.AbsenceReason.PRE_CLAIM))


def test_known_revision_and_explicit_missing_source_identities_round_trip() -> None:
    ver = verification()
    absent_origin = replace(origin(), guidance_sha256=c.HashLink(None, c.AbsenceReason.LEGACY_UNRECORDED),
                            implementation_sha256=c.HashLink(None, c.AbsenceReason.UNAVAILABLE))
    known = replace(ver, context=replace(ver.context, origin=absent_origin,
                    subject=replace(ver.context.subject, round=c.Round(None, c.AbsenceReason.LEGACY_UNRECORDED))),
                    diversity=replace(ver.diversity, resolved_model_revision=link("model-revision-123")))
    restored = c.from_document(known.to_dict(), expected_origin=absent_origin)
    assert_typed_tree(known, restored)
    assert restored.diversity.resolved_model_revision.value == "model-revision-123"


@pytest.mark.parametrize("field", list(c.ReferenceField))
def test_continuation_rows_are_closed_typed_canonical_and_hash_bound(field: c.ReferenceField) -> None:
    records = (relation("b"), relation("a")) if field == c.ReferenceField.RELATIONS else (source("b"), source("a"))
    claim = link("claim-1")
    data = c.reference_bytes(field, records, origin=origin(), claim_id=claim)
    assert data == c.reference_bytes(field, records[::-1], origin=origin(), claim_id=claim)
    ref = c.make_continuation(field, "audit/refs-1.jsonl", records, origin=origin(), claim_id=claim)
    assert ref.sha256 == hashlib.sha256(data).hexdigest()
    assert ref.byte_count == len(data) and ref.record_count == len(records)
    decoded = tuple(c.reference_from_document(json.loads(line), field=field, origin=origin(), claim_id=claim)
                    for line in data.splitlines())
    assert ref == c.make_continuation(field, ref.path, decoded, origin=origin(), claim_id=claim)
    assert c.reference_bytes(field, decoded, origin=origin(), claim_id=claim) == data
    with pytest.raises(IntegrityError, match="continuation reference identities"):
        c.reference_bytes(field, (*records, records[0]), origin=origin(), claim_id=claim)
    with pytest.raises(IntegrityError):
        c.reference_from_document({**records[0].to_dict(), "raw_prompt": "forbidden"},
                                  field=field, origin=origin(), claim_id=claim)


@pytest.mark.parametrize(("field", "records", "claim", "message"), [
    ("unknown", (source(),), link(), "closed ReferenceField"),
    (c.ReferenceField.SOURCES, (), link(), "1..5000"),
    (c.ReferenceField.SOURCES, (relation(),), link(), "wrong record kind"),
    (c.ReferenceField.RELATIONS, (source(),), link(), "wrong kind or foreign"),
    (c.ReferenceField.RELATIONS, (relation(),), link("foreign"), "wrong kind or foreign"),
    (c.ReferenceField.ORIGIN_PROPOSALS, (replace(source(), record_id=link()),), link(), "original identities"),
])
def test_invalid_continuation_rows_cannot_bypass_inline_validation(field, records, claim, message) -> None:
    with pytest.raises(IntegrityError, match=message):
        c.reference_bytes(field, records, origin=origin(), claim_id=claim)


def test_reference_continuation_byte_limit_is_checked_without_silent_truncation() -> None:
    records = tuple(c.RelationRef(
        "r" * 190 + str(index), "claim-1", Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
        "c" * 200, Role.INDEPENDENT_VERIFIER, Admissibility.DIRECT, True, None,
        replace(source("r" * 190 + str(index)), run_id="u" * 200, path="a" * 1024))
        for index in range(5000))
    with pytest.raises(IntegrityError, match="byte limit"):
        c.reference_bytes(c.ReferenceField.RELATIONS, records,
                          origin=replace(origin(), run_id="u" * 200), claim_id=link("claim-1"))


def single_bundle(record: c.Product) -> tuple[c.AuditManifest, dict[str, tuple[c.Product, ...]]]:
    path = "audit/decision.jsonl"
    shard = c.make_shard(path, (record,))
    return c.AuditManifest(origin(), (shard,), coverage((shard,))), {path: (record,)}


def test_bundle_requires_exact_continuation_payloads_and_cross_shard_reference_uniqueness() -> None:
    rel = relation("continued", counted=False)
    rows = (rel,)
    ref = c.make_continuation(c.ReferenceField.RELATIONS, "audit/relations.jsonl", rows,
                              origin=origin(), claim_id=link("claim-1"))
    record = replace(decision(), context=replace(context(), continuations=(ref,)))
    manifest, shards = single_bundle(record)
    c.validate_bundle(manifest, shards, expected_origin=origin(), continuations={ref.path: rows},
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))
    with pytest.raises(IntegrityError, match="supplied reference continuations"):
        c.validate_bundle(manifest, shards, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))
    with pytest.raises(IntegrityError, match="bytes, count or kind"):
        c.validate_bundle(manifest, shards, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest),
                          continuations={ref.path: (replace(rel, actor_role=Role.BLUE_TEAM_REFUTER),)})
    repeated = replace(record, context=replace(record.context, relations=rows))
    duplicate_manifest, duplicate_shards = single_bundle(repeated)
    with pytest.raises(IntegrityError, match="continued relation identities"):
        c.validate_bundle(duplicate_manifest, duplicate_shards, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", duplicate_manifest),
                          continuations={ref.path: rows})
    same_path = replace(ref, path="audit/decision.jsonl")
    overlapping = replace(record, context=replace(context(), continuations=(same_path,)))
    overlapping_manifest, overlapping_shards = single_bundle(overlapping)
    with pytest.raises(IntegrityError, match="distinct paths"):
        c.validate_bundle(overlapping_manifest, overlapping_shards, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", overlapping_manifest),
                          continuations={same_path.path: rows})


def test_continued_deciding_roles_and_proposals_keep_their_original_identity() -> None:
    rel = relation("deciding", role=Role.BLUE_TEAM_REFUTER)
    ref = c.make_continuation(c.ReferenceField.RELATIONS, "audit/relations.jsonl", (rel,),
                              origin=origin(), claim_id=link("claim-1"))
    record = replace(decision(), context=replace(context(), continuations=(ref,)),
                     stage=c.Stage.ADJUDICATION, outcome="supported",
                     deciding_row=DecidingRow.SUPPORTED, deciding_row_absence_reason=None,
                     required_predicates=(Predicate.AFFECTED_CONSTRUCT,))
    manifest, shards = single_bundle(record)
    with pytest.raises(IntegrityError, match="recorded row"):
        c.validate_bundle(manifest, shards, expected_origin=origin(), continuations={ref.path: (rel,)},
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))
    record = replace(record, deciding_actor_roles=(Role.BLUE_TEAM_REFUTER,))
    manifest, shards = single_bundle(record)
    c.validate_bundle(manifest, shards, expected_origin=origin(), continuations={ref.path: (rel,)},
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))
    proposal = source("proposal-1")
    proposal_ref = c.make_continuation(c.ReferenceField.ORIGIN_PROPOSALS, "audit/proposals.jsonl", (proposal,),
                                       origin=origin(), claim_id=link("claim-1"))
    record = replace(decision(), context=replace(context(), continuations=(proposal_ref,)))
    manifest, shards = single_bundle(record)
    with pytest.raises(IntegrityError, match="source record references"):
        c.validate_bundle(manifest, shards, expected_origin=origin(),
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest),
                          continuations={proposal_ref.path: (proposal,)})


@pytest.mark.parametrize("continued", [False, True], ids=["inline", "continued"])
@pytest.mark.parametrize("same_bytes", [False, True], ids=["distinct-bytes", "same-bytes"])
def test_original_proposal_ids_are_local_to_their_receipts(continued: bool, same_bytes: bool) -> None:
    first = source("p1", path="audit/cell-a.json")
    second = source("p1", path="audit/cell-b.json")
    if same_bytes:
        second = replace(second, sha256=first.sha256)
    ctx = replace(context(), subject=replace(subject(), cell_id=link(), proposal_ref=link()),
                  origin_proposals=(first,) if continued else (first, second))
    continuation_rows = {}
    if continued:
        ref = c.make_continuation(c.ReferenceField.ORIGIN_PROPOSALS, "audit/proposals.jsonl",
                                  (second,), origin=origin(), claim_id=link("claim-1"))
        ctx = replace(ctx, continuations=(ref,))
        continuation_rows[ref.path] = (second,)
    record = replace(decision(), context=ctx, stage=c.Stage.PROPOSAL_NORMALIZATION, outcome="merged")
    assert_typed_tree(record, c.from_document(record.to_dict(), expected_origin=origin()))
    manifest, shards = single_bundle(record)
    c.validate_bundle(manifest, shards, expected_origin=origin(), continuations=continuation_rows,
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))
    originals = [*record.context.origin_proposals,
                 *(item for rows in continuation_rows.values() for item in rows)]
    assert {(item.path, item.record_id.value) for item in originals} == {
        ("audit/cell-a.json", "p1"), ("audit/cell-b.json", "p1")}


def test_future_continuations_cannot_contradict_an_explicit_absence() -> None:
    row = source("warrant-original")
    ref = c.make_continuation(c.ReferenceField.WARRANTS, "audit/warrants.jsonl", (row,),
                              origin=origin(), claim_id=link("claim-1"))
    with pytest.raises(IntegrityError, match="absent future references"):
        replace(context(), continuations=(ref,))
    future = replace(context().future, warrants=c.OptionalSources((source("inline-warrant"),), None))
    record = replace(decision(), context=replace(context(), future=future, continuations=(ref,)))
    manifest, shards = single_bundle(record)
    c.validate_bundle(manifest, shards, expected_origin=origin(), continuations={ref.path: (row,)},
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


@pytest.mark.parametrize(("row", "outcome"), [
    (DecidingRow.DUPLICATE, "duplicate"), (DecidingRow.OUT_OF_SCOPE, "out_of_scope"),
    (DecidingRow.UNRESOLVED_CONTRADICTION, "insufficient_evidence"),
    (DecidingRow.DIRECT_CONTRADICTION, "contradicted"),
    (DecidingRow.DIRECT_CONTRADICTION, "not_reachable"),
    (DecidingRow.DIRECT_CONTRADICTION, "not_exploitable_in_observed_configuration"),
    (DecidingRow.CONFIRMED, "confirmed"), (DecidingRow.SUPPORTED, "supported"),
    (DecidingRow.INSUFFICIENT_EVIDENCE, "insufficient_evidence"),
])
def test_observed_adjudication_row_cannot_be_relabelled_as_another_outcome(row, outcome) -> None:
    record = replace(decision(), stage=c.Stage.ADJUDICATION, outcome=outcome,
                     deciding_row=row, deciding_row_absence_reason=None)
    assert_typed_tree(record, c.from_document(record.to_dict(), expected_origin=origin()))
    with pytest.raises(IntegrityError):
        replace(record, outcome="out_of_scope" if outcome == "confirmed" else "confirmed")


def untrusted_continuation(field: c.ReferenceField, path: str,
                           rows: tuple[c.SourceRef | c.RelationRef, ...]) -> c.ContinuationRef:
    """Hash actual supplied rows, including deliberately malformed semantic bindings."""
    data = b"".join(sorted(canonical_json(row.to_dict()) for row in rows))
    return c.ContinuationRef(field, path, hashlib.sha256(data).hexdigest(), len(rows), len(data))


def continued_verifier(rows: tuple[c.SourceRef | c.RelationRef, ...],
                       original: c.VerificationRecord | None = None,
                       inline: tuple[c.RelationRef, ...] = ()) -> c.VerificationRecord:
    original = original or verification()
    ref = untrusted_continuation(c.ReferenceField.RELATIONS, "audit/verifier-relations.jsonl", rows)
    return replace(original, context=replace(original.context, relations=inline, continuations=(ref,)))


def validate_single(record: c.Product, continued: dict[str, tuple[c.SourceRef | c.RelationRef, ...]]) -> None:
    manifest, shards = single_bundle(record)
    c.validate_bundle(manifest, shards, expected_origin=origin(), continuations=continued,
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


@pytest.mark.parametrize("kind", [RelationKind.SUPPORTS, RelationKind.CONTRADICTS, RelationKind.QUALIFIES])
def test_verifier_relations_can_resolve_from_declared_continuations(kind: RelationKind) -> None:
    if kind == RelationKind.QUALIFIES:
        original = verification()
        rel = relation("qualifier", kind=kind, counted=False)
        original = replace(original, context=replace(original.context, relations=(*original.context.relations, rel)),
                           predicates=(replace(original.predicates[0], qualifying_relation_ids=(rel.relation_id,)),))
        inline = (relation(),)
    else:
        original = verification(kind=kind)
        rel = relation(kind=kind)
        inline = ()
    record = continued_verifier((rel,), original, inline)
    optional = c.PredicateCoverage(Predicate.SECURITY_IMPACT, False, (), (), (), (), c.SupportCoverage.MISSING, None)
    record = replace(record, predicates=(*record.predicates, optional))
    restored = c.from_document(record.to_dict(), expected_origin=origin())
    assert_typed_tree(record, restored)
    validate_single(restored, {record.context.continuations[0].path: (rel,)})
    assert restored.confirmation_eligible == original.confirmation_eligible


@pytest.mark.parametrize(("rows", "message"), [
    ((relation("absent-original"),), "foreign or mismatched relation"),
    ((replace(relation(), claim_id="foreign"),), "foreign claim"),
    ((source("relation-1"),), "wrong kind"),
    ((replace(relation(), actor_role=Role.BLUE_TEAM_REFUTER),), "foreign or mismatched relation"),
    ((replace(relation(), producing_cell_id="foreign-cell"),), "foreign or mismatched relation"),
    ((replace(relation(), predicate=Predicate.ATTACKER_INPUT_CONTROL),), "foreign or mismatched relation"),
    ((relation(kind=RelationKind.CONTRADICTS),), "foreign or mismatched relation"),
    ((relation(counted=False),), "confirmation eligibility"),
    ((replace(relation(), source=replace(source("relation-1"), run_id="foreign")),), "foreign run"),
])
def test_malformed_continued_verifier_evidence_cannot_gain_eligibility(rows, message) -> None:
    record = continued_verifier(rows)
    with pytest.raises(IntegrityError, match=message):
        validate_single(record, {record.context.continuations[0].path: rows})


def test_verifier_does_not_defer_missing_ids_without_relevant_continuations() -> None:
    original = verification()
    with pytest.raises(IntegrityError, match="foreign or mismatched relation"):
        replace(original, context=replace(original.context, relations=()))
    source_only = untrusted_continuation(c.ReferenceField.SOURCES, "audit/source-only.jsonl", (source("read"),))
    with pytest.raises(IntegrityError, match="foreign or mismatched relation"):
        replace(original, context=replace(original.context, relations=(), continuations=(source_only,)))
    record = continued_verifier((relation(),))
    with pytest.raises(IntegrityError, match="supplied reference continuations"):
        validate_single(record, {})


def test_known_invalid_verifier_facts_are_not_deferred_by_a_continuation() -> None:
    record = continued_verifier((relation(),))
    for changed in (
        {"status": CellStatus.TIMED_OUT},
        {"blindness": replace(record.blindness, passed=check(False))},
        {"predicates": (replace(record.predicates[0], required=False),)},
    ):
        with pytest.raises(IntegrityError, match="confirmation eligibility"):
            replace(record, **changed)
    with pytest.raises(IntegrityError, match="foreign or mismatched relation"):
        replace(record, context=replace(record.context, relations=(replace(relation(), actor_role=Role.BLUE_TEAM_REFUTER),)))
    with pytest.raises(IntegrityError, match="confirmation eligibility"):
        replace(record, context=replace(record.context, relations=(relation(counted=False),)))
    nondeciding = continued_verifier((relation(counted=False),),
                                    original=replace(verification(), confirmation_eligible=check(False)))
    validate_single(nondeciding, {nondeciding.context.continuations[0].path: (relation(counted=False),)})


def test_full_continuation_population_cannot_hide_a_deciding_own_contradiction() -> None:
    rows = (relation(), relation("unlisted-contra", kind=RelationKind.CONTRADICTS))
    record = continued_verifier(rows)
    with pytest.raises(IntegrityError, match="confirmation eligibility"):
        validate_single(record, {record.context.continuations[0].path: rows})
    with pytest.raises(IntegrityError, match="confirmation eligibility"):
        replace(verification(), context=context(relations=rows))


def products_bundle(records: tuple[c.Product, ...]) -> tuple[c.AuditManifest, dict[str, tuple[c.Product, ...]]]:
    grouped = {kind: tuple(item for item in records if c.RecordRef.of(item).kind == kind)
               for kind in c.ProductKind}
    shards = {f"audit/{kind.value}.jsonl": rows for kind, rows in grouped.items() if rows}
    refs = tuple(c.make_shard(path, rows) for path, rows in shards.items())
    return c.AuditManifest(origin(), refs, coverage(refs)), shards


REFERENCE_LOCATIONS = (
    "decision.cell_receipt", "verification.receipt", "verification.request_check", "verification.own_reads",
    "basis.claim", "basis.finding", "basis.adjudication", "basis.judge_verdicts", "basis.score_refs",
    "future.warrants", "future.request_resolutions", "future.hunt_receipts",
)


def product_with_reference(location: str, original_decision: c.DecisionRecord, path: str, sha256: str) -> c.Product:
    def at_path(ref: c.SourceRef) -> c.SourceRef:
        return replace(ref, path=path, sha256=sha256)

    if location == "decision.cell_receipt":
        return replace(decision(), cell_receipt=c.OptionalSource(at_path(source("cell-1")), None))
    if location.startswith("verification."):
        record = verification()
        if location == "verification.receipt":
            return replace(record, receipt=c.OptionalSource(at_path(record.receipt.value), None))
        if location == "verification.request_check":
            return replace(record, blindness=replace(record.blindness, request_check=c.OptionalSource(
                at_path(record.blindness.request_check.value), None)))
        return replace(record, predicates=(replace(record.predicates[0], own_read_refs=(at_path(source("read-1")),)),))
    if location.startswith("basis."):
        record = basis(original_decision)
        field = location.removeprefix("basis.")
        if field in ("judge_verdicts", "score_refs"):
            return replace(record, **{field: (at_path(getattr(record, field)[0]),)})
        return replace(record, **{field: at_path(getattr(record, field))})
    field = location.removeprefix("future.")
    return replace(decision(), context=replace(context(), future=replace(
        context().future, **{field: c.OptionalSources((at_path(source("future-original")),), None)})))


@pytest.mark.parametrize("location", REFERENCE_LOCATIONS)
@pytest.mark.parametrize("same_hash", [False, True], ids=["collision", "lawful-reuse"])
def test_bundle_checks_every_product_specific_and_nested_source_reference(location: str, same_hash: bool) -> None:
    shared = source("anchor", path="inputs/shared.json")
    first = replace(decision(), context=replace(context(), sources=(shared,)))
    second = product_with_reference(location, first, shared.path, shared.sha256 if same_hash else digest("other"))
    manifest, shards = products_bundle((first, second))
    ref = c.ManifestRef.of("audit/manifest.json", manifest)
    if same_hash:
        c.validate_bundle(manifest, shards, expected_origin=origin(), manifest_reference=ref)
    else:
        with pytest.raises(IntegrityError, match="conflicting hash bindings"):
            c.validate_bundle(manifest, shards, expected_origin=origin(), manifest_reference=ref)


@pytest.mark.parametrize("relation_rows", [False, True], ids=["source-rows", "relation-rows"])
@pytest.mark.parametrize("same_hash", [False, True], ids=["collision", "lawful-reuse"])
def test_continuation_payload_sources_participate_in_bundle_wide_consistency(
        relation_rows: bool, same_hash: bool) -> None:
    shared = source("continued", path="inputs/shared.json")
    rows = (replace(relation("continued", counted=False), source=shared),) if relation_rows else (shared,)
    field = c.ReferenceField.RELATIONS if relation_rows else c.ReferenceField.SOURCES
    continuation = c.make_continuation(field, "audit/refs.jsonl", rows, origin=origin(), claim_id=link("claim-1"))
    first = replace(decision(), context=replace(context(), continuations=(continuation,)))
    second = product_with_reference("verification.receipt", first, shared.path,
                                    shared.sha256 if same_hash else digest("other"))
    manifest, shards = products_bundle((first, second))
    args = {"expected_origin": origin(), "manifest_reference": c.ManifestRef.of("audit/manifest.json", manifest),
            "continuations": {continuation.path: rows}}
    if same_hash:
        c.validate_bundle(manifest, shards, **args)
    else:
        with pytest.raises(IntegrityError, match="conflicting hash bindings"):
            c.validate_bundle(manifest, shards, **args)


@pytest.mark.parametrize("same_hash", [False, True], ids=["collision", "lawful-reuse"])
def test_payloads_in_different_continuations_share_one_path_hash_registry(same_hash: bool) -> None:
    first_row = source("original-1", path="inputs/shared.json")
    second_row = replace(first_row, record_id=link("original-2"),
                         sha256=first_row.sha256 if same_hash else digest("other"))
    records, payloads = [], {}
    for index, row in enumerate((first_row, second_row)):
        ref = c.make_continuation(c.ReferenceField.SOURCES, f"audit/refs-{index}.jsonl", (row,),
                                  origin=origin(), claim_id=link("claim-1"))
        records.append(replace(decision(), context=replace(context(), continuations=(ref,))))
        payloads[ref.path] = (row,)
    manifest, shards = products_bundle(tuple(records))
    args = {"expected_origin": origin(), "manifest_reference": c.ManifestRef.of("audit/manifest.json", manifest),
            "continuations": payloads}
    if same_hash:
        c.validate_bundle(manifest, shards, **args)
    else:
        with pytest.raises(IntegrityError, match="conflicting hash bindings"):
            c.validate_bundle(manifest, shards, **args)


@pytest.mark.parametrize("path", ["audit/manifest.json", "audit/decision.jsonl", "audit/refs.jsonl"])
def test_product_specific_references_cannot_alias_manifest_or_shard_bytes(path: str) -> None:
    row = source("continued-original", path="inputs/original.json")
    ref = c.make_continuation(c.ReferenceField.SOURCES, "audit/refs.jsonl", (row,),
                              origin=origin(), claim_id=link("claim-1"))
    first = replace(decision(), context=replace(context(), continuations=(ref,)))
    second = product_with_reference("verification.receipt", first, path, digest("different-file"))
    manifest, shards = products_bundle((first, second))
    with pytest.raises(IntegrityError, match="conflicting hash bindings"):
        c.validate_bundle(manifest, shards, expected_origin=origin(), continuations={ref.path: (row,)},
                          manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))


@pytest.mark.parametrize("path", ["audit/decision.jsonl", "audit/refs.jsonl"])
def test_manifest_reference_cannot_alias_product_or_reference_shards(path: str) -> None:
    rows = (source("continued"),)
    ref = c.make_continuation(c.ReferenceField.SOURCES, "audit/refs.jsonl", rows,
                              origin=origin(), claim_id=link("claim-1"))
    record = replace(decision(), context=replace(context(), continuations=(ref,)))
    manifest, shards = single_bundle(record)
    with pytest.raises(IntegrityError, match="distinct paths"):
        c.validate_bundle(manifest, shards, expected_origin=origin(), continuations={ref.path: rows},
                          manifest_reference=c.ManifestRef.of(path, manifest))


def cell_terminal(status: CellStatus, role: Role = Role.RED_TEAM_ANALYST) -> c.DecisionRecord:
    original = decision(preclaim=True)
    ctx = replace(original.context,
                  subject=replace(original.context.subject, proposal_ref=link()),
                  sources=(source("cell-1"),), origin_proposals=())
    return replace(original, context=ctx, stage=c.Stage.CELL_EXECUTION, outcome=status.value,
                   original_outcome=link(status.value), reason_code=c.ReasonCode.RECORDED_DECISION,
                   basis_status=c.BasisStatus.UNSTATED, actor_role=role, actor_role_absence_reason=None)


@pytest.mark.parametrize("status", list(CellStatus))
def test_cell_execution_preserves_every_terminal_status_without_semantic_inference(status: CellStatus) -> None:
    record = cell_terminal(status)
    document_validator().validate(record.to_dict())
    restored = c.from_document(record.to_dict(), expected_origin=origin())
    assert_typed_tree(record, restored)
    assert restored.stage is c.Stage.CELL_EXECUTION
    assert restored.outcome == status.value
    assert restored.original_outcome.value == status.value
    assert restored.actor_role is Role.RED_TEAM_ANALYST
    assert restored.actor_role_absence_reason is None
    assert restored.context.subject.cell_id.value == "cell-1"
    assert restored.context.subject.claim_id.value is None
    assert restored.context.subject.proposal_ref.value is None
    assert restored.context.origin_proposals == ()
    assert restored.deciding_actor_roles == () and restored.deciding_row is None
    assert restored.required_predicates == () and restored.missing_predicates == ()
    validate_single(restored, {})


def test_application_defaults_and_nondeciding_actor_roles_are_explicit_and_hash_bound() -> None:
    application = decision()
    assert application.actor_role is None
    assert application.actor_role_absence_reason is c.AbsenceReason.NOT_APPLICABLE
    assert_typed_tree(application, c.from_document(application.to_dict(), expected_origin=origin()))
    known = replace(application, actor_role=Role.LEAD_TRIAGER, actor_role_absence_reason=None)
    unknown = replace(application, actor_role_absence_reason=c.AbsenceReason.LEGACY_UNRECORDED)
    assert_typed_tree(known, c.from_document(known.to_dict(), expected_origin=origin()))
    assert_typed_tree(unknown, c.from_document(unknown.to_dict(), expected_origin=origin()))
    assert len({application.record_id, known.record_id, unknown.record_id}) == 3
    judge = cell_terminal(CellStatus.SUCCEEDED, Role.ADJUDICATION_JUDGE)
    assert judge.actor_role is Role.ADJUDICATION_JUDGE
    assert judge.deciding_actor_roles == ()
    assert judge.outcome == "succeeded"
    assert_typed_tree(judge, c.from_document(judge.to_dict(), expected_origin=origin()))
    assert judge.record_id != cell_terminal(CellStatus.SUCCEEDED).record_id


@pytest.mark.parametrize("changes", [
    {"actor_role": Role.RED_TEAM_ANALYST},
    {"actor_role": Role.RED_TEAM_ANALYST, "actor_role_absence_reason": c.AbsenceReason.LEGACY_UNRECORDED},
    {"actor_role": None, "actor_role_absence_reason": None},
    {"actor_role": "invented_role", "actor_role_absence_reason": None},
    {"actor_role": True, "actor_role_absence_reason": None},
    {"actor_role_absence_reason": "invented_reason"},
    {"actor_role_absence_reason": True},
])
def test_actor_role_and_absence_must_agree_without_defaulting_unknown_data(changes: dict) -> None:
    with pytest.raises(IntegrityError):
        replace(decision(), **changes)
    document = decision().to_dict()
    document.update(changes)
    assert list(document_validator().iter_errors(document))
    with pytest.raises(IntegrityError):
        c.from_document(document, expected_origin=origin())


def test_cell_execution_requires_an_actual_cell_and_known_nondeciding_role() -> None:
    terminal = cell_terminal(CellStatus.SUCCEEDED)
    without_cell = replace(terminal.context, subject=replace(terminal.context.subject, cell_id=link()))
    with pytest.raises(IntegrityError):
        replace(terminal, context=without_cell)
    with pytest.raises(IntegrityError):
        replace(terminal, actor_role=None, actor_role_absence_reason=c.AbsenceReason.LEGACY_UNRECORDED)
    with pytest.raises(IntegrityError):
        replace(terminal, deciding_actor_roles=(Role.RED_TEAM_ANALYST,))
    with pytest.raises(IntegrityError):
        replace(terminal, deciding_actor_roles=(Role.ADJUDICATION_JUDGE,))
    with pytest.raises(IntegrityError):
        replace(terminal, deciding_row=DecidingRow.CONFIRMED, deciding_row_absence_reason=None)
    document = terminal.to_dict()
    document["context"]["subject"]["cell_id"] = link().to_dict()
    assert list(document_validator().iter_errors(document))
    with pytest.raises(IntegrityError):
        c.from_document(document, expected_origin=origin())


@pytest.mark.parametrize("outcome", [
    "proposed", "explicit_no_claim", "proposal_rejected", "red_correct", "unresolved", "confirmed",
    "not_produced", "unavailable", "SUCCEEDED", True, None,
])
def test_cell_execution_outcomes_are_exactly_terminal_statuses(outcome: object) -> None:
    with pytest.raises(IntegrityError):
        replace(cell_terminal(CellStatus.SUCCEEDED), outcome=outcome)


@pytest.mark.parametrize(("stage", "outcome"), [
    (c.Stage.RED_DISCOVERY, "succeeded"),
    (c.Stage.RED_DISCOVERY, "failed"),
    (c.Stage.RED_DISCOVERY, "canceled"),
    (c.Stage.JUDGE_REVIEW, "succeeded"),
    (c.Stage.PROPOSAL_NORMALIZATION, "unavailable"),
    (c.Stage.ADJUDICATION, "unavailable"),
])
def test_terminal_stage_does_not_expand_existing_semantic_or_missing_input_outcomes(
        stage: c.Stage, outcome: str) -> None:
    with pytest.raises(IntegrityError):
        replace(decision(), stage=stage, outcome=outcome)


def test_terminal_and_semantic_populations_coexist_without_double_inference() -> None:
    red_terminal = cell_terminal(CellStatus.SUCCEEDED)
    red_semantic = replace(red_terminal, stage=c.Stage.RED_DISCOVERY, outcome="explicit_no_claim",
                           original_outcome=link("no_claim"), reason_code=c.ReasonCode.UNSTATED)
    judge_terminal = cell_terminal(CellStatus.SUCCEEDED, Role.ADJUDICATION_JUDGE)
    judge_terminal = replace(judge_terminal, context=replace(
        judge_terminal.context, sources=(source("judge-cell"),),
        subject=replace(judge_terminal.context.subject, cell_id=link("judge-cell"), claim_id=link("claim-1"),
                        lead_id=link())))
    judge_semantic = replace(judge_terminal, stage=c.Stage.JUDGE_REVIEW, outcome="unresolved",
                             original_outcome=link("unresolved"))
    records = (red_terminal, red_semantic, judge_terminal, judge_semantic)
    manifest, shards = products_bundle(records)
    manifest = replace(manifest, coverage=tuple(
        replace(item, expected=2, emitted=2) if item.population == c.Population.CELLS else
        replace(item, expected=1, emitted=1) if item.population == c.Population.LEADS else item
        for item in manifest.coverage))
    c.validate_bundle(manifest, shards, expected_origin=origin(),
                      manifest_reference=c.ManifestRef.of("audit/manifest.json", manifest))
    assert len({record.record_id for record in records}) == 4
    assert len({record.context.subject.cell_id.value for record in records}) == 2
    assert sum(record.stage == c.Stage.CELL_EXECUTION for record in records) == 2
    assert sum(record.outcome == "explicit_no_claim" for record in records) == 1
    assert sum(record.outcome == "unresolved" for record in records) == 1
    assert not any(record.outcome == "proposed" for record in records)
    assert all(record.context.subject.proposal_ref.value is None for record in records)
    assert all(record.deciding_actor_roles == () and record.deciding_row is None for record in records)
    assert next(item.emitted for item in manifest.coverage if item.population == c.Population.DECISIONS) == 4
    assert next(item.emitted for item in manifest.coverage if item.population == c.Population.CELLS) == 2
    assert next(item.emitted for item in manifest.coverage if item.population == c.Population.PROPOSALS) == 0
    for record in records:
        assert_typed_tree(record, c.from_document(record.to_dict(), expected_origin=origin()))


def attributed_relation(identity: str, predicate: Predicate, kind: RelationKind, role: Role, *,
                        counted: bool = True) -> c.RelationRef:
    return replace(relation(identity, role=role, kind=kind, counted=counted), predicate=predicate)


def recorded_decision(row: DecidingRow | None, rows: tuple[c.RelationRef, ...],
                      required: tuple[Predicate, ...], roles: tuple[Role, ...]) -> c.DecisionRecord:
    outcomes = {
        DecidingRow.DUPLICATE: "duplicate", DecidingRow.OUT_OF_SCOPE: "out_of_scope",
        DecidingRow.UNRESOLVED_CONTRADICTION: "insufficient_evidence",
        DecidingRow.DIRECT_CONTRADICTION: "not_reachable", DecidingRow.CONFIRMED: "confirmed",
        DecidingRow.SUPPORTED: "supported", DecidingRow.INSUFFICIENT_EVIDENCE: "insufficient_evidence",
    }
    return replace(decision(), context=context(relations=rows),
                   stage=c.Stage.ADMISSION if row is None else c.Stage.ADJUDICATION,
                   outcome="admitted" if row is None else outcomes[row], deciding_row=row,
                   deciding_row_absence_reason=c.AbsenceReason.NOT_APPLICABLE if row is None else None,
                   deciding_actor_roles=roles, required_predicates=required)


@pytest.mark.parametrize("row", [None, *list(DecidingRow)])
def test_deciding_roles_follow_each_recorded_row_without_replacing_its_outcome(row: DecidingRow | None) -> None:
    construct = attributed_relation("construct", Predicate.AFFECTED_CONSTRUCT, RelationKind.SUPPORTS,
                                    Role.RED_TEAM_ANALYST)
    blue = attributed_relation("blue-guard", Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.CONTRADICTS,
                               Role.BLUE_TEAM_REFUTER)
    verifier = attributed_relation("verifier-guard", Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                                   RelationKind.CONTRADICTS, Role.INDEPENDENT_VERIFIER)
    guard_support = attributed_relation("guard-support", Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                                        RelationKind.SUPPORTS, Role.RED_TEAM_ANALYST)
    optional = attributed_relation("optional", Predicate.SECURITY_IMPACT, RelationKind.SUPPORTS,
                                   Role.HYPOTHESIS_HUNTER)
    uncounted = attributed_relation("uncounted", Predicate.MISSING_OR_INEFFECTIVE_GUARD, RelationKind.SUPPORTS,
                                    Role.HYPOTHESIS_HUNTER, counted=False)
    judge = replace(relation("judge", role=Role.ADJUDICATION_JUDGE, counted=False),
                    noncounted_reason=c.NoncountedReason.JUDGE_NONDECIDING)
    required = (Predicate.AFFECTED_CONSTRUCT, Predicate.MISSING_OR_INEFFECTIVE_GUARD)
    if row == DecidingRow.UNRESOLVED_CONTRADICTION:
        rows = (construct, guard_support, blue, verifier, optional, uncounted, judge)
        expected = (Role.BLUE_TEAM_REFUTER, Role.INDEPENDENT_VERIFIER, Role.RED_TEAM_ANALYST)
    elif row == DecidingRow.DIRECT_CONTRADICTION:
        rows = (construct, blue, verifier, optional, uncounted, judge)
        expected = (Role.BLUE_TEAM_REFUTER, Role.INDEPENDENT_VERIFIER)
    elif row == DecidingRow.CONFIRMED:
        rows = (construct, guard_support, optional, uncounted, judge)
        expected = (Role.RED_TEAM_ANALYST,)
    elif row == DecidingRow.SUPPORTED:
        rows = (construct, optional, uncounted, judge)
        expected = (Role.RED_TEAM_ANALYST,)
    elif row == DecidingRow.INSUFFICIENT_EVIDENCE:
        rows = (optional, uncounted, judge)
        expected = ()
    else:
        rows = (construct, blue, verifier, optional, uncounted, judge)
        expected = ()
    before = tuple(canonical_json(item.to_dict()) for item in rows)
    assert c.deciding_roles(row, required, rows) == expected
    assert c.deciding_roles(row, frozenset(required), rows[::-1]) == expected
    assert tuple(canonical_json(item.to_dict()) for item in rows) == before
    record = recorded_decision(row, rows, required, expected)
    assert set(record.context.relations) == set(rows)
    restored = c.from_document(record.to_dict(), expected_origin=origin())
    assert_typed_tree(record, restored)
    assert restored.deciding_row == row and restored.outcome == record.outcome
    validate_single(restored, {})


def test_attribution_uses_polarity_per_required_predicate_not_every_counted_role() -> None:
    required = (Predicate.AFFECTED_CONSTRUCT, Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                Predicate.SOURCE_TO_SINK_REACHABILITY)
    rows = (
        attributed_relation("conflict-support", required[0], RelationKind.SUPPORTS, Role.RED_TEAM_ANALYST),
        attributed_relation("conflict-contradiction", required[0], RelationKind.CONTRADICTS, Role.BLUE_TEAM_REFUTER),
        attributed_relation("unopposed-contradiction", required[1], RelationKind.CONTRADICTS, Role.INDEPENDENT_VERIFIER),
        attributed_relation("unrelated-support", required[2], RelationKind.SUPPORTS, Role.BLUE_TEAM_REFUTER),
        attributed_relation("optional-support", Predicate.SECURITY_IMPACT, RelationKind.SUPPORTS, Role.HYPOTHESIS_HUNTER),
    )
    assert c.deciding_roles(DecidingRow.UNRESOLVED_CONTRADICTION, required, rows) == (
        Role.BLUE_TEAM_REFUTER, Role.RED_TEAM_ANALYST)
    assert c.deciding_roles(DecidingRow.DIRECT_CONTRADICTION, required, rows) == (Role.INDEPENDENT_VERIFIER,)
    for row in (DecidingRow.CONFIRMED, DecidingRow.SUPPORTED):
        assert c.deciding_roles(row, required, rows) == (Role.BLUE_TEAM_REFUTER, Role.RED_TEAM_ANALYST)
    # This is attribution of the supplied row, not selection of R3 despite the conflict.
    record = recorded_decision(DecidingRow.DIRECT_CONTRADICTION, rows, required, (Role.INDEPENDENT_VERIFIER,))
    assert record.deciding_row is DecidingRow.DIRECT_CONTRADICTION
    assert record.outcome == "not_reachable"
    assert len(record.context.relations) == 5
    assert c.deciding_roles(DecidingRow.DIRECT_CONTRADICTION, (), rows) == ()


@pytest.mark.parametrize("roles", [
    (), (Role.BLUE_TEAM_REFUTER,),
    (Role.BLUE_TEAM_REFUTER, Role.INDEPENDENT_VERIFIER, Role.RED_TEAM_ANALYST),
    (Role.BLUE_TEAM_REFUTER, Role.INDEPENDENT_VERIFIER, Role.HYPOTHESIS_HUNTER),
    (Role.BLUE_TEAM_REFUTER, Role.INDEPENDENT_VERIFIER, Role.INDEPENDENT_VERIFIER),
])
def test_dismissal_declared_roles_must_equal_joint_decisive_roles(roles: tuple[Role, ...]) -> None:
    rows = (
        relation("unrelated-red-support", role=Role.RED_TEAM_ANALYST),
        attributed_relation("blue-dismissal", Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                            RelationKind.CONTRADICTS, Role.BLUE_TEAM_REFUTER),
        attributed_relation("verifier-dismissal", Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                            RelationKind.CONTRADICTS, Role.INDEPENDENT_VERIFIER),
    )
    required = (Predicate.AFFECTED_CONSTRUCT, Predicate.MISSING_OR_INEFFECTIVE_GUARD)
    with pytest.raises(IntegrityError):
        recorded_decision(DecidingRow.DIRECT_CONTRADICTION, rows, required, roles)


@pytest.mark.parametrize("row", [
    DecidingRow.UNRESOLVED_CONTRADICTION, DecidingRow.DIRECT_CONTRADICTION,
    DecidingRow.CONFIRMED, DecidingRow.SUPPORTED,
])
def test_exact_attribution_agrees_for_inline_and_continued_populations(row: DecidingRow) -> None:
    construct = relation("construct-support", role=Role.RED_TEAM_ANALYST)
    blue = attributed_relation("blue", Predicate.MISSING_OR_INEFFECTIVE_GUARD,
                               RelationKind.CONTRADICTS if row in (
                                   DecidingRow.UNRESOLVED_CONTRADICTION, DecidingRow.DIRECT_CONTRADICTION)
                               else RelationKind.SUPPORTS, Role.BLUE_TEAM_REFUTER)
    required = (Predicate.AFFECTED_CONSTRUCT, Predicate.MISSING_OR_INEFFECTIVE_GUARD)
    inline = (construct,)
    if row == DecidingRow.UNRESOLVED_CONTRADICTION:
        inline += (attributed_relation("guard-support", required[1], RelationKind.SUPPORTS, Role.RED_TEAM_ANALYST),)
    if row == DecidingRow.SUPPORTED:
        required += (Predicate.ATTACKER_INPUT_CONTROL,)
    rows = (*inline, blue)
    expected = (Role.BLUE_TEAM_REFUTER,) if row == DecidingRow.DIRECT_CONTRADICTION else (
        Role.BLUE_TEAM_REFUTER, Role.RED_TEAM_ANALYST)
    direct = recorded_decision(row, rows, required, expected)
    ref = c.make_continuation(c.ReferenceField.RELATIONS, "audit/attribution-relations.jsonl", (blue,),
                              origin=origin(), claim_id=link("claim-1"))
    continued = replace(direct, context=replace(direct.context, relations=inline, continuations=(ref,)))
    assert c.deciding_roles(row, required, rows) == direct.deciding_actor_roles == continued.deciding_actor_roles
    validate_single(direct, {})
    validate_single(continued, {ref.path: (blue,)})
    assert direct.outcome == continued.outcome and direct.deciding_row == continued.deciding_row
    for bad_roles in ((), (*expected, Role.HYPOTHESIS_HUNTER)):
        malformed = replace(continued, deciding_actor_roles=bad_roles)
        with pytest.raises(IntegrityError, match="recorded row"):
            validate_single(malformed, {ref.path: (blue,)})
    with pytest.raises(IntegrityError, match="supplied reference continuations"):
        validate_single(continued, {})


def test_continued_support_can_remove_r4_attribution_without_changing_the_recorded_row() -> None:
    blue = relation("blue-contra", role=Role.BLUE_TEAM_REFUTER, kind=RelationKind.CONTRADICTS)
    red = relation("red-support", role=Role.RED_TEAM_ANALYST)
    required = (Predicate.AFFECTED_CONSTRUCT,)
    ref = c.make_continuation(c.ReferenceField.RELATIONS, "audit/opposing-support.jsonl", (red,),
                              origin=origin(), claim_id=link("claim-1"))
    direct = recorded_decision(DecidingRow.DIRECT_CONTRADICTION, (blue, red), required, ())
    partial = replace(direct, context=replace(direct.context, relations=(blue,), continuations=(ref,)))
    assert c.deciding_roles(DecidingRow.DIRECT_CONTRADICTION, required, (blue,)) == (Role.BLUE_TEAM_REFUTER,)
    assert c.deciding_roles(DecidingRow.DIRECT_CONTRADICTION, required, (blue, red)) == ()
    validate_single(partial, {ref.path: (red,)})
    assert partial.outcome == "not_reachable"
    assert partial.deciding_row is DecidingRow.DIRECT_CONTRADICTION
    with pytest.raises(IntegrityError, match="recorded row"):
        validate_single(replace(partial, deciding_actor_roles=(Role.BLUE_TEAM_REFUTER,)), {ref.path: (red,)})


@pytest.mark.parametrize("row", [
    None, DecidingRow.DUPLICATE, DecidingRow.OUT_OF_SCOPE, DecidingRow.INSUFFICIENT_EVIDENCE,
])
def test_application_only_attribution_is_empty_even_with_declared_continuations(row: DecidingRow | None) -> None:
    rel = relation()
    ref = c.make_continuation(c.ReferenceField.RELATIONS, "audit/accounted-relations.jsonl", (rel,),
                              origin=origin(), claim_id=link("claim-1"))
    record = recorded_decision(row, (), (Predicate.AFFECTED_CONSTRUCT,), ())
    record = replace(record, context=replace(record.context, continuations=(ref,)))
    validate_single(record, {ref.path: (rel,)})
    with pytest.raises(IntegrityError, match="recorded row"):
        replace(record, deciding_actor_roles=(Role.INDEPENDENT_VERIFIER,))


def test_only_relations_continuations_defer_attribution_and_judge_never_gains_authority() -> None:
    rel = relation()
    ref = c.make_continuation(c.ReferenceField.SOURCES, "audit/source-refs.jsonl", (source("new"),),
                              origin=origin(), claim_id=link("claim-1"))
    record = recorded_decision(DecidingRow.SUPPORTED, (rel,), (Predicate.AFFECTED_CONSTRUCT,),
                               (Role.INDEPENDENT_VERIFIER,))
    record = replace(record, context=replace(record.context, continuations=(ref,)))
    with pytest.raises(IntegrityError, match="recorded row"):
        replace(record, deciding_actor_roles=())
    with pytest.raises(IntegrityError, match="judge"):
        replace(record, deciding_actor_roles=(Role.INDEPENDENT_VERIFIER, Role.ADJUDICATION_JUDGE))
    with pytest.raises(IntegrityError, match="cannot be counted"):
        replace(rel, actor_role=Role.ADJUDICATION_JUDGE)


@pytest.mark.parametrize(("row", "required", "relations", "message"), [
    ("unknown_row", (), (), "closed row"),
    (True, (), (), "closed row"),
    (DecidingRow.SUPPORTED, ("invented_predicate",), (), "closed row"),
    (DecidingRow.SUPPORTED, None, (), "closed row"),
    (DecidingRow.SUPPORTED, (), None, "typed relation"),
    (DecidingRow.SUPPORTED, (), ({},), "typed relation"),
    (DecidingRow.SUPPORTED, (), (relation(), relation()), "attribution relation identities"),
])
def test_attribution_helper_rejects_malformed_closed_inputs(row, required, relations, message) -> None:
    with pytest.raises(IntegrityError, match=message):
        c.deciding_roles(row, required, relations)
