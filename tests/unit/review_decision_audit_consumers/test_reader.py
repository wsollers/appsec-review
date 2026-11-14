from __future__ import annotations

from dataclasses import replace
import json

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.job_final_publication_gate.verify import verify_gate_snapshot
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.reader import AuditBoundExceeded, REVIEW_JOB, _BoundReader
from appsec_review.review.models import IntegrityError, Role
from appsec_review.runtime.consume import upstream_scope
from appsec_review.runtime.contracts import InputRequirement, JobContract
from appsec_review.storage import atomic_bytes

from .helpers import Fixture, continued_verifier, digest, link


def test_real_accepted_bundle_and_gate_bindings(tmp_path):
    fixture = Fixture(tmp_path)
    audit = fixture.load()
    assert audit.available and audit.unavailable_reason is None
    assert set(audit.records) == set(fixture.products)
    assert audit.reference.origin.configuration_sha256 != fixture.review["configuration_sha256"]
    assert audit.basis("claim-1") == fixture.basis
    assert audit.basis("unknown") is None
    assert {row.relation_id for row in audit.relations(fixture.basis)} == {"support", "dissent", "qualification"}
    assert {row.path for row in audit.reads} >= {fixture.reference.path, fixture.finding_ref["path"],
                                                fixture.projection_ref["path"]}
    gate = {"run_id": fixture.root.name, "bindings": [row.reference() for row in audit.reads],
            "inputs": {"audit": {"path": audit.reference.path, "sha256": audit.reference.sha256}},
            "capabilities": {}, "attachments": {}}
    verify_gate_snapshot(fixture.root, gate)
    atomic_bytes(fixture.root / fixture.reference.path, b"tampered")
    with pytest.raises(IntegrityError, match="changed"):
        verify_gate_snapshot(fixture.root, gate)


def test_no_standalone_foreign_record_is_a_verified_member(tmp_path):
    fixture = Fixture(tmp_path)
    audit = fixture.load()
    with pytest.raises(IntegrityError, match="not a member"):
        audit.relations(replace(fixture.decision, original_outcome=link("other")))
    with pytest.raises(IntegrityError, match="not a member"):
        audit.origin_proposals(replace(fixture.decision, original_outcome=link("other")))


def test_legacy_missing_capability_is_not_complete_empty_audit(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.publish(legacy=True)
    audit = fixture.load()
    assert not audit.available and audit.unavailable_reason == "legacy_unrecorded"
    assert audit.records == audit.reads == ()


@pytest.mark.parametrize("reason", ["disabled", "capacity_exceeded", "input_unavailable"])
def test_unavailable_preserves_accepted_reason_and_metadata_reads(tmp_path, reason):
    fixture = Fixture(tmp_path, settings=DecisionAuditSettings(enabled=reason != "disabled"))
    fixture.publish(reason=reason)
    audit = fixture.load()
    assert not audit.available and audit.unavailable_reason == reason
    assert audit.manifest is None and audit.reference is None
    assert any(row.path.endswith("/publication.json") for row in audit.reads)


@pytest.mark.parametrize("change", [
    {"schema": "unknown"}, {"unknown": True}, {"status": "other"},
    {"unavailable_reason": "configured_disabled"}, {"policy": {}},
    {"manifest": None},
], ids=["schema", "extra", "status", "contradictory-absence", "policy", "null-manifest"])
def test_closed_publication_descriptor(tmp_path, change):
    fixture = Fixture(tmp_path)
    fixture.publish(mutate_metadata=lambda row: row.update(change))
    with pytest.raises((IntegrityError, ValueError), match="audit|manifest"):
        fixture.load()


@pytest.mark.parametrize("key,value", [
    ("run_id", "foreign"), ("review_attempt_id", "attempt_9999"), ("target_snapshot", "foreign"),
    ("review_handoff_sha256", digest("foreign")), ("accepted_manifest_sha256", digest("foreign")),
    ("ledger_head_sha256", digest("foreign")), ("projection_sha256", digest("foreign")),
    ("configuration_sha256", digest("foreign")), ("projection_policy_sha256", digest("foreign")),
], ids=["run", "attempt", "target", "handoff", "scope", "ledger", "projection", "configuration", "policy"])
def test_descriptor_origin_is_not_used_as_its_own_trust_anchor(tmp_path, key, value):
    fixture = Fixture(tmp_path)
    fixture.publish(mutate_metadata=lambda row: row["origin"].update({key: value}))
    with pytest.raises(IntegrityError, match="origin disagrees"):
        fixture.load()


@pytest.mark.parametrize("key,value", [("version", "foreign/1"), ("sha256", digest("foreign"))],
                         ids=["version", "hash"])
def test_policy_version_and_hash_are_verified(tmp_path, key, value):
    fixture = Fixture(tmp_path)
    fixture.publish(mutate_metadata=lambda row: row["policy"].update({key: value}))
    with pytest.raises(IntegrityError, match="policy"):
        fixture.load()


def test_policy_cannot_replace_frozen_configuration(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.publish(mutate_metadata=lambda row: row["policy"]["settings"].update({"max_records": 10}))
    with pytest.raises(IntegrityError, match="frozen"):
        fixture.load()


@pytest.mark.parametrize("path", ["../outside.json", "/absolute.json", "data\\evil.json",
                                 "data/./bad.json", "data//bad.json"])
def test_lexical_path_custody(tmp_path, path):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff, fixture.settings)
    with pytest.raises(IntegrityError, match="canonical"):
        reader.read({"path": path, "sha256": digest("anything")})


@pytest.mark.parametrize("kind", ["file", "ancestor", "outside"])
def test_links_are_rejected_even_when_bytes_and_pins_match(tmp_path, kind):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff, fixture.settings)
    path = fixture.root / fixture.reference.path
    if kind == "ancestor":
        original = path.parent
        moved = original.with_name("relocated")
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
    else:
        target = fixture.root / "linked.json" if kind == "file" else tmp_path / "outside.json"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
    with pytest.raises(IntegrityError, match="custody"):
        reader.read(fixture.reference.to_dict(), audit=True)


def test_unpinned_path_and_foreign_attempt_are_not_read(tmp_path):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff, fixture.settings)
    with pytest.raises(IntegrityError, match="admitted"):
        reader.read({"path": "target/private.json", "sha256": digest("private")})
    reader.admit(fixture.finding_ref)
    with pytest.raises(IntegrityError, match="another attempt"):
        reader.read(fixture.finding_ref, audit=True)


def test_same_path_cannot_gain_another_hash(tmp_path):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff, fixture.settings)
    with pytest.raises(IntegrityError, match="conflicting"):
        reader.admit({**fixture.finding_ref, "sha256": digest("other")})


def test_changed_hash_and_nonregular_file_fail(tmp_path):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff, fixture.settings)
    path = fixture.root / fixture.reference.path
    path.write_bytes(b"{}")
    with pytest.raises(IntegrityError, match="hash changed"):
        reader.read(fixture.reference.to_dict(), audit=True)
    path.unlink()
    path.mkdir()
    with pytest.raises(IntegrityError, match="regular"):
        reader.read(fixture.reference.to_dict(), audit=True)


@pytest.mark.parametrize("bound", ["records", "bytes", "shard-records"])
def test_declared_budgets_are_hard_errors_not_empty_success(tmp_path, bound):
    settings = DecisionAuditSettings(enabled=True, **{
        "records": {"max_records": 2}, "bytes": {"max_input_bytes": 4096, "shard_bytes": 4096},
        "shard-records": {"shard_records": 1}}[bound])
    fixture = Fixture(tmp_path, settings=settings)
    if bound == "shard-records":
        extra = replace(fixture.decision, original_outcome=link("other"))
        fixture.publish((*fixture.products, extra))
    with pytest.raises(AuditBoundExceeded):
        fixture.load()


def test_cached_reads_recheck_requested_shard_bound(tmp_path):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff, fixture.settings)
    first = reader.read(fixture.finding_ref)
    assert reader.read(fixture.finding_ref) == first
    assert reader.used_bytes == len(first)
    with pytest.raises(AuditBoundExceeded, match="shard_bytes"):
        reader.read(fixture.finding_ref, maximum=1)


def test_accepted_upstream_requires_a_declared_admitted_pin(tmp_path):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    contract = JobContract(inputs=(InputRequirement(REVIEW_JOB, "handoff", "appsec-review/job-handoff/2"),))
    with upstream_scope(fixture.root, "consumer", {REVIEW_JOB: accepted.sha256}, contract=contract):
        assert fixture.load().available
    with upstream_scope(fixture.root, "consumer", {}, contract=contract):
        with pytest.raises((AttributeError, ValueError)):
            fixture.load()
    with upstream_scope(fixture.root, "consumer", {REVIEW_JOB: accepted.sha256}, contract=JobContract()):
        with pytest.raises(ValueError, match="undeclared"):
            fixture.load()


def test_accepted_envelope_tamper_and_foreign_run_rejected(tmp_path):
    fixture = Fixture(tmp_path)
    path = fixture.root / fixture.attempt / "handoff.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="changed"):
        fixture.load()
    fixture.accept()
    moved = fixture.root.with_name("foreign-run")
    fixture.root.rename(moved)
    with pytest.raises(ValueError, match="accepted handoff"):
        accepted_handoff(moved, REVIEW_JOB)


def test_canonical_jsonl_is_required_after_hash_pin_rebinding(tmp_path):
    fixture = Fixture(tmp_path)
    path = fixture.audit_root + "/decision/0001.jsonl"
    fixture.write(path, json.dumps(fixture.decision.to_dict(), indent=2).encode())
    fixture.accept()
    with pytest.raises((IntegrityError, ValueError), match="count|hash|admitted"):
        fixture.load()


@pytest.mark.parametrize("mutation", ["claim", "package", "cell", "relation", "role",
                                     "finding", "adjudication", "claim-source", "relation-source",
                                     "decisions", "relations", "counted", "predicates", "judges", "scores"])
def test_basis_and_record_membership_are_full_not_hash_only(tmp_path, mutation):
    fixture = Fixture(tmp_path)
    basis = fixture.basis
    products = list(fixture.products)
    if mutation in {"claim", "package", "cell"}:
        key = mutation + "_id"
        subject = replace(fixture.decision.context.subject, **{key: link("foreign")})
        # A foreign decision is not linked by the otherwise valid basis.
        products.append(replace(fixture.decision, context=replace(fixture.context, subject=subject)))
    elif mutation in {"relation", "role", "relation-source", "counted"}:
        relation = fixture.relations[0]
        if mutation == "relation":
            relation = replace(relation, predicate=c.Predicate.ATTACKER_INPUT_CONTROL)
        elif mutation == "role":
            relation = replace(relation, actor_role=Role.BLUE_TEAM_REFUTER)
        elif mutation == "relation-source":
            relation = replace(relation, source=fixture.source(fixture.finding_ref, relation.relation_id))
        else:
            relation = replace(relation, counted=False, noncounted_reason=c.NoncountedReason.NOT_EVALUATED)
        basis = replace(basis, context=replace(basis.context, relations=(relation, *fixture.relations[1:])))
    elif mutation == "finding":
        basis = replace(basis, finding=fixture.source(fixture.projection_ref, "finding-1"))
    elif mutation == "adjudication":
        basis = replace(basis, adjudication=fixture.source(fixture.projection_ref, "adjudication-1"))
    elif mutation == "claim-source":
        basis = replace(basis, claim=fixture.source(fixture.finding_ref, "claim-1"))
    elif mutation == "decisions":
        products.append(replace(fixture.decision, original_outcome=link("another")))
    elif mutation == "relations":
        basis = replace(basis, context=replace(basis.context, relations=fixture.relations[:1]))
    elif mutation == "predicates":
        basis = replace(basis, required_predicates=())
    elif mutation == "judges":
        basis = replace(basis, judge_verdicts=())
    elif mutation == "scores":
        basis = replace(basis, score_refs=(fixture.source(fixture.projection_ref, "foreign-score"),))
    products[2] = basis
    fixture.publish(products)
    with pytest.raises(IntegrityError, match="audit"):
        fixture.load()


def test_complete_continuation_verifies_and_resolves_relation_membership(tmp_path):
    fixture = Fixture(tmp_path)
    products, payloads = continued_verifier(fixture)
    fixture.publish(products, continuations=payloads)
    audit = fixture.load()
    assert audit.relations(products[1]) == (fixture.relations[0],)
    assert len(audit.continuations) == 1


def test_continued_verifier_cannot_borrow_a_judge_relation(tmp_path):
    fixture = Fixture(tmp_path)
    judge = replace(fixture.relations[0], actor_role=Role.ADJUDICATION_JUDGE,
                    counted=False, noncounted_reason=c.NoncountedReason.JUDGE_NONDECIDING)
    products, payloads = continued_verifier(fixture, judge)
    # Standalone parsing deliberately defers this check; only full bundle validation can reject it.
    c.from_document(products[1].to_dict(), expected_origin=fixture.origin)
    fixture.publish(products, continuations=payloads)
    with pytest.raises(IntegrityError, match="verifier coverage"):
        fixture.load()


def test_missing_continuation_cannot_be_a_partial_success(tmp_path):
    fixture = Fixture(tmp_path)
    products, _ = continued_verifier(fixture)
    fixture.publish(products)
    with pytest.raises(IntegrityError, match="admitted"):
        fixture.load()


def test_reference_population_also_consumes_record_budget(tmp_path):
    fixture = Fixture(tmp_path, settings=DecisionAuditSettings(enabled=True, max_records=3))
    products, payloads = continued_verifier(fixture)
    fixture.publish(products, continuations=payloads)
    with pytest.raises(AuditBoundExceeded, match="max_records"):
        fixture.load()
