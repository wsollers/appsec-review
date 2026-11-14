from dataclasses import replace
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.indexing.store import accepted_handoff
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.reader import (
    AuditBoundExceeded, REVIEW_JOB, _authority_sources, _BoundReader,
)
from appsec_review.review.decision_audit.query import Query, Template, execute
from appsec_review.review.decision_audit.metadata import build_publication
from appsec_review.review.models import IntegrityError, Role
from appsec_review.runtime.contracts import InputRequirement, JobContract
from appsec_review.runtime.inputs import input_read_scope, producer_contract
from appsec_review.storage import canonical_json

from .helpers import Fixture, check, continued_verifier, digest, link, rebind_manifest


def test_new_declared_audit_missing_metadata_is_not_legacy(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.published.pop("metadata_path")
    fixture.accept()
    with pytest.raises(IntegrityError, match="declares.*omitted"):
        fixture.load()


def test_undeclared_protected_publication_is_not_an_operator_grant(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.declare_audit = False
    fixture.accept()
    with pytest.raises(IntegrityError, match="dataset declaration"):
        fixture.load()


def test_metadata_and_configuration_together_obey_original_reader_cap(tmp_path):
    fixture = Fixture(tmp_path, settings=DecisionAuditSettings(enabled=True, max_input_bytes=4096, shard_bytes=4096))
    fixture.config["fixture_padding"] = "x" * 5000
    ref = fixture.write("data/configuration/resolved.json", fixture.config, pin=False)
    fixture.write("data/configuration/manifest.json", {"resolved_sha256": ref["sha256"]}, pin=False)
    fixture.accept()
    with pytest.raises(AuditBoundExceeded, match="metadata and configuration"):
        fixture.load()


def test_read_detects_file_growth_after_stat(tmp_path, monkeypatch):
    fixture = Fixture(tmp_path)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    reader = _BoundReader(fixture.root, accepted.handoff,
                          DecisionAuditSettings(max_input_bytes=4096, shard_bytes=4096))
    ref = fixture.write(fixture.attempt + "/large.bin", b"x" * 5000)
    reader.admit(ref)
    actual = os.fstat
    monkeypatch.setattr(os, "fstat", lambda fd: SimpleNamespace(st_mode=actual(fd).st_mode, st_size=0))
    with pytest.raises(AuditBoundExceeded, match="during read"):
        reader.read(ref)


def test_non_json_and_unknown_dataset_path_are_explicit_errors(tmp_path):
    fixture = Fixture(tmp_path)
    reader = _BoundReader(fixture.root, accepted_handoff(fixture.root, REVIEW_JOB).handoff, fixture.settings)
    ref = fixture.write(fixture.audit_root + "/unknown.bin", b"invalid")
    reader.admit(ref)
    with pytest.raises(IntegrityError, match="no declared output"):
        reader.read(ref, audit=True)
    with pytest.raises(IntegrityError, match="not JSON"):
        reader.document(ref)


def test_shared_receipts_and_structural_checks_are_admitted_from_accepted_records_only(tmp_path):
    fixture = Fixture(tmp_path)
    cell = fixture.projection["cells"]["cell-1"][0]
    receipt = fixture.write(f"data/jobs/{REVIEW_JOB}/cells/cell-1/attempt-1.json", {"status": "succeeded"})
    cell["receipt_sha256"] = receipt["sha256"]
    check = fixture.write(f"data/jobs/{REVIEW_JOB}/cells/cell-1/independence-attempt-1.json",
                          {"cell_id": "cell-1", "contains_forbidden_marker": False})
    lane_ref = fixture.write(fixture.attempt + "/steps/lead_review/lane.json", {
        "independence": {"claim-1": [{"verifier_cell_id": "cell-1", "audit": {"request_check": check}},
                                    {"verifier_cell_id": "judge-1"}, {"independent": False}]}})
    fixture.outputs["lead_review.teams"] = {"artifact": lane_ref}
    fixture.accept()
    reader = _BoundReader(fixture.root, accepted_handoff(fixture.root, REVIEW_JOB).handoff, fixture.settings)
    _authority_sources(reader, fixture.outputs, fixture.scope, fixture.projection)
    assert reader.document(check)["cell_id"] == "cell-1"
    assert reader.document(receipt)["status"] == "succeeded"
    bad_lane = fixture.write(fixture.attempt + "/steps/lead_review/foreign.json", {
        "independence": {"claim-1": [{"verifier_cell_id": "judge-1", "audit": {"request_check": check}}]}})
    reader.admit(bad_lane)
    reader.independence.clear()
    with pytest.raises(IntegrityError, match="another cell"):
        _authority_sources(reader, {"lead_review.teams": {"artifact": bad_lane}}, fixture.scope, fixture.projection)


def test_only_scope_selected_exact_shards_are_admitted_and_observed(tmp_path, monkeypatch):
    fixture = Fixture(tmp_path)
    first = fixture.write("data/indices/source/one.bin", b"first")
    second = fixture.write("data/indices/source/two.bin", b"second")
    shards = [{"name": "source", "shard_id": name, "sha256": ref["sha256"], "relative_path": ref["path"],
               "producer": {"job": "job_target_catalog"}} for name, ref in (("one", first), ("two", second))]
    manifest_ref = fixture.write(fixture.manifest_ref["path"], {
        "run_id": fixture.root.name, "target_snapshot": "target-1", "indexes": shards})
    scope = {**fixture.scope, "manifest_sha256": manifest_ref["sha256"],
             "shards": [{"name": "source", "shard_id": "one", "sha256": first["sha256"]}]}
    fixture.accept()
    reader = _BoundReader(fixture.root, accepted_handoff(fixture.root, REVIEW_JOB).handoff, fixture.settings)
    # Original producer artifacts are not review-owned pins.
    reader.pins.pop(first["path"])
    reader.pins.pop(second["path"])
    reads = []
    monkeypatch.setattr("appsec_review.review.decision_audit.reader.observe_shard",
                        lambda root, shard: reads.append(shard))
    _authority_sources(reader, fixture.outputs, scope, fixture.projection)
    assert reader.read(first) == b"first" and reads == [shards[0]]
    with pytest.raises(IntegrityError, match="admitted"):
        reader.read(second)


@pytest.mark.parametrize("data", [b"not-json\n", b"\xff\n"], ids=["invalid-json", "invalid-utf8"])
def test_malformed_product_json_is_rejected_after_exact_pins(tmp_path, data):
    fixture = Fixture(tmp_path)
    manifest = fixture.publish()
    shard = next(row for row in manifest.shards if row.kind == c.ProductKind.DECISION)
    fixture.write(shard.path, data)
    changed = replace(shard, sha256=hashlib.sha256(data).hexdigest(), byte_count=len(data))
    rebind_manifest(fixture, replace(manifest, shards=tuple(changed if row == shard else row for row in manifest.shards)))
    with pytest.raises(IntegrityError, match="invalid JSON"):
        fixture.load()


def test_noncanonical_shard_bytes_do_not_become_valid_by_rehashing(tmp_path):
    fixture = Fixture(tmp_path)
    manifest = fixture.publish()
    shard = next(row for row in manifest.shards if row.kind == c.ProductKind.DECISION)
    data = json.dumps(fixture.decision.to_dict(), separators=(", ", ": ")).encode() + b"\n"
    fixture.write(shard.path, data)
    changed = replace(shard, sha256=hashlib.sha256(data).hexdigest(), byte_count=len(data))
    rebind_manifest(fixture, replace(manifest, shards=tuple(changed if row == shard else row for row in manifest.shards)))
    with pytest.raises(IntegrityError, match="not canonical"):
        fixture.load()


def test_shared_continuation_payload_is_read_once_and_each_owner_validated(tmp_path):
    fixture = Fixture(tmp_path)
    products, payloads = continued_verifier(fixture)
    basis = replace(products[2], context=replace(products[2].context, relations=fixture.relations[1:],
                                                continuations=products[1].context.continuations))
    fixture.publish((*products[:2], basis), continuations=payloads)
    audit = fixture.load()
    assert len(audit.continuations) == 1
    assert {row.relation_id for row in audit.relations(basis)} == {"support", "dissent", "qualification"}


@pytest.mark.parametrize("bad", ["count", "bytes", "json", "noncanonical", "records-bound"])
def test_continuation_transport_is_fully_bounded_and_verified(tmp_path, bad):
    settings = DecisionAuditSettings(enabled=True, shard_records=1 if bad == "records-bound" else 5000)
    fixture = Fixture(tmp_path, settings=settings)
    products, payloads = continued_verifier(fixture)
    verifier = products[1]
    original = verifier.context.continuations[0]
    payload = payloads[original.path]
    changes = {}
    if bad == "count":
        changes["record_count"] = 2
    elif bad == "bytes":
        changes["byte_count"] = len(payload) + 1
    elif bad in ("json", "noncanonical"):
        payload = b"bad-json\n" if bad == "json" else json.dumps(fixture.relations[0].to_dict()).encode() + b"\n"
        changes = {"byte_count": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    else:
        changes["record_count"] = 2
    ref = replace(original, **changes)
    verifier = replace(verifier, context=replace(verifier.context, continuations=(ref,)))
    basis = replace(products[2], verification=c.OptionalRecord(c.RecordRef.of(verifier), None))
    fixture.publish((products[0], verifier, basis), continuations={ref.path: payload})
    with pytest.raises(IntegrityError, match="count|JSON|canonical|shard_records"):
        fixture.load()


def test_bundle_path_collision_in_continued_source_is_not_ignored(tmp_path):
    fixture = Fixture(tmp_path)
    original = fixture.relations[0]
    changed = replace(original, source=replace(original.source, sha256=digest("wrong")))
    products, payloads = continued_verifier(fixture, changed)
    fixture.publish(products, continuations=payloads)
    with pytest.raises(IntegrityError, match="conflicting hash"):
        fixture.load()


def test_query_rejects_broken_internal_available_object(tmp_path):
    audit = Fixture(tmp_path).load()
    with pytest.raises(IntegrityError, match="no accepted manifest"):
        execute(replace(audit, reference=None), Query(Template.POPULATION))


def test_preclaim_lead_keeps_absent_claim_package_and_cell_explicit(tmp_path):
    fixture = Fixture(tmp_path)
    subject = replace(fixture.subject, lead_id=link("lead-1"), claim_id=c.Link(None, c.AbsenceReason.PRE_CLAIM),
                      adjudication_id=link(), finding_package_id=link(), package_id=link(), cell_id=link())
    source = fixture.write(fixture.attempt + "/steps/scope/lead.json", {"lead_id": "lead-1"})
    decision = replace(fixture.decision, context=replace(fixture.context, subject=subject,
                                                         sources=(fixture.source(source, "lead-1"),)))
    fixture.publish((decision,))
    audit = fixture.load()
    assert audit.records[0].context.subject.claim_id.absence_reason == c.AbsenceReason.PRE_CLAIM


@pytest.mark.parametrize("role,status", [(Role.ADJUDICATION_JUDGE, "succeeded"),
                                       (Role.INDEPENDENT_VERIFIER, "failed")], ids=["foreign-role", "wrong-status"])
def test_cell_execution_cannot_change_accepted_role_or_outcome(tmp_path, role, status):
    fixture = Fixture(tmp_path)
    decision = replace(fixture.decision, stage=c.Stage.CELL_EXECUTION, outcome=status,
                       actor_role=role, actor_role_absence_reason=None)
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),))
    fixture.publish((decision, fixture.verification, basis))
    with pytest.raises(IntegrityError, match="role disagrees|outcome disagrees"):
        fixture.load()


def test_real_runtime_read_receipts_require_exact_protected_dataset_permissions(tmp_path):
    fixture = Fixture(tmp_path)
    products, payloads = continued_verifier(fixture)
    fixture.publish(products, continuations=payloads)
    accepted = accepted_handoff(fixture.root, REVIEW_JOB)
    handoff = InputRequirement(REVIEW_JOB, "handoff", "appsec-review/job-handoff/2")
    requirements = tuple(InputRequirement(REVIEW_JOB, row.output_kind, row.schema, authority=row.authority)
                         for row in producer_contract(fixture.root, accepted.handoff))
    context = SimpleNamespace(run_root=fixture.root, config=SimpleNamespace(job_id="job_dossier_publication"),
                              contract=JobContract(inputs=(handoff, *requirements)),
                              upstream_handoffs={REVIEW_JOB: accepted.sha256})
    with input_read_scope(context) as reads:
        audit = fixture.load()
        document = reads.document()
    seen = {row["output_kind"] for row in document["reads"]}
    assert seen == {"handoff", "review_audit_metadata", "review_decision_audit", "review_decisions",
                    "review_verification_coverage", "review_decision_bases", "review_audit_continuations",
                    "accepted_scope", "claim_ledger", "scores_and_findings", "review_cells"}
    assert all(row["read"] is True and row["cited"] is None for row in document["reads"])
    assert document["citation_observation"] == "not_observed"
    assert all(row["sha256"] in {receipt.sha256 for receipt in audit.reads}
               for row in document["reads"] if "sha256" in row)
    denied = SimpleNamespace(**{**vars(context), "config": SimpleNamespace(job_id="job_poc_generation"),
                                "contract": JobContract(inputs=(handoff,))})
    with pytest.raises(ValueError, match="undeclared consumption.*review_audit_metadata"):
        with input_read_scope(denied):
            fixture.load()


@pytest.mark.parametrize("change", [
    {"cell_id": "another-cell"}, {"schema": "unknown"}, {"attempt": 2}, {"status": "failed"},
    {"seen_identities": []}, {"seen_identities": ["foreign-entity"]}, {"seen_identities": "entity-support"},
    {"seen_identities": [True]}, {"reused_from": {"cell_id": "another-cell"}}, {"reused_from": None},
], ids=["cell", "schema", "attempt", "status", "empty-reads", "foreign-read", "not-list",
        "non-identity", "memo", "memo-null"])
def test_own_verifier_reads_are_observed_not_supplied_or_memo_reused(tmp_path, change):
    fixture = Fixture(tmp_path, receipt_changes=change)
    with pytest.raises(IntegrityError, match="receipt identity|own reads require|own observed reads"):
        fixture.load()


def test_own_reads_cannot_borrow_projection_or_another_cell_receipt(tmp_path):
    fixture = Fixture(tmp_path)
    predicate = replace(fixture.verification.predicates[0],
                        own_read_refs=(fixture.source(fixture.projection_ref, "cell-1"),))
    verifier = replace(fixture.verification, predicates=(predicate,))
    basis = replace(fixture.basis, verification=c.OptionalRecord(c.RecordRef.of(verifier), None))
    fixture.publish((fixture.decision, verifier, basis))
    with pytest.raises(IntegrityError, match="subject cell's receipt"):
        fixture.load()


def test_cell_receipt_private_dicts_never_cross_operator_or_dossier_boundary(tmp_path):
    fixture = Fixture(tmp_path)
    decision = replace(fixture.decision, cell_receipt=c.OptionalSource(fixture.source(fixture.receipt_ref, "cell-1"), None))
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),))
    fixture.publish((decision, fixture.verification, basis))
    result = execute(fixture.load(), Query(Template.LEAD_TRACE, lead_id="lead-1"))
    assert "DO_NOT_COPY_PRIVATE_WORKER_DICTIONARY" not in canonical_json(result).decode()
    assert "raw_private_payload" not in canonical_json(result).decode()


def test_score_and_judge_citations_bind_the_original_artifact_not_just_an_id(tmp_path):
    fixture = Fixture(tmp_path, scores=True)
    assert fixture.load().basis("claim-1").score_refs == fixture.basis.score_refs
    wrong = replace(fixture.basis, score_refs=(fixture.source(fixture.projection_ref, "score-1"),))
    fixture.publish((fixture.decision, fixture.verification, wrong))
    with pytest.raises(IntegrityError, match="scoring artifact"):
        fixture.load()
    wrong = replace(fixture.basis, judge_verdicts=(fixture.source(fixture.scoring_ref, "judge-verdict-1"),))
    fixture.publish((fixture.decision, fixture.verification, wrong))
    with pytest.raises(IntegrityError, match="judge verdict.*projection"):
        fixture.load()


def structural_verification(fixture, *, passed=True, document_change=None, capture_change=None):
    source = fixture.write(f"data/jobs/{REVIEW_JOB}/cells/cell-1/independence-attempt-1.json", {
        "schema": "appsec-review/verifier-request-check/1", "cell_id": "cell-1", "attempt": 1,
        "contains_forbidden_marker": not passed, **(document_change or {})})
    capture = {"schema": "appsec-review/verifier-structure-capture/1", "actor_distinct": True,
               "conversation_fresh": True, "prior_response_absent": True, "shared_actor_cache_absent": True,
               "request_markers_absent": passed, "request_check": source, **(capture_change or {})}
    entry = {**fixture.independence, "independent": passed, "audit": capture}
    lane_ref = fixture.write(fixture.lane_ref["path"], {"independence": {"claim-1": [entry]}})
    fixture.outputs["lead_review.teams"] = {"artifact": lane_ref}
    verification = replace(fixture.verification, blindness=c.Blindness(
        check(True), check(True), check(True), check(True),
        c.OptionalSource(fixture.source(source, "cell-1"), None), check(passed)),
        confirmation_eligible=check(passed), existing_r6_passed=check(passed))
    basis = replace(fixture.basis, verification=c.OptionalRecord(c.RecordRef.of(verification), None))
    fixture.publish((fixture.decision, verification, basis))
    return verification


@pytest.mark.parametrize("passed", [False, True])
def test_blindness_is_anchored_to_structural_capture_and_exact_request_check(tmp_path, passed):
    fixture = Fixture(tmp_path)
    verification = structural_verification(fixture, passed=passed)
    audit = fixture.load()
    result = execute(audit, Query(Template.VERIFICATION_COVERAGE))["records"][0]
    assert result["blindness"]["passed"]["value"] is passed
    assert result["existing_r6_passed"]["value"] is passed
    assert result["diversity"]["provider_distinct"]["value"] is False
    assert any(row.sha256 == verification.blindness.request_check.value.sha256 for row in audit.reads)


@pytest.mark.parametrize("document,capture", [
    ({"cell_id": "foreign"}, None), ({"schema": "unknown"}, None),
    ({"contains_forbidden_marker": True}, None), (None, {"request_markers_absent": False}),
    (None, {"actor_distinct": False}), (None, {"schema": "unknown"}),
], ids=["cell", "request-schema", "marker-present", "marker-check", "actor-check", "capture-schema"])
def test_blindness_cannot_turn_unverified_or_failed_request_into_pass(tmp_path, document, capture):
    fixture = Fixture(tmp_path)
    structural_verification(fixture, document_change=document, capture_change=capture)
    with pytest.raises(IntegrityError, match="blindness|structural"):
        fixture.load()


@pytest.mark.parametrize("field", ["r6", "provider", "model"])
def test_verification_does_not_invent_independence_or_diversity(tmp_path, field):
    fixture = Fixture(tmp_path)
    verification = fixture.verification
    if field == "r6":
        verification = replace(verification, existing_r6_passed=check(True))
    else:
        key = "provider_distinct" if field == "provider" else "model_profile_distinct"
        verification = replace(verification, diversity=replace(verification.diversity, **{key: check(True)}))
    basis = replace(fixture.basis, verification=c.OptionalRecord(c.RecordRef.of(verification), None))
    fixture.publish((fixture.decision, verification, basis))
    with pytest.raises(IntegrityError, match="independence provenance"):
        fixture.load()


def test_unknown_own_reads_do_not_rewrite_the_existing_r6_result(tmp_path):
    fixture = Fixture(tmp_path, receipt_changes={"reused_from": {"cell_id": "original-cell"}})
    lane_ref = fixture.write(fixture.lane_ref["path"], {
        "independence": {"claim-1": [{**fixture.independence, "independent": True}]}})
    fixture.outputs["lead_review.teams"] = {"artifact": lane_ref}
    predicate = replace(fixture.verification.predicates[0], own_read_refs=(), supporting_relation_ids=(),
                        coverage=c.SupportCoverage.UNKNOWN, unknown_reason=c.AbsenceReason.LEGACY_UNRECORDED)
    verification = replace(fixture.verification, predicates=(predicate,), confirmation_eligible=check(None),
                           existing_r6_passed=check(True))
    basis = replace(fixture.basis, verification=c.OptionalRecord(c.RecordRef.of(verification), None))
    fixture.publish((fixture.decision, verification, basis))
    result = execute(fixture.load(), Query(Template.VERIFICATION_COVERAGE))["records"][0]
    assert result["existing_r6_passed"]["value"] is True
    assert result["confirmation_eligible"]["value"] is None
    assert result["predicates"][0]["coverage"] == "unknown"
    assert result["predicates"][0]["own_read_refs"] == []
    assert fixture.finding["state"] == "confirmed" and fixture.finding["direct_evidence"] == ["support"]


@pytest.mark.parametrize("kind", ["manifest", "product", "continuation"])
def test_fixed_layout_cannot_relabel_an_artifact_as_another_dataset(tmp_path, kind):
    fixture = Fixture(tmp_path)
    if kind == "manifest":
        manifest = fixture.publish()
        path = fixture.audit_root + "/decision/manifest.json"
        fixture.write(path, c.canonical_bytes(manifest))
        reference = c.ManifestRef.of(path, manifest)
        fixture.write(fixture.audit_root + "/publication.json",
                      build_publication(fixture.origin, settings=fixture.settings, manifest=reference))
        fixture.accept()
    elif kind == "product":
        manifest = fixture.publish()
        shard = next(row for row in manifest.shards if row.kind == c.ProductKind.DECISION)
        path = fixture.audit_root + "/verification_coverage/foreign.jsonl"
        fixture.write(path, (fixture.root / shard.path).read_bytes())
        changed = replace(shard, path=path)
        rebind_manifest(fixture, replace(manifest, shards=tuple(
            changed if row == shard else row for row in manifest.shards)))
    else:
        products, payloads = continued_verifier(fixture)
        original = products[1].context.continuations[0]
        ref = replace(original, path=fixture.audit_root + "/decision/foreign.jsonl")
        verifier = replace(products[1], context=replace(products[1].context, continuations=(ref,)))
        basis = replace(products[2], verification=c.OptionalRecord(c.RecordRef.of(verifier), None))
        fixture.publish((products[0], verifier, basis), continuations={ref.path: payloads[original.path]})
    with pytest.raises(IntegrityError, match="declared manifest location|declared family"):
        fixture.load()


def test_chain_verifier_terminal_is_not_given_a_fictitious_claim_coverage_record(tmp_path):
    fixture = Fixture(tmp_path, chain_cell=True)
    subject = replace(fixture.subject, lead_id=link(), proposal_ref=link(), claim_id=link(),
                      adjudication_id=link(), finding_package_id=link(), package_id=link("chain-package"),
                      cell_id=link("chain-1"))
    terminal = replace(fixture.decision, stage=c.Stage.CELL_EXECUTION, outcome="succeeded",
                       actor_role=Role.INDEPENDENT_VERIFIER, actor_role_absence_reason=None,
                       context=replace(fixture.context, subject=subject,
                                       sources=(fixture.source(fixture.projection_ref, "chain-1"),),
                                       gap_ids=("audit:chain_verification_has_no_claim_coverage_contract",)))
    manifest = fixture.publish((*fixture.products, terminal))
    coverage = tuple(c.CoverageCount(row.population, 2, 1, 0, 1, c.CoverageReason.INPUT_UNAVAILABLE)
                     if row.population == c.Population.VERIFICATIONS else row for row in manifest.coverage)
    rebind_manifest(fixture, replace(manifest, coverage=coverage))
    audit = fixture.load()
    result = execute(audit, Query(Template.POPULATION, stage=c.Stage.CELL_EXECUTION,
                                  role=Role.INDEPENDENT_VERIFIER))
    assert result["total"] == 1 and result["records"][0]["context"]["subject"]["claim_id"]["value"] is None
    coverage = execute(audit, Query(Template.VERIFICATION_COVERAGE))
    assert coverage["total"] == 1
    assert next(row for row in coverage["coverage"] if row["population"] == "verification_coverage")["unavailable"] == 1


def test_original_cell_package_survives_canonical_cross_package_merge(tmp_path):
    fixture = Fixture(tmp_path, cell_package="original-package")
    audit = fixture.load()
    assert fixture.verification in audit.records
    assert fixture.verification.context.subject.package_id.value == "original-package"
    assert audit.basis("claim-1").context.subject.package_id.value == fixture.claim["package_id"] == "package-1"


@pytest.mark.parametrize("field", ["adjudication_id", "finding_package_id"])
def test_non_basis_records_cannot_borrow_foreign_final_identities(tmp_path, field):
    fixture = Fixture(tmp_path)
    decision = replace(fixture.decision, context=replace(fixture.context, subject=replace(
        fixture.subject, **{field: link("foreign")})))
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),))
    fixture.publish((decision, fixture.verification, basis))
    with pytest.raises(IntegrityError, match="foreign adjudication|foreign finding"):
        fixture.load()


def test_wrong_verification_kind_is_rejected_before_a_dossier_can_receive_the_bundle(tmp_path):
    fixture = Fixture(tmp_path)
    manifest = fixture.publish()
    document = fixture.basis.to_dict()
    document["verification"]["value"] = c.RecordRef.of(fixture.decision).to_dict()
    document.pop("record_id")
    document["record_id"] = "decision-basis-" + hashlib.sha256(canonical_json(document)).hexdigest()
    payload = canonical_json(document)
    shard = next(row for row in manifest.shards if row.kind == c.ProductKind.BASIS)
    ref = fixture.write(shard.path, payload)
    changed = c.ShardRef(c.ProductKind.BASIS, shard.path, ref["sha256"], len(payload), 1,
                        (c.RecordRef(c.ProductKind.BASIS, document["record_id"], ref["sha256"]),))
    rebind_manifest(fixture, replace(manifest, shards=tuple(
        changed if row == shard else row for row in manifest.shards)))
    with pytest.raises(IntegrityError, match="decision audit basis"):
        fixture.load()


@pytest.mark.parametrize("mutation", ["row", "predicates", "counted"])
def test_chosen_row_attribution_is_revalidated_against_original_adjudication(tmp_path, mutation):
    fixture = Fixture(tmp_path)
    row, outcome = (c.DecidingRow.SUPPORTED, "supported") if mutation == "row" else (c.DecidingRow.CONFIRMED, "confirmed")
    required = () if mutation == "predicates" else fixture.decision.required_predicates
    relations = fixture.relations
    if mutation == "counted":
        relations = (replace(relations[0], counted=False, noncounted_reason=c.NoncountedReason.NOT_EVALUATED),
                     *relations[1:])
    decision = replace(fixture.decision, context=replace(fixture.context, relations=relations),
                       stage=c.Stage.ADJUDICATION, outcome=outcome, deciding_row=row, deciding_row_absence_reason=None,
                       required_predicates=required, deciding_actor_roles=c.deciding_roles(row, required, relations))
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision),))
    fixture.publish((decision, fixture.verification, basis))
    with pytest.raises(IntegrityError, match="accepted adjudication|accepted predicate accounting"):
        fixture.load()


def test_nondeciding_qualifier_is_retained_without_claiming_an_own_read(tmp_path):
    fixture = Fixture(tmp_path, qualification_cell="cell-1")
    predicate = replace(fixture.verification.predicates[0], qualifying_relation_ids=("qualification",))
    verifier = replace(fixture.verification, predicates=(predicate,),
                       context=replace(fixture.verification.context, relations=(
                           fixture.relations[0], fixture.relations[2])))
    basis = replace(fixture.basis, verification=c.OptionalRecord(c.RecordRef.of(verifier), None))
    fixture.publish((fixture.decision, verifier, basis))
    audit = fixture.load()
    view = execute(audit, Query(Template.VERIFICATION_COVERAGE))["records"][0]
    assert view["predicates"][0]["supporting_relation_ids"] == ["support"]
    assert view["predicates"][0]["qualifying_relation_ids"] == ["qualification"]
    relation = next(row for row in view["context"]["relations"] if row["relation_id"] == "qualification")
    assert relation["counted"] is False and relation["noncounted_reason"] == "qualifying"
    original = fixture.projection["relations"]["claim-1"][2]
    assert original["retrieval_receipt_sha256"] != fixture.receipt_ref["sha256"]
    assert fixture.finding["direct_evidence"] == ["support"]
