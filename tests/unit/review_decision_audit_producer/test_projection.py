from copy import deepcopy
from dataclasses import replace
import json

import pytest

from appsec_review.config.inference_review import PocCandidateSettings
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.schemas import SCHEMA_DIRECTORY, SchemaSet
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.decision_audit.projection import explanation, labelled_text, link, policy_sha256
from appsec_review.review.decision_audit.publication import AuditUnavailable, publish_bundle
from appsec_review.review.models import CellStatus, IntegrityError, Role
from appsec_review.storage import canonical_json

from .helpers import ROOT, document, fixture, digest


def decisions(result, stage):
    return [row for row in result.records if isinstance(row, c.DecisionRecord) and row.stage == stage]


def test_real_adjudication_and_finding_bytes_are_unchanged(tmp_path):
    f = fixture(tmp_path)
    before = deepcopy(f.inputs.projection.to_json())
    finding_bytes = [(f.root / doc.source.path).read_bytes() for doc in f.inputs.findings]
    poc_before = stages.poc_candidates(f.findings, (), PocCandidateSettings())
    result = f.project()
    assert f.inputs.projection.to_json() == before
    assert [(f.root / doc.source.path).read_bytes() for doc in f.inputs.findings] == finding_bytes
    assert stages.poc_candidates(f.findings, (), PocCandidateSettings()) == poc_before
    basis = next(row for row in result.records if isinstance(row, c.DecisionBasisRecord))
    assert basis.context.subject.claim_id.value in f.inputs.projection.claims
    assert basis.context.origin.configuration_sha256 != digest("semantic")
    assert basis.context.subject.operation_id.value == "operation-1"
    assert any(row.kind.value == "qualifies" and not row.counted for row in basis.context.relations)
    judge = next(row for row in basis.context.relations if row.actor_role == Role.ADJUDICATION_JUDGE)
    assert not judge.counted and judge.noncounted_reason == c.NoncountedReason.JUDGE_NONDECIDING
    assert all(Role.ADJUDICATION_JUDGE not in row.deciding_actor_roles
               for row in decisions(result, c.Stage.ADJUDICATION))
    verifier = next(row for row in result.records if isinstance(row, c.VerificationRecord))
    assert verifier.blindness.passed.value is True
    assert verifier.diversity.provider_distinct.value is False
    assert verifier.diversity.model_profile_distinct.value is False
    assert verifier.confirmation_eligible.value is True
    assert verifier.existing_r6_passed.value is True
    assert verifier.diversity.resolved_model_revision.absence_reason == c.AbsenceReason.UNKNOWN_MODEL_REVISION
    assert "private target statement" not in repr(result)
    assert "ghp_SUPERSECRET" not in repr(result)
    assert "password=secret" not in repr(result)


def test_every_lead_including_unadmitted_keeps_scanner_provenance(tmp_path):
    f = fixture(tmp_path)
    result = f.project()
    collected = decisions(result, c.Stage.COLLECTION)
    assert {row.context.subject.lead_id.value for row in collected} == {"lead-1", "lead-2", "lead-3"}
    unadmitted = next(row for row in decisions(result, c.Stage.ADMISSION) if row.outcome == "not_admitted")
    assert unadmitted.context.subject.lead_id.value == "lead-2"
    assert all("family source_sast; scanner scanner" in row.context.explanation.text for row in collected)
    assert all(row.context.sources[0].path == "data/indices/observations.json" for row in collected)
    no_claim = next(row for row in decisions(result, c.Stage.RED_DISCOVERY) if row.outcome == "explicit_no_claim")
    assert no_claim.context.subject.claim_id.value is None
    assert no_claim.context.origin_proposals == ()
    assert no_claim.deciding_row is None
    assert "guard is present" in no_claim.context.explanation.text
    assert no_claim.basis_status == c.BasisStatus.NARRATIVE_ONLY
    supplied = decisions(result, c.Stage.PACKAGE_ASSEMBLY)[0].context.sources[0]
    assert supplied.uses == (c.EvidenceUse.SUPPLIED,)


@pytest.mark.parametrize("state,expected", [("supported", "supported"), ("unresolved", "insufficient_evidence"),
                                           ("conflicted", "insufficient_evidence")])
def test_original_state_not_reinterpreted(tmp_path, state, expected):
    f = fixture(tmp_path, state=state)
    result = f.project()
    row = decisions(result, c.Stage.ADJUDICATION)[0]
    assert row.outcome == expected
    assert bool(row.missing_predicates)
    if state == "conflicted":
        assert row.reason_code == c.ReasonCode.UNRESOLVED_CONTRADICTION


@pytest.mark.parametrize("status", list(CellStatus))
def test_terminal_cell_and_failed_verifier_axes(tmp_path, status):
    f = fixture(tmp_path, verifier_status=status)
    result = f.project()
    row = next(row for row in result.records if isinstance(row, c.VerificationRecord))
    assert row.status == status
    assert row.existing_r6_passed.value is (status == CellStatus.SUCCEEDED)
    if status != CellStatus.SUCCEEDED:
        assert row.blindness.passed.value is None
        assert row.confirmation_eligible.value is None
        assert all(item.coverage == c.SupportCoverage.UNKNOWN for item in row.predicates)
        assert row.diversity.provider_distinct.value is None


@pytest.mark.parametrize("status", [CellStatus.INVALID, CellStatus.TIMED_OUT, CellStatus.FAILED, CellStatus.NOT_LAUNCHED])
def test_failed_red_is_not_empty_success(tmp_path, status):
    f = fixture(tmp_path, red_status=status)
    result = f.project()
    population = next(row for row in result.coverage if row.population == c.Population.PROPOSALS)
    assert population.emitted == 0
    assert population.expected == (0 if status == CellStatus.NOT_LAUNCHED else None)
    assert any(row.outcome == status.value for row in decisions(result, c.Stage.CELL_EXECUTION))


@pytest.mark.parametrize("decision,reason,claim", [
    ("over_cap", "max_active_claims", False), ("rejected", "closed_vocabulary", False),
    ("over_cap", "claims_per_package_cap", True), ("rejected", "unresolvable_citation", True)])
def test_exact_preclaim_dispositions(tmp_path, decision, reason, claim):
    f = fixture(tmp_path)
    lane = deepcopy(f.inputs.lanes[0].value)
    capture = lane["proposal_audit"]["items"][0]
    capture.update(decision=decision, reason=reason)
    if not claim:
        capture["claim_id"] = None
    f.inputs = replace(f.inputs, lanes=(replace(f.inputs.lanes[0], value=lane),))
    result = f.project()
    row = next(row for row in result.records if isinstance(row, c.DecisionRecord)
               and row.context.subject.proposal_ref.value and row.original_outcome.value == decision)
    assert (row.context.subject.claim_id.value is not None) is claim
    assert row.context.subject.proposal_ref.value == "p1"
    assert row.context.explanation.text == reason


def test_duplicate_proposals_keep_exact_original_membership(tmp_path):
    f = fixture(tmp_path, duplicate=True)
    result = f.project()
    basis = next(row for row in result.records if isinstance(row, c.DecisionBasisRecord))
    assert {row.record_id.value for row in basis.context.origin_proposals} == {"p1", "p2"}
    population = next(row for row in result.coverage if row.population == c.Population.PROPOSALS)
    assert population.expected == population.emitted == 2
    assert len(f.inputs.projection.claims) == 1


def test_legacy_absence_is_explicit_and_never_guesses_membership(tmp_path):
    f = fixture(tmp_path, capture=False)
    f.inputs = replace(f.inputs, collection=None, lead_sources={})
    result = f.project()
    basis = next(row for row in result.records if isinstance(row, c.DecisionBasisRecord))
    assert basis.context.origin_proposals == ()
    assert "audit:proposal_membership_legacy_unrecorded" in basis.context.gap_ids
    assert decisions(result, c.Stage.PROPOSAL_NORMALIZATION) == []
    emitted = next(row for row in decisions(result, c.Stage.RED_DISCOVERY)
                   if row.context.subject.proposal_ref.value is not None)
    assert emitted.context.subject.claim_id.absence_reason == c.AbsenceReason.LEGACY_UNRECORDED
    assert [ref.record_id.value for ref in emitted.context.origin_proposals] == ["p1"]
    lead = next(row for row in decisions(result, c.Stage.RED_DISCOVERY)
                if row.context.subject.lead_id.value == "lead-1")
    assert [ref.record_id.value for ref in lead.context.origin_proposals] == ["p1"]
    coverage = next(row for row in result.coverage if row.population == c.Population.PROPOSALS)
    assert coverage.unavailable == 1 and coverage.reason == c.CoverageReason.LEGACY_UNAVAILABLE
    assert all(row.context.gap_ids == ("audit:lead_provenance_legacy_unrecorded",)
               for row in decisions(result, c.Stage.COLLECTION))


def test_reference_continuations_validate_and_publish(tmp_path):
    f = fixture(tmp_path, relation_count=260)
    result = f.project()
    assert result.continuations
    ref = publish_bundle(run_root=f.root, attempt_root=f.attempt, origin=f.inputs.origin, settings=f.settings,
                         records=result.records, coverage=result.coverage, continuations=result.continuations)
    manifest = c.from_document(json.loads((f.root / ref.path).read_bytes()), expected_origin=f.inputs.origin)
    assert sum(row.record_count for row in manifest.shards) == len(result.records)
    assert all((f.root / path).is_file() for path in result.continuations)


@pytest.mark.parametrize("mutation", ["policy", "head", "projection", "disabled", "record-limit"])
def test_projection_bindings_and_limits(tmp_path, mutation):
    f = fixture(tmp_path)
    error = IntegrityError
    if mutation == "policy":
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, projection_policy_sha256=digest("wrong")))
    elif mutation == "head":
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, ledger_head_sha256=digest("wrong")))
    elif mutation == "projection":
        f.inputs = replace(f.inputs, projection_document=replace(f.inputs.projection_document, value={}))
    else:
        f.settings = replace(f.settings, **({"enabled": False} if mutation == "disabled" else {"max_records": 1}))
        f.inputs = replace(f.inputs, origin=replace(f.inputs.origin, projection_policy_sha256=policy_sha256(f.settings)))
        error = AuditUnavailable
    with pytest.raises(error):
        f.project()


@pytest.mark.parametrize("text", [None, "", "ordinary rationale", "password=x", "ghp_secret",
                                "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----", "x" * 2500],
                         ids=["absent", "empty", "ordinary", "assignment", "token", "private-key", "bounded"])
def test_explanation_is_bounded_and_redacted(text):
    value = explanation(text)
    assert value.text is None or len(value.text) <= 2000
    if not text:
        assert labelled_text({"reason": text}, ("reason",)) == ""
    if text in ("password=x", "ghp_secret"):
        assert value.text != text
    if text and "PRIVATE KEY" in text:
        assert "SECRET" not in value.text


def test_secret_bearing_original_id_is_rejected_not_silently_rewritten():
    with pytest.raises(IntegrityError, match="secret-bearing"):
        link("ghp_secret")


def test_actual_nonempty_score_packages_are_unchanged_by_projection(tmp_path):
    f = fixture(tmp_path)
    scores = stages.score_claims(
        f.inputs.adjudications.value["adjudications"], f.inputs.projection, {"CWE-120": "critical"},
        f.attempt / "scoring/packages", f.attempt / "scoring/ledger.jsonl", "scoring.score_claims",
        SchemaSet(ROOT / SCHEMA_DIRECTORY))
    assert scores["scores"]
    source = document(f.root, f.inputs.scores.source.path, scores)
    f.inputs = replace(f.inputs, scores=source)
    paths = [f.attempt / "scoring/packages" / row["file"] for row in scores["scores"]]
    original = [path.read_bytes() for path in paths]
    result = f.project()
    assert [path.read_bytes() for path in paths] == original
    assert len(decisions(result, c.Stage.SCORING)) == len(scores["scores"])
    assert f.inputs.scores.value == scores


@pytest.mark.parametrize("value", [{"secret": "not-dumped"}, 1, []], ids=["object", "integer", "array"])
def test_allowlisted_narratives_reject_nontext_instead_of_dumping_objects(value):
    with pytest.raises(IntegrityError, match="not text"):
        labelled_text({"reason": value}, ("reason",))


def test_severity_retains_raw_value_and_basis_without_replacing_reported_severity(tmp_path):
    f = fixture(tmp_path)
    triage = {"leads": [{"lead_id": "lead-2", "assessed": {
        "value": "medium", "source": "rule_table", "basis": "rule-match",
        "rule_or_prompt_version": "rule/1", "reason": "class-level only"}}]}
    f.inputs = replace(f.inputs, triage=replace(f.inputs.triage, value=triage))
    result = f.project()
    row = decisions(result, c.Stage.SEVERITY_TRIAGE)[0]
    assert row.original_outcome.value == "medium"
    assert "basis rule-match" in row.context.explanation.text
    lead = next(row for row in decisions(result, c.Stage.COLLECTION)
                if row.context.subject.lead_id.value == "lead-2")
    assert "reported_severity low" in lead.context.explanation.text
    assert lead.original_outcome.value is None


def test_missing_severity_result_keeps_original_failure_code(tmp_path):
    f = fixture(tmp_path)
    triage = {"leads": [{"lead_id": "lead-2", "assessed": None,
                         "gap": {"code": "triage_failed:timeout", "reason": "model timed out"}}]}
    f.inputs = replace(f.inputs, triage=replace(f.inputs.triage, value=triage))
    row = decisions(f.project(), c.Stage.SEVERITY_TRIAGE)[0]
    assert row.outcome == "unknown"
    assert row.original_outcome.value == "triage_failed:timeout"
