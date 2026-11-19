"""The accepted-review loader's agreement rule between a PoC candidate and its finding package."""
import pytest

from appsec_review.jobs.accepted_review import poc_candidate_agrees
from appsec_review.jobs.job_inference_security_review.stages import JUDGE_NOT_CONVENED

SHA = "a" * 64


def candidate(**overrides):
    row = {"claim_id": "claim-1", "state": "supported", "judge_verdict": "red_correct",
           "finding_package": {"finding_package_id": "finding-1", "sha256": SHA}}
    row.update(overrides)
    return row


def package(**overrides):
    row = {"finding_package_id": "finding-1", "claim_id": "claim-1", "state": "supported",
           "judge_verdict": {"verdict": "red_correct", "judges": []}}
    row.update(overrides)
    return row


def test_judged_package_agrees_with_a_candidate_carrying_the_same_verdict():
    assert poc_candidate_agrees(candidate(), package(), SHA, judge_cells=())


def test_unjudged_package_agrees_only_with_a_not_convened_candidate():
    # Run 2026-11-17-0006: a supported claim no judge saw was listed as not_convened and the loader rejected it.
    assert poc_candidate_agrees(candidate(judge_verdict=JUDGE_NOT_CONVENED), package(judge_verdict=None), SHA,
                                judge_cells=())
    assert not poc_candidate_agrees(candidate(judge_verdict="red_correct"), package(judge_verdict=None), SHA,
                                    judge_cells=())


def test_judged_package_rejects_a_not_convened_candidate():
    assert not poc_candidate_agrees(candidate(judge_verdict=JUDGE_NOT_CONVENED), package(), SHA, judge_cells=())


@pytest.mark.parametrize("field, value", sorted({
    "claim_id": "claim-2", "state": "confirmed", "judge_verdict": "partly"}.items()))
def test_any_restated_field_must_match(field, value):
    assert not poc_candidate_agrees(candidate(**{field: value}), package(), SHA, judge_cells=())


def test_package_identity_and_accepted_digest_are_required():
    assert not poc_candidate_agrees(candidate(), None, SHA, judge_cells=())
    assert not poc_candidate_agrees(candidate(), package(), None, judge_cells=())
    assert not poc_candidate_agrees(candidate(), package(), "b" * 64, judge_cells=())
