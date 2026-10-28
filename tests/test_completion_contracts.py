from __future__ import annotations

import pytest

from appsec_review.jobs.completion_contracts import (
    FindingBinding, nonexecution_assurance, verify_nonexecution_assurance,
)
from appsec_review.review.models import IntegrityError


def test_finding_binding_round_trips_exact_identity() -> None:
    binding = FindingBinding("claim-one", "finding-one", "a" * 64)
    assert FindingBinding.from_mapping(binding.as_dict()) == binding


@pytest.mark.parametrize("change", [
    {"claim_id": ""}, {"claim_id": True}, {"finding_package_id": ""},
    {"finding_package_id": "x" * 201}, {"sha256": "A" * 64}, {"sha256": "../escape"},
    {"sha256": "a" * 63}, {"extra": "not permitted"},
])
def test_finding_binding_rejects_malformed_or_ambiguous_identity(change) -> None:
    value = {"claim_id": "claim-one", "finding_package_id": "finding-one", "sha256": "a" * 64, **change}
    with pytest.raises(IntegrityError):
        FindingBinding.from_mapping(value)


def test_assurance_is_explicit_and_does_not_share_mutable_state() -> None:
    first = nonexecution_assurance()
    verify_nonexecution_assurance(first)
    first["runtime_verified"] = True
    verify_nonexecution_assurance(nonexecution_assurance())
    with pytest.raises(IntegrityError):
        verify_nonexecution_assurance(first)


@pytest.mark.parametrize("change", [
    {"execution": "executed"}, {"runtime_verified": True}, {"runtime_verified": 0},
    {"result_id": "result-not-real"},
])
def test_compile_only_assurance_rejects_runtime_claims(change) -> None:
    with pytest.raises(IntegrityError):
        verify_nonexecution_assurance({**nonexecution_assurance(), **change})


def test_compile_only_assurance_requires_the_null_result_field() -> None:
    record = nonexecution_assurance()
    del record["result_id"]
    with pytest.raises(IntegrityError):
        verify_nonexecution_assurance(record)


@pytest.mark.parametrize("record", [
    None, [], "not an assurance", True,
    {**nonexecution_assurance(), "executed": True},
])
def test_compile_only_assurance_rejects_nonrecords_and_extra_fields(record) -> None:
    with pytest.raises(IntegrityError):
        verify_nonexecution_assurance(record)
