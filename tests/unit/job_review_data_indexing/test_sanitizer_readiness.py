"""Sanitizer summary permission, lineage and byte custody at the indexing boundary."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from appsec_review.indexing.products import sanitizer_readiness
from appsec_review.jobs.job_review_data_indexing.job import CONTRACT, JOB_ID, sanitizer_status
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.unit.job_sanitizer_build.test_readiness_publication import publish_sanitizer


def _context(case, *, contract=CONTRACT, supplied=True):
    return SimpleNamespace(
        run_root=case.root, config=SimpleNamespace(job_id=JOB_ID), contract=contract,
        upstream_handoffs={"job_sanitizer_build": file_sha256(case.handoff)} if supplied else {})


@pytest.mark.parametrize("mutation", ["run_id", "attempt_id", "source_fingerprint", "schema", "lineage", "duplicate"])
def test_summary_cannot_change_accepted_identity(tmp_path, mutation):
    def corrupt(summary):
        if mutation == "lineage":
            summary["upstream"]["language_build_handoff_sha256"] = "0" * 64
        elif mutation == "duplicate":
            summary["omitted_units"].append(summary["units"][0])
        else:
            summary[mutation] = "foreign"

    case = publish_sanitizer(tmp_path, mutate_summary=corrupt)
    with input_read_scope(_context(case)), pytest.raises(ValueError, match="sanitizer summary"):
        sanitizer_status(case.root, case.snapshot)


def test_summary_tampering_is_not_hidden_as_unavailable(tmp_path):
    case = publish_sanitizer(tmp_path)
    summary = case.root / case.outputs["acceptance.publish_handoff"]["artifact"]["path"]
    summary.write_text("{}")
    with input_read_scope(_context(case)), pytest.raises(ValueError):
        sanitizer_status(case.root, case.snapshot)


def test_handoff_permission_does_not_grant_summary_permission(tmp_path):
    case = publish_sanitizer(tmp_path)
    contract = replace(CONTRACT, inputs=tuple(item for item in CONTRACT.inputs
                       if not (item.producer == "job_sanitizer_build" and item.output_kind == "sanitizer_build_summary")))
    with pytest.raises(ValueError, match="undeclared"):
        with input_read_scope(_context(case, contract=contract)):
            sanitizer_status(case.root, case.snapshot)


def test_disabled_and_unsupplied_ignore_available_pointer_but_pin_survives_pointer_change(tmp_path):
    case = publish_sanitizer(tmp_path)
    atomic_json(case.handoff.parent.parent.parent / "latest.json", {
        "handoff_path": "data/jobs/job_sanitizer_build/attempts/attempt_9999/handoff.json",
        "handoff_sha256": "f" * 64})
    with input_read_scope(_context(case)) as reads:
        accepted = sanitizer_status(case.root, case.snapshot)
    assert accepted["handoff_sha256"] == file_sha256(case.handoff)
    observed = [read for read in reads.document()["reads"] if read["output_kind"] == "sanitizer_build_summary"]
    assert len(observed) == 1
    assert observed[0]["sha256"] == case.outputs["acceptance.publish_handoff"]["artifact"]["sha256"]
    with input_read_scope(_context(case, supplied=False)) as reads:
        disabled = sanitizer_status(case.root, case.snapshot, disabled=True)
        absent = sanitizer_status(case.root, case.snapshot)
    assert reads.document()["reads"] == []
    for state, reason in ((disabled, "disabled"), (absent, "no admitted")):
        derived = sanitizer_readiness(case.snapshot, state, 10)
        assert not derived.entities and derived.coverage[0][1] == "unavailable"
        assert reason in derived.gaps[0]
