"""The evidence header/body partition and the body content identity of a handoff."""
from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.interchange import HANDOFF_SCHEMA
from appsec_review.runtime import equivalence
from appsec_review.runtime.equivalence import (
    BODY_FIELDS, HEADER_FIELDS, artifact_content, content_sha256, handoff_body, normalise_attempt_paths,
)

ATTEMPT = "data/jobs/job_x/attempts/attempt_0003"
SHA = "a" * 64


def handoff(attempt_id="attempt_0003", **overrides):
    attempt = f"data/jobs/job_x/attempts/{attempt_id}"
    value = {
        "schema": HANDOFF_SCHEMA, "run_id": "2026-11-13-0001", "job_id": "job_x", "attempt_id": attempt_id,
        "status": "ACCEPTED", "completion_status": "SUCCEEDED", "execution_status": "SUCCEEDED",
        "outputs": {"work.only": {"artifact": {"path": f"{attempt}/out.json", "sha256": SHA, "size_bytes": 3},
                                  "terminal_status": "SUCCEEDED"}},
        "artifacts": [
            {"path": f"{attempt}/out.json", "sha256": SHA, "size_bytes": 3},
            {"path": f"{attempt}/claim.json", "sha256": "b" * 64, "size_bytes": 9},
            {"path": f"{attempt}/outcomes.json", "sha256": "c" * 64, "size_bytes": 9},
            {"path": f"{attempt}/steps/work/tasks/only/result.json", "sha256": "d" * 64, "size_bytes": 9},
            {"path": f"{attempt}/shared/fixture/{'e' * 64}.json", "sha256": "e" * 64, "size_bytes": 9},
            {"path": "data/configuration/resolved.json", "sha256": "f" * 64, "size_bytes": 9},
        ],
        "upstream_handoff_sha256": {"job_up": "1" * 64}, "resolved_config_sha256": "2" * 64,
        "job_config_sha256": "3" * 64, "source_fingerprint": "none", "target_snapshot": "none",
        "evidence_target_snapshot": "none", "implementation_identity": "impl", "schema_identity": "s",
        "validation_identity": "v", "tool_identity": {"python": "3.12"}, "input_identity": None,
        "input_manifest": None, "dataset_contract_sha256": "4" * 64, "input_set_sha256": "5" * 64,
        "coverage": {"disposition": "complete", "gap_count": 0, "retry_required": False},
        "outcomes": {"path": f"{attempt}/outcomes.json", "sha256": "c" * 64, "size_bytes": 9},
        "resolving_paths": {"attempt": attempt, "result": f"{attempt}/result.json"},
        "started_at": "2026-11-13T00:00:00+00:00", "completed_at": "2026-11-13T00:00:01+00:00",
    }
    value.update(overrides)
    return value


def test_the_partition_covers_every_handoff_field_exactly_once() -> None:
    assert HEADER_FIELDS & set(BODY_FIELDS) == set()
    document = handoff()
    body_from_document = {"outputs", "coverage", "completion_status", "execution_status",
                          "dataset_contract_sha256", "evidence_target_snapshot"}
    assert set(document) - HEADER_FIELDS == body_from_document


def test_two_attempts_with_the_same_evidence_hash_equal_whatever_their_attempt_id() -> None:
    first = handoff_body(handoff("attempt_0001"), gaps=[], upstream_content_sha256={"job_up": "9" * 64})
    second = handoff_body(handoff("attempt_0007", started_at="2026-11-14T00:00:00+00:00"),
                          gaps=[], upstream_content_sha256={"job_up": "9" * 64})
    assert first == second and content_sha256(first) == content_sha256(second)
    assert first["outputs"]["work.only"]["artifact"]["path"] == "data/jobs/job_x/attempts/@/out.json"


@pytest.mark.parametrize("change", ["output", "coverage", "status", "gap", "upstream", "contract", "target"])
def test_every_body_field_changes_the_identity(change: str) -> None:
    base = handoff_body(handoff(), gaps=[], upstream_content_sha256={"job_up": "9" * 64})
    overrides, gaps, upstream = {}, [], {"job_up": "9" * 64}
    if change == "output":
        overrides["outputs"] = {"work.only": {"terminal_status": "SUCCEEDED"}}
    elif change == "coverage":
        overrides["coverage"] = {"disposition": "partial", "gap_count": 1, "retry_required": False}
    elif change == "status":
        overrides["completion_status"] = "COMPLETED_WITH_GAPS"
    elif change == "gap":
        gaps = [{"schema": "appsec-review/producer-gap/1", "code": "x"}]
    elif change == "upstream":
        upstream = {"job_up": "8" * 64}
    elif change == "contract":
        overrides["dataset_contract_sha256"] = "7" * 64
    else:
        overrides["evidence_target_snapshot"] = overrides["target_snapshot"] = "abc"
    changed = handoff_body(handoff(**overrides), gaps=gaps, upstream_content_sha256=upstream)
    assert content_sha256(changed) != content_sha256(base)


def test_bookkeeping_and_run_level_artifacts_are_not_evidence_content() -> None:
    pairs = artifact_content(handoff()["artifacts"], ATTEMPT)
    assert pairs == [[SHA, 3]]
    with_evidence = handoff()["artifacts"] + [{"path": f"{ATTEMPT}/extra/report.sarif", "sha256": "0" * 64, "size_bytes": 1}]
    assert artifact_content(with_evidence, ATTEMPT) == [["0" * 64, 1], [SHA, 3]]
    for excluded in ("status.json", "published.json", "result.json", "revalidation.json", "logs/events.jsonl",
                     "events/x.jsonl", "steps/work/lifecycle.json"):
        extra = handoff()["artifacts"] + [{"path": f"{ATTEMPT}/{excluded}", "sha256": "0" * 64, "size_bytes": 1}]
        assert artifact_content(extra, ATTEMPT) == [[SHA, 3]], excluded


def test_normalisation_touches_only_this_attempt_and_every_string_depth() -> None:
    value = {"a": [f"{ATTEMPT}/x", "data/jobs/job_x/attempts/attempt_0001/x", 3], "b": {"c": f"{ATTEMPT}/y"}}
    assert normalise_attempt_paths(value, "attempt_0003") == {
        "a": ["data/jobs/job_x/attempts/@/x", "data/jobs/job_x/attempts/attempt_0001/x", 3],
        "b": {"c": "data/jobs/job_x/attempts/@/y"}}


def test_body_hash_names_its_schema_and_refuses_a_foreign_shape() -> None:
    from appsec_review.storage import canonical_json
    body = handoff_body(handoff(), gaps=[], upstream_content_sha256={})
    assert content_sha256(body) == __import__("hashlib").sha256(
        canonical_json({"schema": "appsec-review/handoff-content/1", "body": body})).hexdigest()
    with pytest.raises(ValueError, match="documented partition"):
        content_sha256({**body, "attempt_id": "attempt_0001"})


def test_a_pinned_upstream_without_an_identity_yields_no_identity(monkeypatch, tmp_path: Path) -> None:
    upstreams = {"job_up": {"content_sha256": "9" * 64}, "job_old": {}}
    monkeypatch.setattr("appsec_review.retrieval.core._accepted_handoff",
                        lambda root, producer, digest: (upstreams[producer], tmp_path))
    assert equivalence.pinned_upstream_content(tmp_path, {"job_up": "1" * 64}) == {"job_up": "9" * 64}
    assert equivalence.pinned_upstream_content(tmp_path, {"job_up": "1" * 64, "job_old": "2" * 64}) is None
    assert equivalence.handoff_content_sha256(
        tmp_path, handoff(upstream_handoff_sha256={"job_old": "2" * 64}), gaps=[]) is None
    assert equivalence.handoff_content_sha256(tmp_path, handoff(), gaps=[]) == content_sha256(
        handoff_body(handoff(), gaps=[], upstream_content_sha256={"job_up": "9" * 64}))
