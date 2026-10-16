from __future__ import annotations

import json
from pathlib import Path

from appsec_review.acceptance.diff import diff_job_outputs, failing
from appsec_review.acceptance.normalize import Masks, gap_summary, locate_attempt, normalize_job_output
from tests.acceptance.support import RUN_ID, make_job


def _masks(run_id: str = RUN_ID) -> Masks:
    return Masks.for_run(run_id, runs_roots=["/opt/app/runs"], repository_roots=["/opt/app"],
                         target_roots=["/opt/app/targets/appsec-multi-vuln"])


def test_masks_cover_the_phase4_volatile_list() -> None:
    masks = _masks()
    text = masks.text(
        f"/opt/app/runs/{RUN_ID}/data/jobs/job_x/attempts/attempt_0003/out at 2026-10-16T20:21:14.04+00:00 "
        "image sha256:" + "b" * 64 + " digest " + "c" * 64 + " dagster e4811d8c-b3fe-4676-86f9-f84cfe452751 "
        "/opt/app/targets/appsec-multi-vuln/src/a.c .appsec-review-build-scratch.T70GHa targetZ0X9iP "
        "/tmp/tmpab12cd34 .tmp-k3j2h1l9 run 2026-10-17-0001")
    for volatile in (RUN_ID, "attempt_0003", "2026-10-16T", "b" * 64, "c" * 64, "e4811d8c", "/opt/app",
                     "T70GHa", "Z0X9iP", "tmpab12cd34", "k3j2h1l9", "2026-10-17-0001"):
        assert volatile not in text
    assert "<target>/src/a.c" in text and "<run>/data/jobs/job_x/attempts/<attempt>/out" in text
    # Ordinary words that merely start like scratch prefixes survive.
    assert masks.text("targeting the target catalog") == "targeting the target catalog"


def test_normalized_outputs_of_two_runs_differ_only_in_volatile(tmp_path: Path) -> None:
    gaps = ["no other CI definitions discovered", "no other CI definitions discovered",
            {"path": ".git", "reason": "excluded_directory"}]
    findings = [{"id": "CHECK_RPATH", "path": "case-035", "severity": "medium"}]
    first = make_job(tmp_path / RUN_ID, "job_x", dagster_run_id="11111111-1111-1111-1111-111111111111",
                     gaps=gaps, findings=findings)
    second = make_job(tmp_path / "2026-10-17-0001", "job_x", dagster_run_id="22222222-2222-2222-2222-222222222222",
                      gaps=gaps, findings=findings, started="2026-10-17T01:00:00+00:00",
                      artifact_text="{\"items\": [1, 2] }")
    expected = normalize_job_output(tmp_path / RUN_ID, "job_x", _masks(), attempt_root=first)
    actual = normalize_job_output(tmp_path / "2026-10-17-0001", "job_x", _masks("2026-10-17-0001"),
                                  attempt_root=second)
    assert expected["gaps"] == [
        {"unit": "work.scan", "gap": "no other CI definitions discovered", "count": 2},
        {"unit": "work.scan", "gap": {"path": ".git", "reason": "excluded_directory"}, "count": 1}]
    assert expected["findings"][0]["record"]["id"] == "CHECK_RPATH"
    assert gap_summary(expected)[0] == ("no other CI definitions discovered", 2)
    output = expected["outputs"]["work.scan"]
    assert output["duration_ms"] == "<duration>" and output["image_id"] == "<image_id>"
    assert output["path"] == "<run>/data/jobs/job_x/attempts/<attempt>/artifacts/out.json"
    differences = diff_job_outputs(expected, actual)
    assert differences and all(item.kind == "volatile" for item in differences)
    assert failing(differences) == []


def test_diff_classifies_status_gap_finding_and_coverage_changes(tmp_path: Path) -> None:
    base = make_job(tmp_path / RUN_ID, "job_x", dagster_run_id="d1", gaps=["gap a"],
                    findings=[{"id": "F1"}])
    expected = normalize_job_output(tmp_path / RUN_ID, "job_x", _masks(), attempt_root=base)
    actual = json.loads(json.dumps(expected))
    actual["status"] = "COMPLETED_WITH_GAPS"
    actual["gaps"] = [{"unit": "work.scan", "gap": "gap b", "count": 1}]
    actual["findings"] = [{"unit": "work.scan", "source": "findings", "record": {"id": "F2"}, "count": 1}]
    actual["units"]["work.scan"]["status"] = "PARTIAL"
    actual["artifacts"] = []
    kinds = {item.kind for item in diff_job_outputs(expected, actual)}
    assert {"job-status", "gap-added", "gap-removed", "finding-added", "finding-removed", "coverage"} <= kinds
    assert diff_job_outputs(expected, None)[0].kind == "job-status"


def test_locate_attempt_prefers_the_dagster_run_then_the_accepted_pointer(tmp_path: Path) -> None:
    attempt = make_job(tmp_path / RUN_ID, "job_x", dagster_run_id="run-a")
    assert locate_attempt(tmp_path / RUN_ID, "job_x", "run-a") == attempt
    assert locate_attempt(tmp_path / RUN_ID, "job_x", "unknown") == attempt
    assert locate_attempt(tmp_path / RUN_ID, "job_missing") is None
    assert normalize_job_output(tmp_path / RUN_ID, "job_missing", _masks())["status"] == "MISSING"
