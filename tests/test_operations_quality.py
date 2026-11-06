from copy import deepcopy

import pytest

from appsec_review.observability.quality import evaluation_trend, compare_trends, publish_trend
from appsec_review.review.evaluation import REPORT_SCHEMA
from appsec_review.review.identity import sha256_hex


def fixture():
    cases = [{"id": "v", "expected": "vulnerable"}, {"id": "s", "expected": "safe"},
             {"id": "a", "expected": "abstain"}]
    rows = [{"case_id": case["id"], "status": "completed", "decision": case["expected"],
             "correct": True, "unsupported": 0, "conclusions": int(case["expected"] != "abstain"),
             "duplicates": 0, "input_tokens": 10, "output_tokens": 5, "guidance_sha256": "a" * 64}
            for case in cases]
    report = {"schema": REPORT_SCHEMA, "cases_sha256": sha256_hex(cases), "settings_sha256": "b" * 64,
              "role": "independent_verifier", "variants": {"full": {"rows": rows}}}
    return report, cases


def trend(report, cases, revision="1"):
    return evaluation_trend(report, cases, variant="full", implementation_sha=revision * 40,
                            model_sha256="c" * 64)


def test_trends_use_real_scorer_and_publish_immutable_duplicates(tmp_path):
    report, cases = fixture()
    first = trend(report, cases)
    assert first["metrics"]["precision"]["value"] == first["metrics"]["recall"]["value"] == 1
    assert first["metrics"]["abstention_precision"]["value"] == 1
    assert first["metrics"]["retrieval_failure"]["value"] is None
    assert publish_trend(tmp_path, first)["status"] == "published"
    assert publish_trend(tmp_path, first)["status"] == "duplicate"
    assert compare_trends(first, first, thresholds={"recall": 0})["status"] == "duplicate"
    second = trend(report, cases, revision="2")
    assert compare_trends(first, second, thresholds={"precision": 0, "recall": 0})["status"] == "passed"


def test_thresholds_incomparability_missing_results_and_duplicates():
    report, cases = fixture()
    first = trend(report, cases)
    changed = deepcopy(report)
    changed["variants"]["full"]["rows"][0]["correct"] = False
    second = trend(changed, cases, revision="2")
    assert compare_trends(first, second, thresholds={"recall": 0})["status"] == "regression"
    second["identity"]["configuration"] = "d" * 64
    assert compare_trends(first, second, thresholds={"recall": 0})["status"] == "incomparable"
    changed["variants"]["full"]["rows"].pop()
    missing = trend(changed, cases, revision="2")
    assert missing["status"] == "missing_results"
    assert compare_trends(first, missing, thresholds={"recall": 0})["status"] == "missing_results"
    changed["variants"]["full"]["rows"].append(changed["variants"]["full"]["rows"][0])
    with pytest.raises(ValueError, match="duplicate"):
        trend(changed, cases)


def test_empty_denominators_and_unknown_usage_are_explicit():
    report, cases = fixture()
    for row in report["variants"]["full"]["rows"]:
        row.update(decision="abstain", input_tokens=None, output_tokens=None, conclusions=0)
    result = trend(report, cases)
    assert result["metrics"]["precision"]["status"] == "empty_denominator"
    assert result["metrics"]["tokens_per_correct_resolution"] is None
    assert result["metrics"]["usage_complete"] is False
