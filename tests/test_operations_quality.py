from copy import deepcopy
import hashlib
import json
from pathlib import Path

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


def test_pinned_recorded_fixture_thresholds():
    payload = (Path(__file__).parent / "fixtures/operations-quality.json").read_bytes()
    assert hashlib.sha256(payload).hexdigest() == "d7f98edbf8deb0458657ef4fb1f7fee264ee1ff7ee23afa76841955ba3331a33"
    document = json.loads(payload)
    report, _ = fixture()
    report["variants"]["full"]["rows"] = [{**row, "guidance_sha256": "a" * 64} for row in document["rows"]]
    first = trend(report, document["cases"])
    second = trend(report, document["cases"], "2")
    assert compare_trends(first, second, thresholds=document["thresholds"])["status"] == "passed"


def test_acceptance_adapter_uses_existing_detector_scorer():
    from appsec_review.acceptance.scoring import score
    from appsec_review.acceptance.scoring_model import KeyEntry, EntryKind, ScoringKey, Report
    from appsec_review.observability.quality import acceptance_trend
    key = ScoringKey({"identity": "fixture"}, (
        KeyEntry("defect", EntryKind.DEFECT, "fixture.c", "CWE-121", (5,), (1, 10)),))
    report = score(key, [Report("review", "fixture.c", 5, 5, "fixture", frozenset({"CWE-121"}))]).as_dict()
    observation = acceptance_trend(report, producer="review", implementation_sha="1" * 40,
                                   identities={name: "a" * 64 for name in ("corpus", "configuration", "prompts", "model")})
    assert observation["metrics"]["precision"]["value"] == report["producers"][0]["precision"]
    assert observation["metrics"]["recall"]["value"] == report["producers"][0]["recall"]
    assert observation["metrics"]["abstention_precision"] is None


def test_published_competence_results_preserve_retrieval_and_usage_provenance():
    from appsec_review.observability.quality import competence_trend
    from appsec_review.review.competence import REPORT_SCHEMA as COMPETENCE_SCHEMA
    report, cases = fixture()
    rows = report["variants"]["full"]["rows"]
    for row in rows:
        row.update(counts={"queries": 2, "denials": 1, "input_tokens": 999},
                   input_tokens=None, settings_sha256="b" * 64)
    recorded = {"schema": COMPETENCE_SCHEMA, "execution": "scripted", "role": report["role"],
                "cases_sha256": report["cases_sha256"], "settings_sha256": "b" * 64,
                "configuration_sha256": "d" * 64, "model": {"provider": "fixture", "model": "recorded"},
                "rows": rows}
    result = competence_trend(recorded, cases, implementation_sha="1" * 40)
    assert result["metrics"]["retrieval_queries"]["value"] == 6
    assert result["metrics"]["retrieval_denials"]["value"] == 3
    assert result["metrics"]["retrieval_failure"]["value"] is None
    assert result["metrics"]["tokens_per_correct_resolution"] is None
    assert result["identity"]["model"] == sha256_hex(recorded["model"])
    live = competence_trend({**recorded, "execution": "live"}, cases, implementation_sha="2" * 40)
    assert compare_trends(result, live, thresholds={"recall": 0})["status"] == "incomparable"
    rows[0]["settings_sha256"] = "e" * 64
    mixed = competence_trend(recorded, cases, implementation_sha="2" * 40)
    assert mixed["identity"]["configuration"] is None
    assert compare_trends(result, mixed, thresholds={"recall": 0})["status"] == "incomparable"
    with pytest.raises(ValueError, match="unsupported"):
        competence_trend({**recorded, "role": "unsupported-role"}, cases, implementation_sha="2" * 40)
