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
    # A changed configuration is an independent variable: it is named, and the comparison proceeds.
    second["identity"]["configuration"] = "d" * 64
    compared = compare_trends(first, second, thresholds={"recall": 0})
    assert compared["status"] == "regression"
    assert compared["changed"] == ["implementation_sha", "configuration"] and compared["unknown"] == []
    # A different corpus is never comparable, whatever else agrees.
    other_corpus = deepcopy(second)
    other_corpus["identity"]["corpus"] = "e" * 64
    refused = compare_trends(first, other_corpus, thresholds={"recall": 0})
    assert (refused["status"], refused["reason"], refused["checks"]) == ("incomparable", "corpus_differs_or_unknown", {})
    changed["variants"]["full"]["rows"].pop()
    missing = trend(changed, cases, revision="2")
    assert missing["status"] == "missing_results"
    assert compare_trends(first, missing, thresholds={"recall": 0})["status"] == "missing_results"
    changed["variants"]["full"]["rows"].append(changed["variants"]["full"]["rows"][0])
    with pytest.raises(ValueError, match="duplicate"):
        trend(changed, cases)


def test_a_prompt_change_is_compared_and_named_with_its_metric_deltas():
    report, cases = fixture()
    baseline = trend(report, cases)
    reworded = deepcopy(report)
    for row in reworded["variants"]["full"]["rows"]:
        row["guidance_sha256"] = "f" * 64
    reworded["variants"]["full"]["rows"][0]["correct"] = False      # the one vulnerable case is now missed
    candidate = evaluation_trend(reworded, cases, variant="full", implementation_sha="1" * 40,
                                 model_sha256="c" * 64)
    compared = compare_trends(baseline, candidate, thresholds={"precision": 1, "recall": 0})
    assert compared["changed"] == ["prompts"] and compared["unknown"] == []
    assert compared["status"] == "regression" and compared["checks"] == {"precision": "passed", "recall": "regression"}
    assert compared["deltas"]["recall"] == -1.0
    improved = compare_trends(candidate, baseline, thresholds={"recall": 0})
    assert (improved["status"], improved["deltas"]["recall"], improved["changed"]) == ("passed", 1.0, ["prompts"])


def test_an_unknown_identity_is_reported_as_unknown_not_as_unchanged():
    report, cases = fixture()
    baseline = trend(report, cases)
    candidate = evaluation_trend(report, cases, variant="full", implementation_sha="2" * 40, model_sha256=None)
    compared = compare_trends(baseline, candidate, thresholds={"recall": 0})
    assert compared["status"] == "passed"
    assert compared["unknown"] == ["model"] and compared["changed"] == ["implementation_sha"]


@pytest.mark.parametrize("field, value, reason", [
    ("case_count", 99, "differs:case_count"), ("role", "red_team_analyst", "differs:role"),
    ("source_schema", "appsec-review/other/1", "differs:source_schema"), ("variant", "other", "differs:variant"),
], ids=["case_count", "role", "source_schema", "variant"])
def test_what_was_measured_must_agree(field, value, reason):
    report, cases = fixture()
    baseline = trend(report, cases)
    candidate = {**trend(report, cases, revision="2"), field: value}
    compared = compare_trends(baseline, candidate, thresholds={"recall": 0})
    assert (compared["status"], compared["reason"]) == ("incomparable", reason)


@pytest.mark.parametrize("thresholds", [{"castle": 0}, {"recall": 1.5}, {"recall": -0.1}, {"recall": True}],
                         ids=["unknown_metric", "above_one", "negative", "boolean"])
def test_invalid_thresholds_are_refused_before_any_comparison(thresholds):
    report, cases = fixture()
    with pytest.raises(ValueError, match="threshold"):
        compare_trends(trend(report, cases), trend(report, cases, revision="2"), thresholds=thresholds)


def test_run_identities_come_from_the_runs_frozen_records(tmp_path):
    from appsec_review.observability.quality import check_supplied_identities, run_identities
    run = tmp_path / "run-1"
    assert run_identities(run) == {"configuration": None, "prompts": None}
    configuration = run / "data" / "configuration"
    configuration.mkdir(parents=True)
    (configuration / "resolved.json").write_bytes(b'{"jobs": {}}')
    digest = hashlib.sha256(b'{"jobs": {}}').hexdigest()
    (configuration / "manifest.json").write_text(json.dumps({"resolved_sha256": digest}), encoding="utf-8")
    for name in ("b" * 64, "a" * 64, "not-a-bundle"):
        (run / "data" / "guidance" / name).mkdir(parents=True)
    recorded = run_identities(run)
    assert recorded == {"configuration": digest, "prompts": sha256_hex(["a" * 64, "b" * 64])}
    check_supplied_identities({"configuration": digest, "prompts": None}, recorded)
    with pytest.raises(ValueError, match="configuration identity"):
        check_supplied_identities({"configuration": "0" * 64}, recorded)
    # A manifest that no longer matches the file is not an identity.
    (configuration / "resolved.json").write_bytes(b'{"jobs": {"x": 1}}')
    assert run_identities(run)["configuration"] is None


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
