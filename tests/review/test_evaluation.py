from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet, SCHEMA_DIRECTORY
from appsec_review.review import evaluation as ev

ROOT = Path(__file__).resolve().parents[2]
CASES = ev.load_cases(ROOT / "tests" / "fixtures" / "review_guidance" / "cases.json")
SCHEMAS = SchemaSet(ROOT / SCHEMA_DIRECTORY)


def verdict(case, *, disposition=None, cites=None, gap=True):
    expected = case["expected"]
    disposition = disposition or {"vulnerable": "supported", "safe": "contradicted",
                                   "abstain": "insufficient_evidence"}[expected]
    result = {"disposition": disposition, "per_predicate": {
        "missing_or_ineffective_guard": {
            "stance": "contradicts" if disposition == "contradicted" else "supports",
            "cites": case["decisive_labels"] if cites is None else cites}}}
    if expected == "abstain" and gap:
        result["evidence_requests"] = [{
            "predicate": "missing_or_ineffective_guard", "requested_kind": "source_line",
            "anchors": ["S1"], "question": "What does the missing implementation enforce?"}]
    return {"action": "final", "result": result}


def row(case, **changes):
    return {"case_id": case["id"], "proposal": verdict(case),
            **ev.assess(case, "independent_verifier", verdict(case), SCHEMAS),
            "input_tokens": 90, "output_tokens": 10, **changes}


def test_cases_are_paired_source_grounded_and_answer_keys_are_held_out():
    families = {case["family"] for case in CASES}
    assert len(families) == 5
    for family in families:
        assert {case["expected"] for case in CASES if case["family"] == family} == ev.OUTCOMES
    for case in CASES:
        for role in ev.ROLES:
            payload = ev.task_input(case, role)
            assert not {"expected", "decisive_labels", "family", "id"} & payload.keys()
            encoded = json.dumps(payload)
            assert '"expected"' not in encoded and '"decisive_labels"' not in encoded
            assert all(source["sha256"] and source["lines"][0].startswith("1|")
                       for source in payload["package"]["source"])


def test_metrics_use_all_cases_and_do_not_turn_missing_results_into_abstentions():
    rows = [row(case) for case in CASES]
    metrics = ev.score(CASES, rows, "independent_verifier")
    assert metrics["recall"] == {"numerator": 5, "denominator": 5, "value": 1}
    assert metrics["abstention_precision"]["value"] == 1
    assert metrics["abstention_recall"]["value"] == 1
    assert metrics["false_refutation_rate"]["value"] == 0
    assert metrics["unsupported_conclusion_rate"]["value"] == 0
    assert metrics["tokens_per_correct_resolution"]["value"] == 100
    assert metrics["monetary_cost"] is None
    missing = ev.score(CASES, [], "independent_verifier")
    assert missing["recall"]["value"] == 0 and missing["gaps"] == 15
    assert missing["abstention_recall"]["value"] == 0
    assert missing["abstention_precision"]["value"] is None


def test_false_refutation_unsupported_citations_and_empty_abstention_are_not_success():
    vulnerable, _, incomplete = CASES[:3]
    false = ev.assess(vulnerable, "independent_verifier",
                      verdict(vulnerable, disposition="contradicted"), SCHEMAS)
    assert not false["correct"] and false["unsupported"] == 1
    ungrounded = ev.assess(vulnerable, "independent_verifier", verdict(vulnerable, cites=["S99"]), SCHEMAS)
    assert not ungrounded["correct"] and not ungrounded["grounded"]
    incomplete_citations = ev.assess(vulnerable, "independent_verifier", verdict(vulnerable, cites=["S1"]), SCHEMAS)
    assert not incomplete_citations["correct"]
    assert not ev.assess(incomplete, "independent_verifier", verdict(incomplete, gap=False), SCHEMAS)["correct"]
    metrics = ev.score(CASES, [row(vulnerable, **false)], "independent_verifier")
    assert metrics["false_refutation_rate"]["numerator"] == 1


def test_blue_cannot_be_scored_as_a_confirmation():
    case = CASES[0]
    result = ev.assess(case, "blue_team_refuter", {
        "action": "final", "result": {"stance": "supports", "predicate": "security_impact", "cites": ["S1"]}}, SCHEMAS)
    assert result["status"] == "invalid"
    assert ev.score(CASES, [], "blue_team_refuter")["recall"] is None


def test_duplicate_requests_and_missing_usage_are_explicit():
    with pytest.raises(ValueError, match="duplicate"):
        ev.score(CASES, [row(CASES[0]), row(CASES[0])], "independent_verifier")
    metrics = ev.score(CASES, [row(CASES[0], output_tokens=None)], "independent_verifier")
    assert metrics["tokens_per_correct_resolution"] is None and not metrics["usage_complete"]


def test_red_duplicates_and_unrelated_conclusions_are_counted_separately():
    from tests.review.test_compact import claim

    case = CASES[0]
    supported = claim(cwe=case["cwe"], security_predicate=case["condition"],
                      support={"affected_construct": ["S1"], "security_impact": ["S2"]}, counter={}, missing=[])
    duplicate = {**supported, "id": "c2"}
    unrelated = {**supported, "id": "c3", "cwe": "CWE-89", "security_predicate": "sql_injection"}
    result = ev.assess(case, "red_team_analyst", {
        "action": "final", "result": {"claims": [supported, duplicate, unrelated]}}, SCHEMAS)
    assert result["status"] == "completed" and result["correct"]
    assert result["duplicates"] == 1 and result["unsupported"] == 1 and result["conclusions"] == 3
    no_claim = ev.assess(CASES[1], "red_team_analyst", {
        "action": "final", "result": {"claims": [], "no_claim": ["L1"]}}, SCHEMAS)
    assert no_claim["decision"] == "no_claim" and not no_claim["correct"]


def test_live_calls_require_explicit_opt_in_and_never_overwrite_a_run(tmp_path):
    settings = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
    with pytest.raises(ValueError, match="--live"):
        ev.run_evaluation(ROOT, CASES, settings, tmp_path / "new", role="independent_verifier")
    assert not (tmp_path / "new").exists()
    with pytest.raises(FileExistsError):
        ev.run_evaluation(ROOT, CASES, settings, tmp_path, role="independent_verifier", transport=lambda *_: None)


def test_evaluation_records_errors_and_enforces_existing_budget(tmp_path):
    settings = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
    settings = replace(settings, budgets=replace(settings.budgets, max_model_turns=1))
    calls = []

    def failing(request, *, timeout_seconds):
        calls.append(request)
        raise TimeoutError("fixture transport timeout")

    report = ev.run_evaluation(ROOT, CASES[:2], settings, tmp_path / "evaluation",
                               role="independent_verifier", variants=("full",), transport=failing)
    rows = report["variants"]["full"]["rows"]
    assert len(calls) == 1
    assert rows[0]["status"] == "error" and rows[1]["status"] == "not_launched"
    assert report["variants"]["full"]["metrics"]["gaps"] == 2
    assert (tmp_path / "evaluation" / "data" / "evaluation" / "report.json").is_file()
    assert json.loads((tmp_path / "evaluation" / "data" / "jobs" / "job_inference_security_review"
                       / "budget" / "budget.json").read_text())["model_turns"] == 1


def test_real_guidance_variants_are_hash_distinct_and_keep_governing_rules():
    case = CASES[0]
    payload = ev.task_input(case, "independent_verifier")
    full, prompt = ev._guidance(ROOT, case, "independent_verifier", payload, "full")
    ablated = ev.procedure_variant(full, "without_procedures")
    assert full["sha256"] != ablated["sha256"]
    assert full["sections"][0] == ablated["sections"][0]
    assert next(section for section in full["sections"] if section["name"] == "procedures")["items"]
    assert not next(section for section in ablated["sections"] if section["name"] == "procedures")["items"]
    assert prompt


def test_all_real_case_routes_compose_without_answer_keys():
    for case in CASES:
        for role in ev.ROLES:
            bundle, prompt = ev._guidance(ROOT, case, role, ev.task_input(case, role), "full")
            assert bundle["sha256"]
            assert '"expected"' not in prompt and '"decisive_labels"' not in prompt


def test_pair_run_uses_same_inputs_models_and_preserves_raw_responses(tmp_path):
    settings = load_config(ROOT / "appsec-review.toml").job("job_inference_security_review").typed_settings
    calls = []

    def replay(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult(verdict(CASES[0]), input_tokens=12, output_tokens=4)

    report = ev.run_evaluation(ROOT, CASES[:1], settings, tmp_path / "evaluation",
                               role="independent_verifier", transport=replay)
    assert len(calls) == 2
    assert calls[0].task_input == calls[1].task_input and calls[0].model == calls[1].model
    assert calls[0].guidance_bundle_sha256 != calls[1].guidance_bundle_sha256
    assert all(value["rows"][0]["proposal"] == verdict(CASES[0]) for value in report["variants"].values())
    assert all(value["metrics"]["recall"]["value"] == 1 for value in report["variants"].values())


def test_case_loader_rejects_output_path_traversal(tmp_path):
    cases = deepcopy(CASES[:1])
    cases[0]["id"] = "../escape"
    path = tmp_path / "cases.json"
    path.write_text(json.dumps({"schema": ev.CASE_SCHEMA, "cases": cases}))
    with pytest.raises(ValueError):
        ev.load_cases(path)


def test_offline_cli_recomputes_raw_answers_instead_of_trusting_saved_scores(tmp_path, capsys):
    forged = row(CASES[0], correct=True)
    forged["proposal"] = verdict(CASES[0], disposition="contradicted")
    report = {"schema": ev.REPORT_SCHEMA, "cases_sha256": ev.sha256_hex(CASES), "role": "independent_verifier",
              "variants": {"full": {"rows": [forged], "metrics": {"recall": 1}}}}
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    assert ev.main(["--root", str(ROOT), "--responses", str(path)]) == 0
    metrics = json.loads(capsys.readouterr().out)["full"]
    assert metrics["recall"]["value"] == 0 and metrics["false_refutation_rate"]["numerator"] == 1
