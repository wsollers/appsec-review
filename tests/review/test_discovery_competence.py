"""Scripted discovery at the real cell boundary; no detector-effectiveness claims."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from appsec_review.guidance import verify_bundle
from appsec_review.inference import ModelResult
from appsec_review.inference.request import review_prompt
from appsec_review.review.competence import run_competence_case
from appsec_review.review.evaluation import load_cases
from appsec_review.review.models import CellStatus, GapClass, Role
from tests.review.test_prompt_competence import (
    FIXTURES, ROOT, SETTINGS, ScriptedTransport, accepted_corpus, returned_rows,
)

STATEFUL = load_cases(FIXTURES / "stateful_competence_cases.json")
DISCOVERY = (Role.HYPOTHESIS_HUNTER, Role.RED_TEAM_ANALYST)


class DiscoveryTransport(ScriptedTransport):
    def __call__(self, request, *, timeout_seconds):
        answer = super().__call__(request, timeout_seconds=timeout_seconds)
        if answer.proposal["action"] != "final":
            return answer
        leads = ["L1"] if request.role == Role.RED_TEAM_ANALYST.value else []
        if self.answer != "vulnerable":
            group = "blocked" if self.answer == "abstain" else "no_claim"
            result = {"claims": [], group: [
                {"lead": label, "why": "Selected configuration or helper evidence is unavailable."
                 if group == "blocked" else "The retrieved helper enforces the invariant."}
                for label in leads]}
        else:
            cites = answer.proposal["result"]["per_predicate"]["missing_or_ineffective_guard"]["cites"]
            result = {"claims": [{
                "id": "candidate", "leads": leads, "cwe": self.case["cwe"],
                "security_predicate": self.case["condition"], "statement": self.case["question"],
                "entry": "The tenant controls its refund key and concurrent retries, not another tenant.",
                "trigger": "Two permitted retries interleave before the key is committed.",
                "affected": ["A1"], "support": {
                    "affected_construct": ["A1"], "missing_or_ineffective_guard": cites},
            }]}
        return ModelResult({"action": "final", "result": result}, input_tokens=80, output_tokens=20)


def execute(tmp_path, case, role, script="retrieve_then_resolve", *, settings=SETTINGS,
            transport=None, variant="full", **limits):
    corpus = accepted_corpus(tmp_path, case, role=role, **limits)
    result = run_competence_case(
        ROOT, case, settings, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment",
        transport=transport or DiscoveryTransport(case, script), variant=variant)
    return corpus, result


@pytest.mark.parametrize("role", DISCOVERY, ids=lambda role: role.value)
def test_discovery_retrieves_decisive_later_page_and_admits_real_proposal(tmp_path, role):
    corpus, result = execute(tmp_path, STATEFUL[0], role, "paging",
                             page_size=1, max_turns=4, max_queries=4)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.row["correct"] and result.row["grounded"]
    assert result.outcome.result["role"] == role.value
    assert result.outcome.result["round_id"] == "0"
    assert result.outcome.counts["turns"] == 4 and result.outcome.counts["queries"] == 4
    second_page = result.requests[2].transcript[-1]["responses"][0]
    first_page = result.requests[1].transcript[-1]["responses"][0]
    decisive = {corpus.labels[label] for label in STATEFUL[0]["decisive_labels"]}
    assert second_page["results"][0]["identity"] in decisive
    assert not decisive <= {first_page["results"][0]["identity"]}
    assert not second_page["next_cursor"]
    assert result.requests[-1].transcript[-1]["final_required"]
    prompt = review_prompt(result.requests[0], include_guidance=True)
    encoded = json.dumps(prompt)
    assert all(f'"{key}"' not in encoded for key in ("expected", "decisive_labels", "family"))
    assert all(source["text"] not in encoded for source in STATEFUL[0]["sources"])
    assert prompt["capability_artifact_card"]["sha256"]
    assert "stateful-invariant-analysis" in prompt["guidance"]
    assert "authenticated tenant" in prompt["guidance"]
    assert {row["identity"] for row in returned_rows(result.requests[-1])} == set(corpus.labels.values())


@pytest.mark.parametrize("role", DISCOVERY, ids=lambda role: role.value)
def test_cross_file_control_and_hostile_comment_do_not_turn_no_claim_into_safety(tmp_path, role):
    _, result = execute(tmp_path, STATEFUL[1], role, "paging", page_size=1, max_turns=4, max_queries=4)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.outcome.result["proposals"] == []
    assert result.row["decision"] == "no_claim" and not result.row["correct"]
    assert result.row["conclusions"] == 0
    assert "MISLEADING_UNTRUSTED" not in result.requests[0].guidance_text
    assert "MISLEADING_UNTRUSTED" in json.dumps(result.requests[-1].transcript)
    assert "shell" not in result.requests[-1].task_input["capability"]["tools"]


def test_contradictory_unselected_configuration_requires_discovery_abstention(tmp_path):
    _, result = execute(tmp_path, STATEFUL[2], Role.RED_TEAM_ANALYST, "missing_artifact")
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.row["decision"] == "abstain" and result.row["correct"] and result.row["named_gap"]
    assert result.outcome.result["result_status"] == "partial"
    assert result.outcome.result["proposals"] == []
    assert result.outcome.result["lead_accounting"][0]["outcome"] == "blocked"
    assert result.requests[1].transcript[-1]["responses"][0]["coverage_gaps"] == [
        "artifacts index is unavailable"]
    assert "exactly_once" in json.dumps(result.requests[-1].transcript)
    assert "at_least_once" in json.dumps(result.requests[-1].transcript)


@pytest.mark.parametrize("case", STATEFUL, ids=lambda case: case["id"])
def test_blind_verifier_checks_stateful_control_or_names_unselected_configuration(tmp_path, case):
    corpus = accepted_corpus(tmp_path, case)
    result = run_competence_case(
        ROOT, case, SETTINGS, core=corpus.core, capability=corpus.capability, view=corpus.view,
        source_labels=corpus.labels, output=corpus.core.run_root / "data" / "experiment",
        transport=ScriptedTransport(case, "retrieve_then_resolve"))
    assert result.row["correct"]
    assert "stateful-invariant-analysis" in result.requests[0].guidance_text
    payload = result.requests[0].task_input["input"]
    assert "statement" not in payload["claim"] and "red_reasoning" not in json.dumps(payload)
    assert result.row["decision"] == case["expected"]


@pytest.mark.parametrize("role", DISCOVERY, ids=lambda role: role.value)
def test_discovery_denial_recovery_uses_actual_authorization_and_charges_budget(tmp_path, role):
    _, result = execute(tmp_path, STATEFUL[0], role, "denial_recovery")
    assert result.row["correct"]
    assert result.requests[1].transcript[-1]["responses"][0]["status"] == "denied"
    assert result.outcome.counts["denials"] == 1 and result.outcome.counts["queries"] == 4


@pytest.mark.parametrize("script", ("wrong_label", "wrong_identity"))
def test_discovery_unknown_citations_never_earn_grounded_credit(tmp_path, script):
    # Affected A1 is real; the required cross-file evidence must also survive expansion.
    _, result = execute(tmp_path, STATEFUL[0], Role.RED_TEAM_ANALYST, script)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.row["unsupported"] == 1 and not result.row["correct"]
    assert not result.row["grounded"]


def test_discovery_path_citation_is_rejected_by_the_closed_compact_schema(tmp_path):
    _, result = execute(tmp_path, STATEFUL[0], Role.RED_TEAM_ANALYST, "path_citation")
    assert result.outcome.record.status is CellStatus.INVALID
    assert result.outcome.gaps[0].gap_class is GapClass.SCHEMA_ERROR
    assert result.row["status"] == "invalid" and "correct" not in result.row


def test_unknown_blocked_label_is_not_a_justified_discovery_abstention(tmp_path):
    scripted = DiscoveryTransport(STATEFUL[2], "retrieve_then_resolve")

    def transport(request, *, timeout_seconds):
        answer = scripted(request, timeout_seconds=timeout_seconds)
        if answer.proposal["action"] == "final":
            return ModelResult({"action": "final", "result": {"claims": [], "blocked": [
                {"lead": "Q999", "why": "Unresolved configuration."}]}})
        return answer

    _, result = execute(tmp_path, STATEFUL[2], Role.RED_TEAM_ANALYST, transport=transport)
    assert result.outcome.record.status is CellStatus.SUCCEEDED
    assert result.outcome.result["gaps"]
    assert not result.row["correct"] and result.row["decision"] == "no_claim"


@pytest.mark.parametrize("role", DISCOVERY, ids=lambda role: role.value)
def test_discovery_final_turn_cap_cannot_be_relabelled_as_abstention(tmp_path, role):
    _, result = execute(tmp_path, STATEFUL[0], role, "final_turn_ignored", max_turns=2)
    assert result.outcome.record.status is CellStatus.TIMED_OUT
    assert result.outcome.gaps[0].gap_class is GapClass.BUDGET_GAP
    assert result.row["status"] == "invalid" and "decision" not in result.row
    assert result.outcome.counts["queries"] == 1


def test_discovery_actual_red_admission_checks_configured_output_limit(tmp_path):
    scripted = DiscoveryTransport(STATEFUL[0], "retrieve_then_resolve")

    def transport(request, *, timeout_seconds):
        answer = scripted(request, timeout_seconds=timeout_seconds)
        if answer.proposal["action"] == "final":
            result = deepcopy(answer.proposal["result"])
            result["claims"].append({**deepcopy(result["claims"][0]), "id": "second"})
            return ModelResult({"action": "final", "result": result})
        return answer

    settings = replace(SETTINGS, red_output=replace(SETTINGS.red_output, max_proposals=1))
    _, result = execute(tmp_path, STATEFUL[0], Role.RED_TEAM_ANALYST, settings=settings, transport=transport)
    assert result.outcome.record.status is CellStatus.INVALID
    assert result.outcome.gaps[0].gap_class is GapClass.SCHEMA_ERROR
    assert result.row["status"] == "invalid"
    receipt = json.loads(result.outcome.receipt_paths[0].read_text())
    assert "limit is 1" in json.dumps(receipt)


def test_procedure_ablation_preserves_authority_and_rehashes_actual_bundle(tmp_path):
    results = [execute(tmp_path / variant, STATEFUL[0], Role.RED_TEAM_ANALYST, variant=variant)
               for variant in ("full", "without_procedures")]
    bundles = []
    for corpus, result in results:
        path = corpus.core.run_root / "data" / "guidance" / result.row["guidance_sha256"] / "bundle.json"
        bundle = json.loads(path.read_text())
        verify_bundle(bundle)
        bundles.append(bundle)
        assert result.row["correct"]
    assert bundles[0]["sha256"] != bundles[1]["sha256"]
    assert {name for name in bundles[0]["section_sha256"]
            if bundles[0]["section_sha256"][name] != bundles[1]["section_sha256"][name]} == {"procedures"}


def test_manual_acceptance_selectors_keep_legacy_defaults_without_running_acceptance():
    from tests.acceptance.test_prompt_competence import argument_parser

    parser = argument_parser()
    required = ["--config", "appsec-review.toml", "--profile", "dev", "--provider", "claude-cli",
                "--model", "configured-model", "--cases", "cases.json", "--output", "runs/manual"]
    legacy = parser.parse_args(required)
    assert legacy.role == Role.INDEPENDENT_VERIFIER.value and legacy.variant == "full"
    assert not legacy.live and legacy.turn_cap is None
    for role in DISCOVERY:
        parsed = parser.parse_args([*required, "--role", role.value, "--variant", "without_procedures",
                                    "--turn-cap", "3"])
        assert parsed.role == role.value and parsed.turn_cap == 3 and not parsed.live
    with pytest.raises(SystemExit):
        parser.parse_args([*required, "--role", "adjudication_judge"])
