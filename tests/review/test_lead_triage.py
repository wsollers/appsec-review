"""Deterministic-first lead severity triage and its bounded model fallback."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config.inference_review import ModelProfileSettings
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review import lead_triage, numeric_reasoning
from appsec_review.review.lead_families import Lead, with_triage
from appsec_review.review.lead_triage import (
    RESULT_SCHEMA, TriageGuidance, finding_fingerprint, finding_input, run_triage, supplied_fact_ids,
    validate_result,
)
from appsec_review.review.lead_triage_settings import TriageRule, TriageSettings
from appsec_review.review.packages import PackageSettings, admission_reasons, lead_record
from appsec_review.review.references import CweConsequence, CweEntry, CweReference


SCHEMAS = SchemaSet(Path("docs/schemas/inference-security-review"))
PROFILE = ModelProfileSettings("claude-cli", "claude-haiku-5-5", "low", 32_000, 1_400, 0, 2, 60)
GUIDANCE = TriageGuidance({"sha256": "a" * 64}, "bounded triage guidance")


class _AnyText:
    def __eq__(self, other: object) -> bool:
        return isinstance(other, str) and bool(other)


ANY_TEXT = _AnyText()


def lead(identifier: str, *, family: str = "source_sast", scanner: str = "tool-unknown",
         rule: str = "unknown-rule", reported: str = "unknown", native: str | None = None,
         cwes: tuple[str, ...] = (), path: str | None = "src/a.c", line: int | None = 2) -> Lead:
    return Lead(identifier, family, scanner, rule, native, reported, "native-label", "scanner message", cwes,
                path, line, True, "observations", "default", "b" * 64)


def settings(*rules: TriageRule, max_leads: int = 200) -> TriageSettings:
    return TriageSettings(True, 20, "triage", max_leads, 24, 200, tuple(rules))


def reader(_lead: Lead):
    return ["int main(void) {", "  return dangerous(input);", "}"], None


@pytest.mark.parametrize("failure", [RuntimeError("contract bug"), TypeError("wrong transport")])
def test_triage_programming_errors_are_not_provider_gaps(failure):
    def infer(*args, **kwargs):
        raise failure

    with pytest.raises(type(failure)) as raised:
        run_triage([lead("lead-model")], settings=settings(), profile=PROFILE, infer=infer,
                   read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    assert raised.value is failure


@pytest.mark.parametrize("source", ["provider", "replay"])
def test_triage_usage_retains_unknown_and_replay_provenance(source):
    def infer(*args, **kwargs):
        return ModelResult({"schema": RESULT_SCHEMA, "items": [{
            "lead_id": "lead-model", "severity": None, "basis": "insufficient_context",
            "reason": "The evidence does not establish reachability.",
        }]}, input_tokens=-1, output_tokens=30, usage_source=source)

    outcome = run_triage([lead("lead-model")], settings=settings(), profile=PROFILE, infer=infer,
                        read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    usage = outcome.document["batches"][0]["attempts"][0]["usage"]
    assert usage["input_tokens"] is None and usage["source"] == source
    assert usage["output_tokens"] == (30 if source == "provider" else None)


def test_triage_first_error_disables_schema_repair(monkeypatch):
    from appsec_review.runtime import execution_safety
    monkeypatch.setattr(execution_safety, "active", lambda: True)
    calls = []

    def infer(request, **kwargs):
        calls.append(request)
        return ModelResult({"schema": RESULT_SCHEMA, "items": []})

    outcome = run_triage([lead("lead-model")], settings=settings(), profile=PROFILE, infer=infer,
                        read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    assert len(calls) == 1 and outcome.model_calls == 1
    assert outcome.document["batches"][0]["gap"] == "triage_failed:invalid_output"


def test_rule_table_runs_before_the_model_and_records_original_and_assessed_severity() -> None:
    table_lead = lead("lead-table", family="secret", scanner="tool-gitleaks:8.2:adapter-1",
                      rule="generic-api-key")
    model_lead = lead("lead-model")
    known_lead = lead("lead-known", reported="high", native="HIGH")
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        assert [item["lead_id"] for item in request.task_input["findings"]] == ["lead-model"]
        return ModelResult({"schema": RESULT_SCHEMA, "items": [{
            "lead_id": "lead-model", "severity": "medium", "basis": "code_context",
            "reason": "The bounded excerpt shows a dangerous call, but not whether input is attacker controlled.",
        }]}, 100, 30)

    outcome = run_triage(
        [known_lead, model_lead, table_lead],
        settings=settings(TriageRule("gitleaks", "high", "rule_semantics",
                                     "A hard-coded credential is exposed to every reader of the repository.")),
        profile=PROFILE, infer=infer, read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS)

    assert outcome.model_calls == 1 and len(calls) == 1
    assert outcome.document["counts"] == {
        "unknown_leads": 2, "rule_table": 1, "cwe_catalog": 0, "model_triage": 1,
        "unresolved": 0, "leads_total": 3, "reused_from_cache": 0, "batches": 1, "model_calls": 1,
    }
    triaged_table = with_triage(table_lead, outcome.assessments["lead-table"])
    table_record = triaged_table.severity_record()
    model_record = with_triage(model_lead, outcome.assessments["lead-model"]).severity_record()
    assert table_record["original"]["reported_severity"] == "unknown"
    assert table_record["assessed"]["value"] == "high"
    assert "hard-coded credential" in table_record["assessed"]["reason"].lower()
    assert admission_reasons(triaged_table, PackageSettings()) == ["assessed_severity"]
    menu = lead_record(triaged_table, "component-a", None, admission=["assessed_severity"])
    assert menu["reported_severity"] == "unknown" and menu["severity_record"] == table_record
    assert model_record["original"]["reported_severity"] == "unknown"
    assert model_record["assessed"]["value"] == "medium"
    assert "bounded excerpt" in model_record["assessed"]["reason"].lower()
    assert with_triage(known_lead, None).effective_severity == "high"


def test_pinned_cwe_catalog_decides_before_the_model() -> None:
    consequence = CweConsequence(1, ("Confidentiality",), ("Execute Unauthorized Code or Commands",))
    reference = CweReference(
        "mitre_catalog", {"CWE-78": CweEntry("CWE-78", "OS Command Injection", "Base", (consequence,))},
        snapshot_id="mitre-1", manifest_sha256="c" * 64, version="4.17", consequences_indexed=True)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("the model must not run when the pinned catalog decides")

    outcome = run_triage(
        [lead("lead-cwe", rule="custom-command-rule", cwes=("CWE-78",))], settings=settings(),
        profile=PROFILE, infer=forbidden, read_excerpt=reader, reference=reference,
        guidance=GUIDANCE, schemas=SCHEMAS)
    row = outcome.document["leads"][0]
    assert outcome.model_calls == 0 and row["origin"] == "deterministic"
    assert row["assessed"]["source"] == "cwe_catalog" and row["assessed"]["value"] == "high"
    assert row["references"][0]["id"] == "CWE-78"
    assert "numeric_reasoning" not in row and "tool_fact" not in row["assessed"]


def test_unresolved_model_result_keeps_unknown_and_records_why() -> None:
    unresolved = lead("lead-unresolved", path=None, line=None)

    def infer(_request, *, timeout_seconds):
        return ModelResult({"schema": RESULT_SCHEMA, "items": [{
            "lead_id": unresolved.observation_id, "severity": None, "basis": "insufficient_context",
            "reason": "No source excerpt was available, so reachability and impact remain unknown.",
        }]})

    outcome = run_triage([unresolved], settings=settings(), profile=PROFILE, infer=infer,
                         read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    record = with_triage(unresolved, outcome.assessments[unresolved.observation_id]).severity_record()
    assert record["original"]["reported_severity"] == "unknown"
    assert record["assessed"] is None and record["effective"] == {"value": "unknown", "from": "unknown"}
    assert record["gap"] == {
        "code": "triage_unresolved:insufficient_context",
        "reason": "No source excerpt was available, so reachability and impact remain unknown.",
    }


def test_secret_excerpt_is_redacted_before_it_enters_a_model_request() -> None:
    secret = lead("lead-secret", family="secret", scanner="tool-gitleaks", rule="unmapped-secret")
    item = finding_input(secret, settings=settings(),
                         reader=lambda _lead: (["header", 'API_TOKEN = "actual-secret-value"', "footer"], None),
                         reference=None, impact=None)
    rendered = "\n".join(item["excerpt"])
    assert "actual-secret-value" not in rendered and "<redacted:" in rendered



# ------------------------------------------------------------------------- numeric-reasoning-guardrail/1

NUMERIC_UNCITED = "The length can overflow when multiplied, so the allocation may be too small."
NUMERIC_CITED = "Scanner observation O1 reports a size overflow before the allocation."


def single_reply(reason: str, *, severity: str | None = "high", basis: str = "code_context",
                 tool_fact: str | None = None, lead_id: str = "lead-num") -> dict:
    item = {"lead_id": lead_id, "severity": severity, "basis": basis, "reason": reason}
    if tool_fact is not None:
        item["tool_fact"] = tool_fact
    return {"schema": RESULT_SCHEMA, "items": [item]}


def triage_one(target: Lead, *replies: dict):
    calls = []

    def infer(request, *, timeout_seconds):
        calls.append(request)
        return ModelResult(replies[len(calls) - 1])

    outcome = run_triage([target], settings=settings(), profile=PROFILE, infer=infer, read_excerpt=reader,
                         reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    return outcome, calls


def test_finding_input_supplies_the_scanner_observation_as_tool_fact_o1_and_it_feeds_the_fingerprint() -> None:
    target = lead("lead-num", scanner="tool-codeql", rule="cpp/tainted-arithmetic")
    target = replace(target, message="user value may overflow in multiplication " + "x" * 400)
    item = finding_input(target, settings=settings(), reader=reader, reference=None, impact=None)
    assert item["tool_facts"] == [{
        "id": "O1", "kind": "scanner_observation", "scanner": "tool-codeql", "rule_id": "cpp/tainted-arithmetic",
        "message": item["message"], "path": "src/a.c", "line": 2}]
    assert len(item["tool_facts"][0]["message"]) == 300
    assert supplied_fact_ids(item) == {"O1"}
    without = {key: value for key, value in item.items() if key != "tool_facts"}
    fingerprint = finding_fingerprint(item, settings=settings(), profile=PROFILE, guidance=GUIDANCE)
    assert fingerprint != finding_fingerprint(without, settings=settings(), profile=PROFILE, guidance=GUIDANCE)
    changed = {**item, "tool_facts": [{**item["tool_facts"][0], "message": "different"}]}
    assert fingerprint != finding_fingerprint(changed, settings=settings(), profile=PROFILE, guidance=GUIDANCE)


def test_uncited_numeric_reason_keeps_the_lead_unknown_with_the_named_gap() -> None:
    target = lead("lead-num")
    assert numeric_reasoning.detect(NUMERIC_UNCITED) == ("arithmetic_wrap",)
    outcome, calls = triage_one(target, single_reply(NUMERIC_UNCITED))
    assert len(calls) == 1 and outcome.model_calls == 1           # valid reply: no repair turn
    assert calls[0].task_input["findings"][0]["tool_facts"][0]["id"] == "O1"
    row = outcome.document["leads"][0]
    assert row["state"] == "unresolved" and row["assessed"] is None
    assert row["gap"] == {"code": numeric_reasoning.TRIAGE_GAP, "reason": numeric_reasoning.TRIAGE_GAP_REASON}
    assert row["numeric_reasoning"] == {"rule": numeric_reasoning.RULE, "categories": ["arithmetic_wrap"],
                                        "tool_fact": None, "model_severity": "high",
                                        "model_reason": NUMERIC_UNCITED}
    record = with_triage(target, outcome.assessments["lead-num"]).severity_record()
    assert record["assessed"] is None and record["effective"] == {"value": "unknown", "from": "unknown"}
    assert record["gap"]["code"] == "triage_unresolved:uncited_numeric_reasoning"
    assert outcome.document["counts"]["unresolved"] == 1 and outcome.document["counts"]["model_triage"] == 0
    assert outcome.document["numeric_reasoning"] == {
        "rule": numeric_reasoning.RULE, "gap": numeric_reasoning.TRIAGE_GAP, "fact_ids": ANY_TEXT,
        "numeric_reasons": 1, "cited": 0, "uncited": 1}


def test_numeric_reason_citing_a_supplied_tool_fact_is_accepted_and_records_the_fact() -> None:
    target = lead("lead-num")
    outcome, calls = triage_one(target, single_reply(NUMERIC_CITED, tool_fact="O1"))
    assert len(calls) == 1
    row = outcome.document["leads"][0]
    assert row["state"] == "assessed" and row["gap"] is None
    assert row["assessed"]["value"] == "high" and row["assessed"]["tool_fact"] == "O1"
    assert row["numeric_reasoning"] == {"rule": numeric_reasoning.RULE, "categories": ["arithmetic_wrap"],
                                        "tool_fact": "O1"}
    assert outcome.document["batches"][0]["results"][0]["tool_fact"] == "O1"
    assert outcome.document["numeric_reasoning"]["cited"] == 1
    assert outcome.document["numeric_reasoning"]["uncited"] == 0
    assert with_triage(target, outcome.assessments["lead-num"]).effective_severity == "high"


def test_unsupplied_tool_fact_is_a_validation_error_that_the_repair_turn_fixes() -> None:
    target = lead("lead-num")
    outcome, calls = triage_one(target, single_reply(NUMERIC_CITED, tool_fact="R7"),
                                single_reply(NUMERIC_CITED, tool_fact="O1"))
    assert len(calls) == 2 and outcome.model_calls == 2
    assert calls[0].repair_errors == ()
    assert any("tool_fact R7 is not a tool fact supplied for this lead (supplied: O1)" in error
               for error in calls[1].repair_errors)
    attempts = outcome.document["batches"][0]["attempts"]
    assert "valid" not in attempts[0] and attempts[1]["valid"] is True
    row = outcome.document["leads"][0]
    assert row["state"] == "assessed" and row["assessed"]["tool_fact"] == "O1"


def test_unsupplied_tool_fact_that_survives_repair_fails_the_batch() -> None:
    reply = single_reply(NUMERIC_CITED, tool_fact="O2")
    outcome, calls = triage_one(lead("lead-num"), reply, reply)
    assert len(calls) == 2
    row = outcome.document["leads"][0]
    assert row["state"] == "unresolved" and row["gap"]["code"] == "triage_failed:invalid_output"


def test_validate_result_checks_tool_fact_membership_per_lead() -> None:
    proposal = {"schema": RESULT_SCHEMA, "items": [
        {"lead_id": "a", "severity": "low", "basis": "code_context", "reason": "fine", "tool_fact": "O1"},
        {"lead_id": "b", "severity": "low", "basis": "code_context", "reason": "fine", "tool_fact": "O1"}]}
    items, errors = validate_result(proposal, ["a", "b"], max_reason_chars=200, schemas=SCHEMAS,
                                    fact_ids={"a": {"O1"}, "b": set()})
    assert items is None and errors == [
        "items[1].tool_fact O1 is not a tool fact supplied for this lead (supplied: none)"]
    items, errors = validate_result(proposal, ["a", "b"], max_reason_chars=200, schemas=SCHEMAS,
                                    fact_ids={"a": {"O1"}, "b": {"O1"}})
    assert errors == [] and [item["tool_fact"] for item in items] == ["O1", "O1"]


def test_non_numeric_reason_without_tool_fact_is_still_accepted() -> None:
    reason = "Command string built from a command-line argument reaches system()."
    assert numeric_reasoning.detect(reason) == ()
    outcome, _calls = triage_one(lead("lead-num"), single_reply(reason))
    row = outcome.document["leads"][0]
    assert row["state"] == "assessed" and row["assessed"]["value"] == "high"
    assert "tool_fact" not in row["assessed"] and "numeric_reasoning" not in row
    assert outcome.document["numeric_reasoning"]["numeric_reasons"] == 0


def test_cached_items_pass_through_the_same_guardrail(monkeypatch) -> None:
    cached = {
        "lead-uncited": {"lead_id": "lead-uncited", "severity": "high", "basis": "code_context",
                         "reason": NUMERIC_UNCITED},
        "lead-cited": {"lead_id": "lead-cited", "severity": "high", "basis": "code_context",
                       "reason": NUMERIC_CITED, "tool_fact": "O1"},
        "lead-forged": {"lead_id": "lead-forged", "severity": "high", "basis": "code_context",
                        "reason": NUMERIC_CITED, "tool_fact": "R9"},
    }

    def cache_hit(_cache_dir, _fingerprint, lead_id, *, shared=None):
        return {"item": cached[lead_id], "batch_id": "batch-0001", "shared_receipt": None}

    def forbidden(*_args, **_kwargs):
        raise AssertionError("cached leads must not reach the model")

    monkeypatch.setattr(lead_triage, "cache_read", cache_hit)
    outcome = run_triage([lead(name) for name in cached], settings=settings(), profile=PROFILE, infer=forbidden,
                         read_excerpt=reader, reference=None, guidance=GUIDANCE, schemas=SCHEMAS)
    rows = {row["lead_id"]: row for row in outcome.document["leads"]}
    assert {row["origin"] for row in rows.values()} == {"cache"}
    assert outcome.document["counts"]["reused_from_cache"] == 3 and outcome.model_calls == 0
    assert rows["lead-uncited"]["gap"]["code"] == numeric_reasoning.TRIAGE_GAP
    assert rows["lead-cited"]["state"] == "assessed" and rows["lead-cited"]["assessed"]["tool_fact"] == "O1"
    assert rows["lead-forged"]["state"] == "unresolved"
    assert rows["lead-forged"]["gap"]["code"] == numeric_reasoning.TRIAGE_GAP


def test_deterministic_steps_ignore_the_numeric_guardrail() -> None:
    table_lead = lead("lead-table", scanner="tool-cppcheck:2.1", rule="integerOverflow")
    reason = "Signed integer overflow in a size calculation can corrupt the heap."
    assert numeric_reasoning.detect(reason)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("the model must not run when the rule table decides")

    outcome = run_triage([table_lead], settings=settings(TriageRule("cppcheck", "high", "rule_semantics", reason,
                                                                    rule="integerOverflow")),
                         profile=PROFILE, infer=forbidden, read_excerpt=reader, reference=None,
                         guidance=GUIDANCE, schemas=SCHEMAS)
    row = outcome.document["leads"][0]
    assert row["origin"] == "deterministic" and row["state"] == "assessed"
    assert row["assessed"]["source"] == "rule_table" and row["assessed"]["value"] == "high"
    assert row["assessed"]["reason"] == reason and row["gap"] is None
    assert "numeric_reasoning" not in row and "tool_fact" not in row["assessed"]
    assert outcome.document["numeric_reasoning"]["numeric_reasons"] == 0