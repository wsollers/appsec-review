"""Deterministic-first lead severity triage and its bounded model fallback."""
from __future__ import annotations

from pathlib import Path

from appsec_review.config.inference_review import ModelProfileSettings
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.lead_families import Lead, with_triage
from appsec_review.review.lead_triage import RESULT_SCHEMA, TriageGuidance, finding_input, run_triage
from appsec_review.review.lead_triage_settings import TriageRule, TriageSettings
from appsec_review.review.packages import PackageSettings, admission_reasons, lead_record
from appsec_review.review.references import CweConsequence, CweEntry, CweReference


SCHEMAS = SchemaSet(Path("docs/schemas/inference-security-review"))
PROFILE = ModelProfileSettings("claude-cli", "claude-haiku-5-5", "low", 32_000, 1_400, 0, 2, 60)
GUIDANCE = TriageGuidance({"sha256": "a" * 64}, "bounded triage guidance")


def lead(identifier: str, *, family: str = "source_sast", scanner: str = "tool-unknown",
         rule: str = "unknown-rule", reported: str = "unknown", native: str | None = None,
         cwes: tuple[str, ...] = (), path: str | None = "src/a.c", line: int | None = 2) -> Lead:
    return Lead(identifier, family, scanner, rule, native, reported, "native-label", "scanner message", cwes,
                path, line, True, "observations", "default", "b" * 64)


def settings(*rules: TriageRule, max_leads: int = 200) -> TriageSettings:
    return TriageSettings(True, 20, "triage", max_leads, 24, 200, tuple(rules))


def reader(_lead: Lead):
    return ["int main(void) {", "  return dangerous(input);", "}"], None


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

