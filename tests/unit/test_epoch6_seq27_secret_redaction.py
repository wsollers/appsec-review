from __future__ import annotations

from dataclasses import replace

import pytest

from appsec_review.reporting.dossier_render import (
    render_dossier_html,
    render_dossier_markdown,
    render_latex,
)
from appsec_review.reporting.dossiers import build_dossier, dossier_document
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.models import Predicate, Role
from appsec_review.review.decision_audit.query import Query, Template, execute
from appsec_review.review.secret_redaction import (
    redact_message,
    redact_prose_secrets,
    redact_source_line,
)
from appsec_review.storage import canonical_json
from tests.unit.review_decision_audit_consumers.helpers import Fixture, link


def test_defect_27a_preserves_canonical_scale_refs_and_benign_kv_tokens(tmp_path):
    scale_values = (
        "application_risk_matrix/3",
        "exploitability_evidence/1",
        "environmental_exposure/1",
    )
    for scale in scale_values:
        assert "<redacted:" not in redact_source_line(scale, assignments=False)
        assert redact_prose_secrets(scale) == scale
        assert redact_message(scale, bound=256) == scale

    benign_prose = (
        f"Existing deciding row r5_confirmed; policy={'a' * 64}. "
        "technical_severity critical; provider application_risk_matrix/3; band critical; "
        "max_paths_per_sink=8; max_depth=12."
    )
    assert redact_prose_secrets(benign_prose) == benign_prose
    assert redact_message(benign_prose, bound=512) == benign_prose

    fixture = Fixture(tmp_path)
    doc = fixture.dossier()
    doc["finding"]["scores"] = [
        {
            "score_id": "score-tech",
            "sha256": "c" * 64,
            "provider": {"id": "application_risk_matrix/3"},
            "technical_severity": {
                "rating": "critical",
                "value": 9.2,
                "scale": "application_risk_matrix/3",
            },
            "exploitability_confidence": {
                "rating": "high",
                "value": 8.5,
                "scale": "exploitability_evidence/1",
            },
            "environmental_business_impact": {
                "rating": "medium",
                "value": 5.0,
                "scale": "environmental_exposure/1",
            },
        }
    ]
    dossier = build_dossier(**doc)
    serialized = canonical_json(dossier).decode("utf-8")
    md_out = render_dossier_markdown(dossier)
    html_out = render_dossier_html(dossier)
    tex_out = render_latex(dossier_document(dossier))

    for rendered in (serialized, md_out, html_out, tex_out):
        assert "<redacted:" not in rendered
    for scale in scale_values:
        assert scale in serialized
        assert scale.replace("_", "\\_") in md_out
        assert scale in html_out


_STRIPE_PREFIX = "sk_" + "live_"


@pytest.mark.parametrize(
    "sample,secret_fragment",
    [
        (
            f"api_key={_STRIPE_PREFIX}0123456789abcdef01234567",
            f"{_STRIPE_PREFIX}0123456789abcdef01234567",
        ),
        ("client_secret=superSecretTokenValue9876543210", "superSecretTokenValue9876543210"),
        ("password=mySecretPassphrase12345678", "mySecretPassphrase12345678"),
        ("auth_token=abcdef0123456789abcdef0123456789", "abcdef0123456789abcdef0123456789"),
        ("session_key=0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"),
    ],
)
def test_defect_27a_still_redacts_secret_bearing_kv_and_tokens(sample, secret_fragment):
    redacted_prose = redact_prose_secrets(sample)
    redacted_line = redact_source_line(sample, assignments=False)
    assert "<redacted:" in redacted_prose
    assert secret_fragment not in redacted_prose
    assert "<redacted:" in redacted_line
    assert secret_fragment not in redacted_line


def test_defect_27b_preserves_possessive_apostrophes_and_c_char_literals_in_prose(tmp_path):
    samples = [
        "In handle_request's buffer validation path, the caller's privileges reach the service's boundary.",
        "main's loop increments the parser's size_t count before checking bounds.",
        "log_message appends client's payload terminated by putchar('\\n') and delimiter '.' or '_' or '-'.",
        "fixture's setup validates fopen: realpath before opening the child's descriptor.",
        "Single-quoted 'multi word English explanation' and \"double quoted normal prose\" stay intact.",
    ]
    for text in samples:
        assert redact_prose_secrets(text) == text
        assert redact_message(text, bound=512) == text

    fixture = Fixture(tmp_path)
    doc = fixture.dossier()
    doc["claim"] = {
        **doc["claim"],
        "statement": samples[0],
        "preconditions": [samples[1]],
    }
    doc["remediation"] = [
        {
            "stage": "Guidance",
            "status": "recommended",
            "reason": samples[4],
            "violated_invariant": samples[2],
            "corrected_invariant": samples[3],
        }
    ]
    doc["chains"] = [
        {
            "chain_id": "chain-0123456789abcdef",
            "status": "plausible",
            "objective": "Caller's untrusted buffer reaches putchar('\\n') without parser's length guard.",
            "qualifications": ["fixture's setup validates '.' and '_' delimiters."],
        }
    ]
    dossier = build_dossier(**doc)
    serialized = canonical_json(dossier).decode("utf-8")
    md_out = render_dossier_markdown(dossier)
    html_out = render_dossier_html(dossier)
    tex_out = render_latex(dossier_document(dossier))

    for rendered in (serialized, md_out, html_out, tex_out):
        assert "<redacted:" not in rendered
    assert "handle_request's" in serialized
    assert "putchar('\\n')" in dossier["remediation"][0]["violated_invariant"]


def test_defect_27b_redacts_genuine_secrets_in_prose_and_honors_secret_context(tmp_path):
    secret_cases = [
        ('password = "private-value"', "private-value"),
        ('A redacted "literal-secret" explanation.', "literal-secret"),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        ),
        (
            "Leak of ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD and AKIAIOSFODNN7EXAMPLE",
            "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD",
        ),
        ("Header -----BEGIN OPENSSH PRIVATE KEY----- seen", "BEGIN OPENSSH PRIVATE KEY"),
        ("Token 'Q9zX7mK2pL8vR4nW1tY6bJ3cH5fG0dS9' exposed", "Q9zX7mK2pL8vR4nW1tY6bJ3cH5fG0dS9"),
        (
            "Narrative synthetic-token-abcdef0123456789abcdef0123456789 leaked",
            "abcdef0123456789abcdef0123456789",
        ),
    ]
    for raw, secret_sub in secret_cases:
        out = redact_prose_secrets(raw, secret_context=False)
        assert "<redacted:" in out, f"expected redaction for {raw!r}, got {out!r}"
        assert secret_sub not in out

    strict = redact_prose_secrets('config_value = "ordinary_looking_literal"', secret_context=True)
    assert "<redacted:" in strict
    assert "ordinary_looking_literal" not in strict

    fixture = Fixture(tmp_path)
    doc = fixture.dossier()
    doc["claim"] = {
        **doc["claim"],
        "weakness_cwe": "CWE-798",
        "security_predicate": "hardcoded_secret",
        "statement": 'Hardcoded credential "ordinary_looking_literal" embedded in binary.',
    }
    secret_dossier = build_dossier(**doc)
    assert "ordinary_looking_literal" not in canonical_json(secret_dossier).decode("utf-8")


def test_defect_27c_producer_and_query_preserve_policy_provider_and_possessives(tmp_path):
    import appsec_review.jobs.job_inference_security_review  # noqa: F401
    from appsec_review.review.decision_audit.projection import explanation as producer_explanation

    adj_exp = producer_explanation(f"Existing deciding row r5_confirmed; policy={'b' * 64}.")
    score_exp = producer_explanation(
        "technical_severity critical; provider application_risk_matrix/3; band critical"
    )
    judge_exp = producer_explanation(
        "Judge confirmed shell's command line reaches popen without escaping service's input; "
        "fopen: realpath and putchar('\\n') do not sanitize metacharacters."
    )
    secret_exp = producer_explanation(
        'Judge saw "literal-secret" and ghp_0123456789abcdef0123456789abcdef in logs.'
    )

    assert adj_exp.text is not None and "<redacted:" not in adj_exp.text
    assert score_exp.text is not None and "<redacted:" not in score_exp.text
    assert judge_exp.text is not None and "<redacted:" not in judge_exp.text
    assert secret_exp.text is not None
    assert "literal-secret" not in secret_exp.text
    assert "ghp_0123456789abcdef0123456789abcdef" not in secret_exp.text

    fixture = Fixture(tmp_path)
    prose_narrative = (
        "Verifier confirmed handle_request's parser passes client's delimiter '\\n' "
        "under application_risk_matrix/3."
    )
    decision_prose = replace(
        fixture.decision,
        context=replace(
            fixture.decision.context,
            explanation=c.Explanation(prose_narrative, None, link()),
        ),
    )
    basis = replace(fixture.basis, decisions=(c.RecordRef.of(decision_prose),))
    fixture.publish((decision_prose, fixture.verification, basis))
    result = execute(fixture.load(), Query(Template.POPULATION, stage=c.Stage.ADMISSION))
    assert len(result["records"]) == 1
    assert result["records"][0]["context"]["explanation"]["text"] == prose_narrative


def test_defect_27c_dossier_recovers_prebaked_redactions_only_from_verified_provenance(tmp_path):
    fixture = Fixture(tmp_path, scores=True)
    judge_reason = (
        "Judge confirmed shell's command argument reaches popen without escaping service's input."
    )

    adj_decision = replace(
        fixture.decision,
        stage=c.Stage.ADJUDICATION,
        outcome="confirmed",
        deciding_row=c.DecidingRow.CONFIRMED,
        deciding_row_absence_reason=None,
        deciding_actor_roles=(Role.INDEPENDENT_VERIFIER,),
        required_predicates=(Predicate.AFFECTED_CONSTRUCT,),
        reason_code=c.ReasonCode.RECORDED_DECISION,
        context=replace(
            fixture.context,
            origin=fixture.origin,
            relations=fixture.relations,
            sources=(fixture.source(fixture.adjudication_ref, "adjudication-1"),),
            explanation=c.Explanation(
                "Existing deciding row r5_confirmed; policy=<redacted:65 chars>",
                None,
                link(),
            ),
        ),
    )
    score_decision = replace(
        fixture.decision,
        stage=c.Stage.SCORING,
        outcome="scored",
        reason_code=c.ReasonCode.RECORDED_DECISION,
        context=replace(
            fixture.context,
            origin=fixture.origin,
            sources=(fixture.source(fixture.scoring_ref, "score-1"),),
            explanation=c.Explanation(
                "technical_severity critical; provider <redacted:25 chars>; band critical",
                None,
                link(),
            ),
        ),
    )
    judge_decision = replace(
        fixture.decision,
        stage=c.Stage.JUDGE_REVIEW,
        outcome="blue_correct",
        reason_code=c.ReasonCode.RECORDED_DECISION,
        context=replace(
            fixture.context,
            origin=fixture.origin,
            sources=(fixture.source(fixture.projection_ref, "judge-verdict-1"),),
            explanation=c.Explanation(
                "Judge confirmed shell'<redacted:54 chars>'s input.",
                None,
                link(),
            ),
        ),
    )
    verifier = replace(
        fixture.verification,
        context=replace(
            fixture.verification.context,
            origin=fixture.origin,
            sources=(fixture.source(fixture.projection_ref, "claim-1"),),
            relations=tuple(
                replace(r, source=fixture.source(fixture.projection_ref, r.relation_id))
                for r in fixture.relations
            ),
        ),
    )
    basis = replace(
        fixture.basis,
        context=replace(
            fixture.basis.context,
            origin=fixture.origin,
            sources=(fixture.source(fixture.projection_ref, "claim-1"),),
            relations=verifier.context.relations,
        ),
        claim=fixture.source(fixture.projection_ref, "claim-1"),
        decisions=(
            c.RecordRef.of(adj_decision),
            c.RecordRef.of(score_decision),
            c.RecordRef.of(judge_decision),
        ),
        verification=c.OptionalRecord(c.RecordRef.of(verifier), None),
        judge_verdicts=(fixture.source(fixture.projection_ref, "judge-verdict-1"),),
    )
    fixture.publish((adj_decision, score_decision, judge_decision, verifier, basis))
    audit = fixture.load()

    doc = fixture.dossier()
    doc["finding"]["scores"] = [
        {
            "score_id": "score-1",
            "sha256": "c" * 64,
            "provider": {"id": "application_risk_matrix/3"},
            "technical_severity": {
                "rating": "critical",
                "value": 9.4,
                "scale": "application_risk_matrix/3",
            },
        }
    ]
    policy_sha = "d" * 64
    verified_adjudications = [
        {**row, "policy_sha256": policy_sha} for row in fixture.adjudications["adjudications"]
    ]
    recovered = build_dossier(
        **doc,
        decision_audit=audit,
        judge_verdicts=[{"verdict_id": "judge-verdict-1", "verdict": "blue_correct", "reason": judge_reason}],
        adjudications=verified_adjudications,
    )
    explanations = {
        row["stage"]: row["explanation"] for row in recovered["decision_basis"]["decisions"]
    }
    assert explanations["adjudication"] == (
        f"Existing deciding row r5_confirmed; policy={policy_sha}."
    )
    assert explanations["scoring"] == (
        "technical_severity critical; provider application_risk_matrix/3; band critical"
    )
    assert explanations["judge_review"] == judge_reason
    assert "<redacted:" not in canonical_json(recovered).decode("utf-8")

    secret_verdict = [
        {
            "verdict_id": "judge-verdict-1",
            "verdict": "blue_correct",
            "reason": 'Judge saw password = "private-value" in shell\'s environment.',
        }
    ]
    recovered_secret = build_dossier(
        **doc,
        decision_audit=audit,
        judge_verdicts=secret_verdict,
        adjudications=fixture.adjudications["adjudications"],
    )
    judge_out = next(
        row["explanation"]
        for row in recovered_secret["decision_basis"]["decisions"]
        if row["stage"] == "judge_review"
    )
    assert "private-value" not in judge_out
    assert "shell's environment" in judge_out
    assert "<redacted:" in judge_out

    unverified_judge = build_dossier(
        **doc,
        decision_audit=audit,
        judge_verdicts=[{"verdict_id": "other-verdict", "reason": judge_reason}],
        adjudications=fixture.adjudications["adjudications"],
    )
    unverified_judge_out = next(
        row["explanation"]
        for row in unverified_judge["decision_basis"]["decisions"]
        if row["stage"] == "judge_review"
    )
    assert unverified_judge_out == "Judge confirmed shell'<redacted:54 chars>'s input."

    secret_ctx_doc = {
        **doc,
        "claim": {
            **doc["claim"],
            "weakness_cwe": "CWE-798",
            "security_predicate": "hardcoded_secret",
        },
    }
    secret_ctx_dossier = build_dossier(
        **secret_ctx_doc,
        decision_audit=audit,
        judge_verdicts=[{"verdict_id": "judge-verdict-1", "verdict": "blue_correct", "reason": judge_reason}],
        adjudications=fixture.adjudications["adjudications"],
    )
    for row in secret_ctx_dossier["decision_basis"]["decisions"]:
        assert "<redacted:" in row["explanation"]
