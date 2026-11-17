"""Unit tests for CI workflow high-risk review-lead promotion metadata (T-171)."""

from __future__ import annotations

from appsec_review.jobs.job_ci_configuration_analysis.static_rules import (
    classify_ci_lead_promotion,
    scan_text,
)


def test_static_rules_promote_high_risk_workflow_patterns_and_suppress_low_noise() -> None:
    workflow = "\n".join(
        [
            "on:",
            "  pull_request_target:",
            "permissions: write-all",
            "jobs:",
            "  pr_check:",
            "    runs-on: ubuntu-latest",
            "    continue-on-error: true",
            "    steps:",
            "      - uses: third-party/action@main",
            "      - run: echo \"PR title: ${{ github.event.pull_request.title }}\"",
            "        key: cache",
        ]
    )
    records = scan_text("github", ".github/workflows/pr.yml", workflow, tool_id="ci-schema")
    by_rule = {rec["native_rule_id"]: rec for rec in records}

    assert by_rule["CI-UNTRUSTED-TRIGGER"]["lead_candidate"] is True
    assert by_rule["CI-UNTRUSTED-TRIGGER"]["attack_class"] == "ci_untrusted_trigger_execution"
    assert by_rule["CI-UNTRUSTED-TRIGGER"]["severity_hint"] == "high"

    assert by_rule["CI-EXPRESSION-INJECTION"]["lead_candidate"] is True
    assert by_rule["CI-EXPRESSION-INJECTION"]["attack_class"] == "ci_expression_injection"
    assert by_rule["CI-EXPRESSION-INJECTION"]["severity_hint"] == "critical"

    assert by_rule["CI-MUTABLE-DEPENDENCY"]["lead_candidate"] is True
    assert by_rule["CI-MUTABLE-DEPENDENCY"]["attack_class"] == "ci_unpinned_dependency"
    assert by_rule["CI-MUTABLE-DEPENDENCY"]["severity_hint"] == "high"

    assert by_rule["CI-WRITE-ALL"]["lead_candidate"] is True
    assert by_rule["CI-WRITE-ALL"]["attack_class"] == "ci_excessive_permissions"
    assert by_rule["CI-WRITE-ALL"]["severity_hint"] == "high"

    # Low-noise operational checks stay non-lead observations
    assert by_rule["CI-CONTINUE-ON-ERROR"]["lead_candidate"] is False
    assert by_rule["CI-CONTINUE-ON-ERROR"]["attack_class"] is None
    assert by_rule["CI-STATIC-CACHE-KEY"]["lead_candidate"] is False


def test_external_linter_records_classify_lead_promotion() -> None:
    zizmor_inj = classify_ci_lead_promotion(
        {
            "tool_id": "tool-zizmor",
            "native_rule_id": "template-injection",
            "category": "code-execution",
            "message": "code injection via ${{ github.event.comment.body }}",
            "severity": "high",
        }
    )
    assert zizmor_inj == {
        "lead_candidate": True,
        "attack_class": "ci_expression_injection",
        "severity_hint": "critical",
    }

    info_note = classify_ci_lead_promotion(
        {
            "tool_id": "tool-actionlint",
            "native_rule_id": "shellcheck-info",
            "category": "style",
            "message": "quote variable to prevent globbing",
            "severity": "low",
        }
    )
    assert info_note["lead_candidate"] is False
    assert info_note["attack_class"] is None
