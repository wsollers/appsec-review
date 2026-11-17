from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


RULESET_IDENTITY = "ci-static-reviewed-rules/1"

_RULES: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("untrusted-trigger-execution", "CI-UNTRUSTED-TRIGGER", re.compile(r"\bpull_request_target\s*:|\brepository_dispatch\s*:"),
     "An untrusted or externally controlled trigger can reach this pipeline."),
    ("unsafe-pipeline-command-execution", "CI-PIPE-COMMAND", re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b|\b(?:eval|Invoke-Expression)\b", re.I),
     "Pipeline command text contains direct evaluation or a downloaded-script pipe."),
    ("privileged-runner-or-isolation", "CI-PRIVILEGED-RUNNER", re.compile(r"\bruns-on\s*:\s*(?:\[?\s*self-hosted|.*self-hosted)|\bprivileged\s*:\s*true\b", re.I),
     "The job requests a self-hosted or privileged execution environment."),
    ("secret-or-credential-exposure", "CI-SECRET-OUTPUT", re.compile(r"\b(?:echo|printf|Write-Host)\b.*(?:secrets\.|\$[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY))", re.I),
     "A command appears to emit a secret-bearing value."),
    ("dependency-or-provenance-integrity", "CI-MUTABLE-DEPENDENCY", re.compile(r"\buses\s*:\s*[^\s@]+@(?:main|master|latest|v?\d+)\s*$|\bimage\s*:\s*[^\s]+:latest\s*$", re.I),
     "A CI dependency is selected by a mutable reference rather than an immutable digest."),
    ("artifact-or-cache-poisoning", "CI-STATIC-CACHE-KEY", re.compile(r"\bkey\s*:\s*(?:cache|build|deps|dependencies)\s*$", re.I),
     "A cache key is static and may permit cross-revision cache reuse."),
    ("approval-or-protection-bypass", "CI-PRODUCTION-NO-GATE", re.compile(r"\bdeploy(?:ment)?\b.*\bprod(?:uction)?\b", re.I),
     "A production deployment marker requires independent environment/approval verification."),
    ("permission-or-authorization", "CI-WRITE-ALL", re.compile(r"\bpermissions\s*:\s*write-all\b|\ballow_failure\s*:\s*true\b", re.I),
     "The pipeline grants broad write authority or makes a security-sensitive job optional."),
    ("release-or-signing-integrity", "CI-UNSIGNED-RELEASE", re.compile(r"\b(?:publish|release)\b.*--no-(?:sign|provenance)\b", re.I),
     "Release publication explicitly disables signing or provenance."),
    ("dangerous-defaults-and-uncaught-static-misconfiguration", "CI-CONTINUE-ON-ERROR", re.compile(r"\bcontinue-on-error\s*:\s*true\b", re.I),
     "A CI step suppresses failure by default."),
    ("expression-injection", "CI-EXPRESSION-INJECTION",
     re.compile(
         r"\$\{\{\s*github\.event\.(?:issue\.|pull_request\.|comment\.|review\.|discussion\.|commits|head_commit\.message|pages\.|workflow_run\.head_branch)[^}]*\}\}",
         re.I,
     ),
     "Workflow interpolates untrusted github.event context directly into a step or expression."),
)

_PROMOTION_BY_RULE: Mapping[str, tuple[bool, str | None, str]] = {
    "CI-UNTRUSTED-TRIGGER": (True, "ci_untrusted_trigger_execution", "high"),
    "CI-EXPRESSION-INJECTION": (True, "ci_expression_injection", "critical"),
    "CI-PIPE-COMMAND": (True, "ci_unsafe_command_execution", "high"),
    "CI-PRIVILEGED-RUNNER": (True, "ci_privileged_runner", "high"),
    "CI-SECRET-OUTPUT": (True, "ci_secret_exposure", "high"),
    "CI-MUTABLE-DEPENDENCY": (True, "ci_unpinned_dependency", "high"),
    "CI-WRITE-ALL": (True, "ci_excessive_permissions", "high"),
    "CI-UNSIGNED-RELEASE": (True, "ci_unsigned_release", "medium"),
    "CI-STATIC-CACHE-KEY": (False, None, "low"),
    "CI-PRODUCTION-NO-GATE": (False, None, "low"),
    "CI-CONTINUE-ON-ERROR": (False, None, "low"),
}

_EXTERNAL_PROMOTION_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"template[-_ ]injection|expression[-_ ]injection|github\.event\.", re.I),
     "ci_expression_injection", "critical"),
    (re.compile(r"dangerous[-_ ]triggers|pull_request_target|repository_dispatch|pwn[-_ ]request", re.I),
     "ci_untrusted_trigger_execution", "critical"),
    (re.compile(r"unpinned[-_ ]uses|mutable|ckv_gha_7|tag[-_ ]pin|unpinned", re.I),
     "ci_unpinned_dependency", "high"),
    (re.compile(r"excessive[-_ ]permissions|write-all|permissions", re.I),
     "ci_excessive_permissions", "high"),
    (re.compile(r"artipacked|credential|secret|cache[-_ ]poison", re.I),
     "ci_secret_or_artifact_exposure", "high"),
)


def classify_ci_lead_promotion(record: Mapping[str, Any]) -> dict[str, Any]:
    """Classify whether a CI observation/finding should be promoted into an actionable review lead."""
    rule_id = str(record.get("native_rule_id") or "").strip()
    if rule_id in _PROMOTION_BY_RULE:
        lead, attack_class, sev_hint = _PROMOTION_BY_RULE[rule_id]
        return {"lead_candidate": lead, "attack_class": attack_class, "severity_hint": sev_hint}
    sev = str(record.get("severity") or "").strip().lower()
    haystack = " ".join(
        str(record.get(k) or "") for k in ("native_rule_id", "category", "message")
    )
    for pat, attack_class, default_hint in _EXTERNAL_PROMOTION_PATTERNS:
        if pat.search(haystack):
            hint = "critical" if sev == "critical" else default_hint
            return {"lead_candidate": True, "attack_class": attack_class, "severity_hint": hint}
    if sev in {"critical", "high"}:
        return {
            "lead_candidate": True,
            "attack_class": str(record.get("category") or "ci_high_severity_risk").replace("-", "_"),
            "severity_hint": sev,
        }
    return {
        "lead_candidate": False,
        "attack_class": None,
        "severity_hint": sev if sev in {"medium", "low"} else "low",
    }


def line_offsets(data: bytes) -> list[int]:
    return [0, *(match.end() for match in re.finditer(b"\n", data))]


def scan_text(provider: str, path: str, text: str, *, tool_id: str,
              enabled_rules: Mapping[str, bool] | None = None) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    offset = 0
    for number, line in enumerate(text.splitlines(keepends=True), 1):
        for category, rule_id, pattern, message in _RULES:
            if enabled_rules is not None and not enabled_rules.get(rule_id, True):
                continue
            match = pattern.search(line.rstrip("\r\n"))
            if match:
                start = offset + len(line[:match.start()].encode("utf-8"))
                end = offset + len(line[:match.end()].encode("utf-8"))
                base_rec = {
                    "provider": provider, "tool_id": tool_id, "native_rule_id": rule_id,
                    "category": category, "message": message, "severity": "medium",
                    "path": path, "start_line": number, "end_line": number,
                    "start_column": match.start() + 1, "end_column": match.end() + 1,
                    "start_byte": start, "end_byte": end,
                }
                base_rec.update(classify_ci_lead_promotion(base_rec))
                values.append(base_rec)
        offset += len(line.encode("utf-8"))
    return values


def hierarchy(provider: str, path: str, text: str) -> list[dict[str, Any]]:
    """Build a conservative source-backed hierarchy without interpreting a provider DSL."""
    nodes: list[dict[str, Any]] = [{"kind": "pipeline", "name": path, "path": path,
                                    "start_line": 1, "end_line": max(1, len(text.splitlines()))}]
    current_stage = None
    current_job = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if re.match(r"^(stages|workflows)\s*:", stripped):
            current_stage = stripped.split(":", 1)[0]
            nodes.append({"kind": "stage", "name": current_stage, "path": path,
                          "start_line": number, "end_line": number})
        elif re.match(r"^(jobs|job|buildType|stage)\s*[:({]", stripped) or (indent <= 4 and re.match(r"^[A-Za-z0-9_.-]+\s*:\s*$", stripped)):
            current_job = re.split(r"[:({]", stripped, maxsplit=1)[0]
            nodes.append({"kind": "job", "name": current_job, "stage": current_stage,
                          "path": path, "start_line": number, "end_line": number})
        elif re.match(r"^(?:-\s*)?(?:run|script|sh|bat|powershell|checkout|uses)\s*[:({]", stripped):
            nodes.append({"kind": "step", "name": stripped[:120], "job": current_job,
                          "stage": current_stage, "path": path, "start_line": number, "end_line": number})
    return nodes
