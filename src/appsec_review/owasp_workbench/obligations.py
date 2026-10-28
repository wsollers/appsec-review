"""Reviewed, bounded proof procedures, not model-generated control interpretations.

The full catalog is selected independently. A control without a procedure is an unresolved
coverage row. These source procedures assess a named site, never a whole deployment.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping, Sequence

from .standards import digest


VERSION = "owasp-proof-obligations/1"


@dataclass(frozen=True, slots=True)
class Procedure:
    family: str
    version: str
    control: str
    invariant: str
    subject_pattern: str
    support: str
    contradiction: str
    effective_control_questions: tuple[str, ...]
    required_categories: tuple[str, ...] = ("source",)
    evidence_mode: str = "static_source"


PROCEDURES = (
    Procedure("ASVS", "5.0.0", "V1.2.4",
              "The named database query site separates query structure from untrusted data.",
              r"(?i)\b(?:execute|executemany|raw|query|prepare)\s*\(",
              "The cited query and argument construction show parameter binding or a bounded safe alternative.",
              "The cited query construction demonstrably inserts attacker-influenced data into query structure.",
              ("Inspect query construction and its parameters, not just the call name.",
               "Inspect upstream validation, ORM behavior, alternate query paths and trusted-only inputs.")),
    Procedure("ASVS", "5.0.0", "V6.2.1",
              "The named user-password validation site enforces at least eight characters.",
              r"(?i)(?:len\s*\(\s*(?:password|passwd)|(?:password|passwd)\.length|min_password_length)",
              "The complete named validation path rejects user passwords shorter than eight characters.",
              "A concrete named validation path accepts shorter user passwords; a missing excerpt is not proof.",
              ("Inspect alternate registration, reset and change-password paths and upstream policy.",
               "Distinguish user-set passwords from machine credentials and test-only values.")),
    Procedure("ASVS", "5.0.0", "V8.2.1",
              "The named protected operation has an effective trusted-boundary authorization check.",
              r"(?i)(?:@\w+(?:\.\w+)*\.(?:route|get|post|put|delete)\s*\(|\bdef\s+(?:admin|delete_user|set_role))",
              "The named operation and its invoked guard enforce an explicit permission at a trusted boundary.",
              "A concrete path to the named protected operation bypasses the relevant permission check.",
              ("Inspect middleware, service-level guards, policy defaults and alternate entry points.",
               "Client-side checks and declarations do not establish trusted-boundary enforcement.")),
    Procedure("MASVS", "2.1.0", "MASVS-NETWORK-1",
              "The named mobile network connection protects data in transit in the observed environment.",
              r"(?i)\b(?:https?|tls|ssl|urlsession|okhttp)\b",
              "Accepted environment-bound runtime observations establish the negotiated protection.",
              "Accepted environment-bound runtime observations demonstrate an unprotected connection.",
              ("Inspect platform trust configuration and alternate connections.",),
              ("runtime_observation",), "dynamic_runtime"),
)


def procedure_for(control: Mapping[str, Any]) -> Procedure | None:
    family = control.get("family", control.get("standard"))
    native = control.get("id", control.get("control_id"))
    return next((rule for rule in PROCEDURES if (rule.family, rule.version, rule.control)
                 == (family, control.get("version"), native)), None)


def subjects(rule: Procedure, evidence: Mapping[str, Any]) -> list[str]:
    if evidence.get("category") not in rule.required_categories:
        return []
    excerpt = evidence.get("excerpt", "")
    if not isinstance(excerpt, str) or not re.search(rule.subject_pattern, excerpt):
        return []
    # Entity/span identities, not a model's chosen label, define the assessed subject.
    return [digest({"procedure": asdict(rule),
                    "source_identity": evidence["reference"]["source_identity"]})]


def instantiate(control: Mapping[str, Any], row: Mapping[str, Any],
                evidence: Sequence[Mapping[str, Any]], *, max_subjects: int) -> list[dict[str, Any]]:
    rule = procedure_for(control)
    common = {
        "rule_version": VERSION, "control_identity": row["control_identity"],
        "component_id": row["component_id"], "scope": {
            "run_id": row.get("run_id"), "target_snapshot": row.get("target_id"),
            "component_id": row["component_id"], "build_scope": "per-reference; no deployment claim",
        },
        "static_limits": ["No runtime/deployment state, exploitability, absence of alternate paths, "
                          "or component-wide safety is established by a bounded source excerpt."],
    }
    if rule is None:
        return [{**common, "obligation_id": f"{row['row_id']}:unsupported", "subject_id": None,
                 "supported": False, "reason": "no reviewed versioned proof procedure",
                 "evidence_mode": row["evidence_mode"], "required_categories": [],
                 "evidence_ids": []}]
    candidates = [(item, subject) for item in evidence for subject in subjects(rule, item)]
    obligations = []
    for item, subject in candidates[:max_subjects]:
        obligations.append({
            **common, "obligation_id": f"{row['row_id']}:{subject[:20]}", "subject_id": subject,
            "supported": True, "procedure": asdict(rule), "invariant": rule.invariant,
            "evidence_mode": rule.evidence_mode, "required_categories": list(rule.required_categories),
            "evidence_ids": [item["evidence_id"]], "material": True,
            "insufficient": "Missing, truncated, ambiguous or declaration-only evidence remains unknown.",
        })
    if not candidates or len(candidates) > max_subjects:
        obligations.append({
            **common, "obligation_id": f"{row['row_id']}:coverage", "subject_id": None,
            "supported": False, "material": True, "procedure": asdict(rule),
            "reason": ("no resolving subject/evidence for this procedure" if not candidates
                       else f"{len(candidates) - max_subjects} subjects omitted by max_subjects_per_control"),
            "evidence_mode": rule.evidence_mode, "required_categories": list(rule.required_categories),
            "evidence_ids": [],
        })
    return obligations
