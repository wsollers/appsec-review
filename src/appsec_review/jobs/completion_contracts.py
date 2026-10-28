"""Versioned contracts shared by evidence completion, remediation and dossier jobs."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import re
from typing import Any, Mapping

from appsec_review.review.models import IntegrityError


ATTACK_CHAIN_SCHEMA = "appsec-review/attack-chain/1"
ATTACK_CHAIN_MANIFEST_SCHEMA = "appsec-review/attack-chain-manifest/1"
REMEDIATION_PLAN_SCHEMA = "appsec-review/remediation-plan/1"
REMEDIATION_PLANNING_SCHEMA = "appsec-review/remediation-planning/1"
REMEDIATION_PLANNING_HANDOFF_SCHEMA = "appsec-review/remediation-planning-handoff/1"
REMEDIATION_VALIDATION_SCHEMA = "appsec-review/remediation-validation/1"
REMEDIATION_VALIDATION_SUMMARY_SCHEMA = "appsec-review/remediation-validations/1"
REMEDIATION_VALIDATION_HANDOFF_SCHEMA = "appsec-review/remediation-validation-handoff/1"
DOSSIER_SCHEMA = "appsec-review/dossier/1"
DOSSIER_PUBLICATION_SCHEMA = "appsec-review/dossier-publication/1"
DOSSIER_PUBLICATION_HANDOFF_SCHEMA = "appsec-review/dossier-publication-handoff/1"
NONEXECUTION_POLICY = "not_performed_by_policy"

REMEDIATION_PLANNING_JOB = "job_remediation_planning"
REMEDIATION_VALIDATION_JOB = "job_remediation_validation"
DOSSIER_PUBLICATION_JOB = "job_dossier_publication"

_SHA256 = re.compile(r"[0-9a-f]{64}")


class CompletionCapability(StrEnum):
    POC_GENERATION = "poc_generation"
    ATTACK_CHAINS = "attack_chains"
    REMEDIATION_PLANNING = "remediation_planning"
    REMEDIATION_VALIDATION = "remediation_validation"
    DOSSIERS = "dossiers"


class DossierKind(StrEnum):
    CONFIRMED_FINDING = "confirmed_finding"
    POC = "poc"


class RemediationValidationStatus(StrEnum):
    BUILD_CHECKED = "build_checked"
    STATIC_CHECKED = "static_checked"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    MANUAL_VALIDATION_REQUIRED = "manual_validation_required"


@dataclass(frozen=True, slots=True)
class FindingBinding:
    """An attachment identifies exact accepted finding bytes, not just a claim."""

    claim_id: str
    finding_package_id: str
    sha256: str

    def __post_init__(self) -> None:
        for name in ("claim_id", "finding_package_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 200:
                raise IntegrityError(f"finding binding has an invalid {name}")
        if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
            raise IntegrityError("finding binding has an invalid sha256")

    def as_dict(self) -> dict[str, str]:
        return {"claim_id": self.claim_id, "finding_package_id": self.finding_package_id, "sha256": self.sha256}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> FindingBinding:
        if not isinstance(value, Mapping) or set(value) != {"claim_id", "finding_package_id", "sha256"}:
            raise IntegrityError("finding binding must contain exactly claim_id, finding_package_id and sha256")
        return cls(value["claim_id"], value["finding_package_id"], value["sha256"])


def nonexecution_assurance() -> dict[str, Any]:
    """A fresh record that cannot be mistaken for an observed runtime proof."""
    return {"execution": NONEXECUTION_POLICY, "runtime_verified": False, "result_id": None}


def verify_nonexecution_assurance(value: object) -> None:
    if (not isinstance(value, Mapping) or value.get("execution") != NONEXECUTION_POLICY
            or value.get("runtime_verified") is not False or "result_id" not in value
            or value["result_id"] is not None):
        raise IntegrityError("compile-only evidence cannot assert runtime verification or an execution result")
