"""Deterministic ship-block policy ``ship-block-policy/1`` (design decision 1, with decision 2).

``decide`` is a pure function of one finding's adjudicated state, its ``application_risk_matrix/3``
technical severity, its dependency-lead and CISA KEV reference inputs, and whether its verifier ran
on a different model profile than every red cell on the claim. The rows, first match wins:

=====  ==========================================================  ===============================================
row    condition                                                    status
=====  ==========================================================  ===============================================
1      state ``confirmed``, qualifies, distinct verification held   ``ship_blocking``
2      state ``confirmed``, qualifies, distinct verification not    ``ship_blocking_pending_distinct_verification``
3      state ``supported``, qualifies                               ``needs_verification``
4      state ``confirmed`` or ``supported``, does not qualify,      ``decision_pending``
       and a material input is missing (technical severity
       unrated, or material missing factors listed)
5      anything else                                                ``not_ship_blocking``
=====  ==========================================================  ===============================================

Precedence: rows 1-3 come first because a qualifying finding already names its next action (block,
obtain a distinct verifier, obtain independent confirmation), and a KEV-listed dependency qualifies
even when its severity is unrated. ``decision_pending`` therefore applies only when the finding
does not qualify *and* the missing input could still change that; it is never an affirmative
release decision. ``not_ship_blocking`` is reserved for findings that were rated and fall below the
blocking thresholds, and for claim states that cannot block (contradicted, not reachable,
insufficient evidence, duplicate, out of scope), which are never published as findings at all.

A finding *qualifies* when its ``application_risk_matrix/3`` technical severity is in
``blocking_technical_severities`` (default high, critical), or when ``kev_dependency_blocks`` is on
and it is a dependency finding (proposed from a lane A lead of a ``dependency_lead_families``
family) whose reference input is KEV-listed. *Distinct verification held* is true when
``require_distinct_model`` is off or the verifier's model profile (provider and model) differs from
every red cell's. CVSS and SSVC outputs are recorded as displayed context and never decide.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any, Iterable, Mapping

from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import ClaimState
from appsec_review.review.scoring.risk_model import BANDS

POLICY_VERSION = "ship-block-policy/1"
SEVERITY_PROVIDER = "application_risk_matrix/3"   # the only implementation whose rating may decide
SEVERITY_BANDS = BANDS                            # application_risk_matrix/3 technical severity bands
DEPENDENCY_FAMILIES = ("dependency_advisory", "artifact_scanner")


class ShipBlockStatus(StrEnum):
    SHIP_BLOCKING = "ship_blocking"
    PENDING_DISTINCT_VERIFICATION = "ship_blocking_pending_distinct_verification"
    NEEDS_VERIFICATION = "needs_verification"
    DECISION_PENDING = "decision_pending"
    NOT_SHIP_BLOCKING = "not_ship_blocking"


@dataclass(frozen=True, slots=True)
class ShipBlockSettings:
    """``settings.ship_block``; the defaults are decision 1 as recorded."""

    blocking_technical_severities: tuple[str, ...] = ("high", "critical")
    kev_dependency_blocks: bool = True
    dependency_lead_families: tuple[str, ...] = DEPENDENCY_FAMILIES

    def __post_init__(self) -> None:
        for name in ("blocking_technical_severities", "dependency_lead_families"):
            value = getattr(self, name)
            if (not isinstance(value, tuple) or any(not isinstance(item, str) for item in value)
                    or len(set(value)) != len(value)):
                raise ValueError(f"ship_block.{name} must be an array of distinct strings")
        if not self.blocking_technical_severities:
            raise ValueError("ship_block.blocking_technical_severities must name at least one band")
        unknown = set(self.blocking_technical_severities) - set(SEVERITY_BANDS)
        if unknown:
            raise ValueError(f"ship_block.blocking_technical_severities has unknown bands: {', '.join(sorted(unknown))}")
        if not isinstance(self.kev_dependency_blocks, bool):
            raise ValueError("ship_block.kev_dependency_blocks must be a Boolean")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None, field: str = "ship_block",
                     known_families: Iterable[str] = ()) -> "ShipBlockSettings":
        """Settings from a TOML table; unknown keys are rejected and absent keys keep their default."""
        if value is None:
            return cls()
        if not isinstance(value, Mapping):
            raise ValueError(f"{field} must be a table")
        unknown = sorted(str(key) for key in set(value) - {item.name for item in fields(cls)})
        if unknown:
            raise ValueError(f"{field} has unknown settings: {', '.join(unknown)}")
        data = {key: tuple(item) if isinstance(item, list) else item for key, item in value.items()}
        try:
            settings = cls(**data)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc).replace("ship_block.", f"{field}.", 1)) from exc
        families = set(known_families)
        if families and set(settings.dependency_lead_families) - families:
            extra = sorted(set(settings.dependency_lead_families) - families)
            raise ValueError(f"{field}.dependency_lead_families has unknown lead families: {', '.join(extra)}")
        return settings

    def record(self) -> dict[str, Any]:
        return {"blocking_technical_severities": list(self.blocking_technical_severities),
                "kev_dependency_blocks": self.kev_dependency_blocks,
                "dependency_lead_families": list(self.dependency_lead_families)}


def policy_sha256(settings: ShipBlockSettings, require_distinct_model: bool) -> str:
    """Identity of the policy as configured: version, severity provider, thresholds, distinctness."""
    return sha256_hex({"policy": POLICY_VERSION, "severity_provider": SEVERITY_PROVIDER,
                       "settings": settings.record(), "require_distinct_model": bool(require_distinct_model),
                       "rows": [status.value for status in ShipBlockStatus],
                       "unrated_precedence": "qualifying_statuses_before_decision_pending"})


@dataclass(frozen=True, slots=True)
class ShipBlockInputs:
    """Everything the policy reads for one finding; each field is cited in the decision record."""

    claim_state: ClaimState
    technical_severity: str | None          # application_risk_matrix/3 rating; None when unrated
    severity_score_id: str | None           # the score package that carried it
    lead_families: tuple[str, ...]          # lead families of the lane A lead packages that proposed it
    kev_listed: bool | None                 # merged reference input (None: no advisory context)
    verifier_model_distinct: bool
    # Material missing inputs of the technical severity: the factors that kept it unrated, and the
    # severity range they leave open (None when the provider could not bound it).
    severity_missing_factors: tuple[str, ...] = ()
    severity_floor: str | None = None
    severity_ceiling: str | None = None


@dataclass(frozen=True, slots=True)
class ShipBlockDecision:
    status: ShipBlockStatus
    conditions: Mapping[str, bool]
    reasons: tuple[str, ...]
    policy_sha256: str

    def record(self, inputs: ShipBlockInputs, *, adjudication_id: str, verification_review_id: str | None,
               displayed_context: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "policy": POLICY_VERSION, "policy_sha256": self.policy_sha256, "status": self.status.value,
            "conditions": dict(self.conditions), "reasons": list(self.reasons),
            "inputs": {"claim_state": inputs.claim_state.value,
                       "technical_severity": {"provider": SEVERITY_PROVIDER, "rating": inputs.technical_severity,
                                              "score_id": inputs.severity_score_id,
                                              "severity_floor": inputs.severity_floor,
                                              "severity_ceiling": inputs.severity_ceiling,
                                              "missing_factors": sorted(inputs.severity_missing_factors)},
                       "lead_families": sorted(inputs.lead_families), "kev_listed": inputs.kev_listed,
                       "verifier_model_distinct": inputs.verifier_model_distinct},
            "citations": {"adjudication_id": adjudication_id,
                          "score_ids": [inputs.severity_score_id] if inputs.severity_score_id else [],
                          "verification_review_id": verification_review_id},
            "displayed_context": {"decides": False, **dict(displayed_context)},
        }


def decide(inputs: ShipBlockInputs, settings: ShipBlockSettings = ShipBlockSettings(), *,
           require_distinct_model: bool = True) -> ShipBlockDecision:
    """Apply ``ship-block-policy/1``; deterministic for the same inputs and settings."""
    state = ClaimState(inputs.claim_state)
    severity = inputs.technical_severity in settings.blocking_technical_severities
    dependency = bool(set(inputs.lead_families) & set(settings.dependency_lead_families))
    kev = settings.kev_dependency_blocks and dependency and inputs.kev_listed is True
    distinct_held = (not require_distinct_model) or inputs.verifier_model_distinct
    conditions = {"claim_confirmed": state is ClaimState.CONFIRMED, "claim_supported": state is ClaimState.SUPPORTED,
                  "technical_severity_qualifies": severity, "dependency_finding": dependency,
                  "kev_dependency_qualifies": kev, "distinct_verification_required": bool(require_distinct_model),
                  "verifier_model_distinct": bool(inputs.verifier_model_distinct)}
    reasons: list[str] = []
    if severity:
        reasons.append(f"technical_severity_{inputs.technical_severity}")
    if kev:
        reasons.append("kev_listed_dependency")
    publishable = state in (ClaimState.CONFIRMED, ClaimState.SUPPORTED)
    unrated = inputs.technical_severity is None
    missing = tuple(sorted(inputs.severity_missing_factors))
    if unrated and publishable:
        reasons.append("technical_severity_unrated")
    if publishable:
        reasons.extend(f"missing_factor_{name}" for name in missing)
    qualifies = severity or kev
    conditions["decision_input_missing"] = publishable and (unrated or bool(missing))
    if state is ClaimState.CONFIRMED and qualifies and distinct_held:
        status = ShipBlockStatus.SHIP_BLOCKING
    elif state is ClaimState.CONFIRMED and qualifies:
        status = ShipBlockStatus.PENDING_DISTINCT_VERIFICATION
        reasons.append("verifier_model_not_distinct")
    elif state is ClaimState.SUPPORTED and qualifies:
        status = ShipBlockStatus.NEEDS_VERIFICATION
        reasons.append("claim_not_confirmed")
    elif conditions["decision_input_missing"]:
        status = ShipBlockStatus.DECISION_PENDING
    else:
        status = ShipBlockStatus.NOT_SHIP_BLOCKING
    return ShipBlockDecision(status, conditions, tuple(reasons), policy_sha256(settings, require_distinct_model))


def summarize(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Counts per status, overall and per lane, from ``{"lane": ..., "status": ...}`` records."""
    statuses = [status.value for status in ShipBlockStatus]
    total = {status: 0 for status in statuses}
    lanes = {lane: {status: 0 for status in statuses} for lane in ("lead", "hunt")}
    for record in records:
        total[record["status"]] += 1
        lanes[record["lane"]][record["status"]] += 1
    return {"policy": POLICY_VERSION, "by_status": total, "by_lane": lanes}


__all__ = ["DEPENDENCY_FAMILIES", "POLICY_VERSION", "SEVERITY_BANDS", "SEVERITY_PROVIDER", "ShipBlockDecision",
           "ShipBlockInputs", "ShipBlockSettings", "ShipBlockStatus", "decide", "policy_sha256", "summarize"]
