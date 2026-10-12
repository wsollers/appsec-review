"""Proof obligations for claims (``obligation-rules/1``, design R4).

The tables in this module are application policy, never prompt text. Any change to them changes
``POLICY_SHA256`` and therefore every adjudication fingerprint that depends on it.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Iterable

from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Predicate

RULES_VERSION = "obligation-rules/1"
PRECONDITIONS_VERSION = "preconditions/1"


class Precondition(StrEnum):
    """Closed precondition vocabulary (``preconditions/1``)."""

    # Attacker position and control.
    ATTACKER_CONTROLS_REQUEST_FIELD = "attacker_controls_request_field"
    ATTACKER_CONTROLS_FILE_CONTENT = "attacker_controls_file_content"
    ATTACKER_CONTROLS_COMMAND_LINE = "attacker_controls_command_line"
    ATTACKER_CONTROLS_ENVIRONMENT_VARIABLE = "attacker_controls_environment_variable"
    ATTACKER_CONTROLS_IPC_MESSAGE = "attacker_controls_ipc_message"
    ATTACKER_CONTROLS_STORED_DATA = "attacker_controls_stored_data"
    ATTACKER_HAS_NETWORK_ACCESS = "attacker_has_network_access"
    ATTACKER_HAS_LOCAL_ACCESS = "attacker_has_local_access"
    ATTACKER_IS_AUTHENTICATED = "attacker_is_authenticated"
    ATTACKER_IS_UNAUTHENTICATED = "attacker_is_unauthenticated"
    VICTIM_INTERACTION_REQUIRED = "victim_interaction_required"
    CONCURRENT_ACCESS_WINDOW = "concurrent_access_window"
    # Configuration- and deployment-scoped conditions; each also requires configuration_enables.
    NON_DEFAULT_CONFIGURATION = "non_default_configuration"
    FEATURE_FLAG_ENABLED = "feature_flag_enabled"
    DEBUG_MODE_ENABLED = "debug_mode_enabled"
    SERVICE_EXPOSED_TO_NETWORK = "service_exposed_to_network"
    PROCESS_RUNS_PRIVILEGED = "process_runs_privileged"
    HARDENING_DISABLED = "hardening_disabled"
    OPTIONAL_COMPONENT_ENABLED = "optional_component_enabled"


CONFIGURATION_SCOPED: frozenset[Precondition] = frozenset({
    Precondition.NON_DEFAULT_CONFIGURATION,
    Precondition.FEATURE_FLAG_ENABLED,
    Precondition.DEBUG_MODE_ENABLED,
    Precondition.SERVICE_EXPOSED_TO_NETWORK,
    Precondition.PROCESS_RUNS_PRIVILEGED,
    Precondition.HARDENING_DISABLED,
    Precondition.OPTIONAL_COMPONENT_ENABLED,
})

ALWAYS_REQUIRED: tuple[Predicate, ...] = (
    Predicate.AFFECTED_CONSTRUCT,
    Predicate.ATTACKER_INPUT_CONTROL,
    Predicate.SOURCE_TO_SINK_REACHABILITY,
    Predicate.MISSING_OR_INEFFECTIVE_GUARD,
    Predicate.SECURITY_IMPACT,
)
CONFIGURATION_PREDICATE = Predicate.CONFIGURATION_ENABLES


def parse_precondition(value: str | Precondition) -> Precondition:
    """Return the closed member for ``value``; unknown values are a schema error."""
    if isinstance(value, Precondition):
        return value
    if not isinstance(value, str):
        raise ValueError("precondition must be a string")
    try:
        return Precondition(value.strip().lower())
    except ValueError as exc:
        raise ValueError(f"unknown {PRECONDITIONS_VERSION} member") from exc


def required_predicates(preconditions: Iterable[str | Precondition]) -> frozenset[Predicate]:
    """Return the predicates a claim with ``preconditions`` must satisfy (R4)."""
    parsed = {parse_precondition(item) for item in preconditions}
    required = set(ALWAYS_REQUIRED)
    if parsed & CONFIGURATION_SCOPED:
        required.add(CONFIGURATION_PREDICATE)
    return frozenset(required)


def _policy_document() -> dict[str, object]:
    return {
        "rules": RULES_VERSION,
        "preconditions": PRECONDITIONS_VERSION,
        "predicates": sorted(item.value for item in Predicate),
        "always_required": sorted(item.value for item in ALWAYS_REQUIRED),
        "configuration_predicate": CONFIGURATION_PREDICATE.value,
        "precondition_scopes": {
            item.value: "configuration" if item in CONFIGURATION_SCOPED else "attacker"
            for item in sorted(Precondition, key=lambda member: member.value)
        },
    }


POLICY_SHA256 = sha256_hex(_policy_document())
