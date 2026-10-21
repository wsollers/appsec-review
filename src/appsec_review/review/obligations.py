"""Proof obligations for claims (``obligation-rules/1``, design R4).

The tables in this module are application policy, never prompt text. Any change to them changes
``POLICY_SHA256`` and therefore every adjudication fingerprint that depends on it. The policy also
pins the evidence-admissibility rule version and the graph-fact predicate mapping
(``graph-fact-predicates/1``, re-exported here from the shared code-graph contract), so a change to
which graph facts may satisfy which predicate changes the policy hash.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Iterable, Mapping

from appsec_review.graph.contract import (
    ADMISSIBILITY_RULE as GRAPH_FACT_ADMISSIBILITY_RULE, ATTACKER_REACHABLE_SOURCES, FACT_PREDICATES_RULE,
    GRAPH_FACT_PREDICATES, Family,
)
from appsec_review.retrieval.model import EntityKind, LogicalIdentity
from appsec_review.review import admission
from appsec_review.review.identity import sha256_hex
from appsec_review.review.models import Claim, Predicate, SecurityPredicate

# /2: the required predicates depend on the claim family and ``security_impact`` is derived.
RULES_VERSION = "obligation-rules/2"
PRECONDITIONS_VERSION = "preconditions/1"
# R3 classification rules (review/evidence.py). /2 adds the graph-fact branch: graph kinds are
# direct only for their mapped predicates and only when the re-resolved fact is direct-eligible.
ADMISSIBILITY_RULES_VERSION = "evidence-admissibility/2"
# Pinned next to the admissibility version: which kind of cited content may bear on which predicate.
PREDICATE_ADMISSION_VERSION = admission.VERSION


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

class ObligationFamily(StrEnum):
    """Which proof a claim owes, from its security predicate and weakness (``obligation-rules/2``).

    A memory or injection claim owes a source-to-sink argument; a hard-coded secret, a weak
    primitive, a misconfiguration or a vulnerable dependency does not have one, and demanding it
    would either block every such claim or invite a vacuous citation. The predicate vocabulary is
    unchanged; only which predicates a family requires differs.
    """

    MEMORY_AND_INPUT = "memory_and_input"   # default: every weakness not listed below
    SECRETS = "secrets"
    CRYPTOGRAPHY = "cryptography"
    CONFIGURATION = "configuration"
    SUPPLY_CHAIN = "supply_chain"           # vulnerable dependencies, CI workflows


_P = Predicate
# The default family's set. The name is kept for the many callers that mean "the usual obligations".
ALWAYS_REQUIRED: tuple[Predicate, ...] = (
    _P.AFFECTED_CONSTRUCT,
    _P.ATTACKER_INPUT_CONTROL,
    _P.SOURCE_TO_SINK_REACHABILITY,
    _P.MISSING_OR_INEFFECTIVE_GUARD,
)
REQUIRED_BY_FAMILY: dict[ObligationFamily, tuple[Predicate, ...]] = {
    ObligationFamily.MEMORY_AND_INPUT: ALWAYS_REQUIRED,
    # The secret is in the shipped artifact and nothing else keeps it from use (rotation, scoping).
    ObligationFamily.SECRETS: (_P.AFFECTED_CONSTRUCT, _P.MISSING_OR_INEFFECTIVE_GUARD),
    # The weak primitive is at the construct and no compensating control protects the data.
    ObligationFamily.CRYPTOGRAPHY: (_P.AFFECTED_CONSTRUCT, _P.MISSING_OR_INEFFECTIVE_GUARD),
    # The construct exists and the configuration that makes it a weakness is in effect.
    ObligationFamily.CONFIGURATION: (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES),
    # The component is present and enabled in this build or workflow.
    ObligationFamily.SUPPLY_CHAIN: (_P.AFFECTED_CONSTRUCT, _P.CONFIGURATION_ENABLES),
}
# ``security_impact`` is derived, never cited: no entity kind is DIRECT for it under
# ``predicate-admission/1``, because impact follows from the adjudicated facts of the claim (its
# weakness class and the predicates above), so requiring a cited relation would make ``confirmed``
# unreachable. It stays in the vocabulary: relations may still be recorded for it (analyst-assessed
# at best), and scoring derives the impact class from the claim's CWE.
DERIVED_PREDICATES: frozenset[Predicate] = frozenset({_P.SECURITY_IMPACT})
# CWE ids that make a claim a secrets claim whatever security predicate the worker chose.
SECRET_CWES: frozenset[str] = frozenset({"CWE-798", "CWE-259", "CWE-321", "CWE-256", "CWE-312", "CWE-522"})
_SECURITY_PREDICATE_FAMILY: dict[SecurityPredicate, ObligationFamily] = {
    SecurityPredicate.CRYPTO_WEAKNESS: ObligationFamily.CRYPTOGRAPHY,
    SecurityPredicate.INSECURE_CONFIGURATION: ObligationFamily.CONFIGURATION,
    SecurityPredicate.SUPPLY_CHAIN_COMPROMISE: ObligationFamily.SUPPLY_CHAIN,
}
# Claims about these affected entities concern the build itself, so the configuration predicate is
# owed whatever preconditions the proposing model chose to list.
BUILD_CONFIGURATION_KINDS: frozenset[EntityKind] = frozenset({EntityKind.BUILD_ACTION, EntityKind.COMPILE_UNIT})
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


def obligation_family(security_predicate: SecurityPredicate | str | None = None,
                      weakness_cwe: str | None = None) -> ObligationFamily:
    """The claim's obligation family; a secrets CWE wins, anything unlisted is the default family."""
    if weakness_cwe in SECRET_CWES:
        return ObligationFamily.SECRETS
    if security_predicate is None:
        return ObligationFamily.MEMORY_AND_INPUT
    return _SECURITY_PREDICATE_FAMILY.get(SecurityPredicate(security_predicate), ObligationFamily.MEMORY_AND_INPUT)


def _concerns_build(affected_entities: Iterable[str]) -> bool:
    for value in affected_entities:
        try:
            if LogicalIdentity.parse(str(value)).kind in BUILD_CONFIGURATION_KINDS:
                return True
        except ValueError:
            continue
    return False


def required_predicates(preconditions: Iterable[str | Precondition], *,
                        security_predicate: SecurityPredicate | str | None = None,
                        weakness_cwe: str | None = None,
                        affected_entities: Iterable[str] = ()) -> frozenset[Predicate]:
    """Return the predicates a claim must satisfy (R4).

    The set is the claim family's (``REQUIRED_BY_FAMILY``), plus ``configuration_enables`` when any
    precondition is configuration-scoped or when an affected entity is a build action or compile
    unit. Called with preconditions only, it is the default family's set.
    """
    parsed = {parse_precondition(item) for item in preconditions}
    required = set(REQUIRED_BY_FAMILY[obligation_family(security_predicate, weakness_cwe)])
    if parsed & CONFIGURATION_SCOPED or _concerns_build(affected_entities):
        required.add(CONFIGURATION_PREDICATE)
    return frozenset(required)


def required_predicates_for(claim: Claim) -> frozenset[Predicate]:
    """:func:`required_predicates` for a claim record."""
    return required_predicates(claim.preconditions, security_predicate=claim.security_predicate,
                               weakness_cwe=claim.weakness_cwe, affected_entities=claim.affected_entities)


def _graph_predicates_record(mapping: Mapping[Family, Iterable[Predicate]]) -> dict[str, object]:
    return {
        "rule": FACT_PREDICATES_RULE, "fact_admissibility": GRAPH_FACT_ADMISSIBILITY_RULE,
        "families": {Family(family).value: sorted(Predicate(item).value for item in predicates)
                     for family, predicates in sorted(mapping.items(), key=lambda item: Family(item[0]).value)},
        "attacker_reachable_sources": sorted(item.value for item in ATTACKER_REACHABLE_SOURCES),
    }


def _policy_document(graph_predicates: Mapping[Family, Iterable[Predicate]] = GRAPH_FACT_PREDICATES
                     ) -> dict[str, object]:
    return {
        "rules": RULES_VERSION,
        "admissibility": ADMISSIBILITY_RULES_VERSION,
        "predicate_admission": {"version": PREDICATE_ADMISSION_VERSION, "table_sha256": admission.TABLE_SHA256},
        "graph_fact_predicates": _graph_predicates_record(graph_predicates),
        "preconditions": PRECONDITIONS_VERSION,
        "predicates": sorted(item.value for item in Predicate),
        "always_required": sorted(item.value for item in ALWAYS_REQUIRED),
        "required_by_family": {family.value: sorted(item.value for item in predicates)
                               for family, predicates in sorted(REQUIRED_BY_FAMILY.items(),
                                                                key=lambda entry: entry[0].value)},
        "derived_predicates": sorted(item.value for item in DERIVED_PREDICATES),
        "secret_cwes": sorted(SECRET_CWES),
        "security_predicate_families": {key.value: value.value for key, value
                                        in sorted(_SECURITY_PREDICATE_FAMILY.items(), key=lambda e: e[0].value)},
        "build_configuration_kinds": sorted(item.value for item in BUILD_CONFIGURATION_KINDS),
        "configuration_predicate": CONFIGURATION_PREDICATE.value,
        "precondition_scopes": {
            item.value: "configuration" if item in CONFIGURATION_SCOPED else "attacker"
            for item in sorted(Precondition, key=lambda member: member.value)
        },
    }


POLICY_SHA256 = sha256_hex(_policy_document())

__all__ = ["ADMISSIBILITY_RULES_VERSION", "ALWAYS_REQUIRED", "BUILD_CONFIGURATION_KINDS", "CONFIGURATION_PREDICATE",
           "CONFIGURATION_SCOPED", "DERIVED_PREDICATES", "FACT_PREDICATES_RULE", "GRAPH_FACT_PREDICATES",
           "ObligationFamily", "POLICY_SHA256", "PRECONDITIONS_VERSION", "PREDICATE_ADMISSION_VERSION",
           "Precondition", "REQUIRED_BY_FAMILY", "RULES_VERSION", "SECRET_CWES", "obligation_family",
           "parse_precondition", "required_predicates", "required_predicates_for"]
