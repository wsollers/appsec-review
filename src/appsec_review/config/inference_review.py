"""Typed settings for ``job_inference_security_review``.

Every table rejects unknown keys. ``teams.review_teams`` is capacity, not semantics: it is the only
job setting a local overlay may change, and :func:`semantic_settings_view` strips it so that runs at
different concurrency share cell, lane, and round fingerprints. Everything else here is semantic.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping

from appsec_review.review.models import Role


JOB_ID = "job_inference_security_review"
REVIEW_TEAMS_KEY = f"jobs.{JOB_ID}.settings.teams.review_teams"
POOLS_KEY = "orchestration.dagster.pools.*"
CAPACITY_KEYS: tuple[str, ...] = (REVIEW_TEAMS_KEY, POOLS_KEY)
SEMANTIC_VIEW_SCHEMA = "appsec-review/inference-review-semantic-settings/1"

REPORTED_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
REASONING_LEVELS = ("low", "medium", "high", "xhigh", "max")
SCORING_PROVIDERS = ("cvss_v4", "cvss_v31_compat", "application_risk_matrix", "ssvc_decision")
CVSS_METRIC_GROUPS = ("base", "threat", "environmental", "supplemental")
IMPACT_CLASSES = ("critical", "high", "medium", "low")
ELIGIBILITY_OPERATORS = ("in",)
_RULE_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}/[1-9][0-9]{0,3}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_PROFILE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}")
_FIELD = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,7}")

_PREFIX = f"jobs.{JOB_ID}.settings"


def _table(value: object, field: str, required: set[str], optional: set[str] = frozenset()
           ) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a table")
    unknown = set(value) - required - optional
    if unknown:
        raise ValueError(f"{field} has unknown settings: {', '.join(sorted(map(str, unknown)))}")
    missing = required - set(value)
    if missing:
        raise ValueError(f"{field} is missing settings: {', '.join(sorted(missing))}")
    return value


def _int(value: object, field: str, low: int = 1, high: int = 2**53) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{field} must be an integer between {low} and {high}")
    return value


def _ratio(value: object, field: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{field} must be a number between 0 and 1")
    return float(value)


def _bool(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a Boolean")
    return value


def _str(value: object, field: str, pattern: re.Pattern[str] = _IDENTIFIER) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{field} is invalid")
    return value


def _choices(value: object, field: str, allowed: tuple[str, ...], *, empty: bool = False) -> tuple[str, ...]:
    if (not isinstance(value, list) or (not value and not empty) or
            any(not isinstance(item, str) for item in value) or len(set(value)) != len(value)):
        raise ValueError(f"{field} must be an array of distinct strings")
    unknown = set(value) - set(allowed)
    if unknown:
        raise ValueError(f"{field} has unknown values: {', '.join(sorted(unknown))}")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class RoundSettings:
    max_rounds: int
    stable_rounds_required: int
    max_active_claims: int
    max_attack_chains: int

    def __post_init__(self) -> None:
        if self.stable_rounds_required > self.max_rounds:
            raise ValueError(f"{_PREFIX}.rounds.stable_rounds_required must not exceed max_rounds")


@dataclass(frozen=True, slots=True)
class TeamSettings:
    review_teams: int          # capacity only; never fingerprinted
    red_per_team: int
    blue_per_team: int
    verifier_per_team: int


@dataclass(frozen=True, slots=True)
class LaneSettings:
    lead_admission: tuple[str, ...]
    lead_budget_share: float
    lead_max_claims_per_package: int
    hunt_max_units: int
    hunt_max_claims_per_package: int
    hunt_panel_rule: str
    incomplete_gap_ratio: float

    def __post_init__(self) -> None:
        if "unknown" not in self.lead_admission:
            raise ValueError(f"{_PREFIX}.lanes.lead_admission must admit unknown severity; "
                             "unknown is never treated as low")

    @property
    def hunt_budget_share(self) -> float:
        return 1.0 - self.lead_budget_share


@dataclass(frozen=True, slots=True)
class PackageAssemblySettings:
    """Package assembly bounds (review-package contract gates 3-6); admission and the hunt cutoff
    come from ``lanes.lead_admission`` and ``lanes.hunt_max_units``."""

    hunt_menu_partition_size: int
    unit_max_files: int
    max_context_entries: int
    max_package_bytes: int
    max_page_size: int
    max_pages: int
    max_depth: int


@dataclass(frozen=True, slots=True)
class BudgetSettings:
    budget_team_packages: int
    max_model_turns: int
    max_input_tokens: int
    max_output_tokens: int
    max_retrieval_queries: int
    timeout_seconds: int


@dataclass(frozen=True, slots=True)
class RetrySettings:
    max_attempts: int
    retry_on_timeout: bool
    retry_on_provider_error: bool
    retry_on_invalid_output: bool
    backoff_seconds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ModelProfileSettings:
    """One ``settings.models.<profile>``; the existing ``settings.model`` field shape plus cell caps."""

    provider: str
    model: str
    reasoning: str
    max_input_tokens: int
    max_output_tokens: int
    max_queries: int
    max_turns: int
    timeout_seconds: int
    retries: int = 0
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class RoleSettings:
    model_profile: str
    workers: int
    require_distinct_from_roles: tuple[Role, ...] = ()


@dataclass(frozen=True, slots=True)
class RoutingSettings:
    persona_rule: str
    stack_rule: str


@dataclass(frozen=True, slots=True)
class ScoringProviderSettings:
    implementation: str
    metric_groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScoringSettings:
    enabled_providers: tuple[str, ...]
    priority_policy: str
    override_policy: str
    providers: Mapping[str, ScoringProviderSettings]
    cwe_impact_classes: Mapping[str, str]   # application_risk_matrix impact_class axis


@dataclass(frozen=True, slots=True)
class PocEligibilityRule:
    provider: str
    field: str
    operator: str
    values: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PocSettings:
    execution_enabled: bool
    require_target_authorization: bool
    require_isolation: bool
    network: str
    read_only_target: bool
    allow_host_execution: bool
    allow_production_services: bool
    allow_real_credentials: bool
    allow_privileged_containers: bool
    allow_docker_socket: bool
    allow_deploy_sign_publish: bool
    max_attempts_per_claim: int
    cpu_limit: float
    memory_mb: int
    timeout_seconds: int
    scratch_mb: int
    eligibility_rules: tuple[PocEligibilityRule, ...]


@dataclass(frozen=True, slots=True)
class InferenceSecurityReviewSettings:
    rounds: RoundSettings
    teams: TeamSettings
    lanes: LaneSettings
    packages: PackageAssemblySettings
    budgets: BudgetSettings
    retry: RetrySettings
    models: Mapping[str, ModelProfileSettings]
    roles: Mapping[Role, RoleSettings]
    routing: RoutingSettings
    scoring: ScoringSettings
    poc: PocSettings

    def profile_for(self, role: Role) -> ModelProfileSettings:
        """The model profile a role uses; an unconfigured role uses ``default``."""
        configured = self.roles.get(Role(role))
        return self.models[configured.model_profile if configured else "default"]

    def as_document(self) -> dict[str, Any]:
        """Canonical JSON-compatible form of every setting."""
        return _jsonable(self)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {name: _jsonable(getattr(value, name)) for name in value.__dataclass_fields__}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Role):
        return value.value
    return value


def semantic_settings_view(settings: InferenceSecurityReviewSettings) -> dict[str, Any]:
    """Settings with every capacity key removed; the only view cell/lane/round fingerprints may use.

    Pool limits live outside job settings and are therefore never part of this view.
    """
    document = settings.as_document()
    del document["teams"]["review_teams"]
    return {"schema": SEMANTIC_VIEW_SCHEMA, "settings": document}


def semantic_settings_sha256(settings: InferenceSecurityReviewSettings) -> str:
    encoded = json.dumps(semantic_settings_view(settings), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _model_profile(name: str, value: object) -> ModelProfileSettings:
    field = f"{_PREFIX}.models.{name}"
    table = _table(value, field, {"provider", "model", "reasoning", "max_input_tokens", "max_output_tokens",
                                  "max_queries", "max_turns", "timeout_seconds"}, {"retries", "enabled"})
    reasoning = table["reasoning"]
    if reasoning not in REASONING_LEVELS:
        raise ValueError(f"{field}.reasoning must be one of: {', '.join(REASONING_LEVELS)}")
    return ModelProfileSettings(
        provider=_str(table["provider"], f"{field}.provider"),
        model=_str(table["model"], f"{field}.model"),
        reasoning=reasoning,
        max_input_tokens=_int(table["max_input_tokens"], f"{field}.max_input_tokens", 1, 2_000_000),
        max_output_tokens=_int(table["max_output_tokens"], f"{field}.max_output_tokens", 1, 1_000_000),
        max_queries=_int(table["max_queries"], f"{field}.max_queries", 0, 10_000),
        max_turns=_int(table["max_turns"], f"{field}.max_turns", 1, 1_000),
        timeout_seconds=_int(table["timeout_seconds"], f"{field}.timeout_seconds", 1, 86_400),
        retries=_int(table.get("retries", 0), f"{field}.retries", 0, 10),
        enabled=_bool(table.get("enabled", True), f"{field}.enabled"),
    )


def _role(name: str, value: object, profiles: Mapping[str, ModelProfileSettings]) -> tuple[Role, RoleSettings]:
    field = f"{_PREFIX}.roles.{name}"
    try:
        role = Role(name)
    except ValueError as exc:
        raise ValueError(f"{_PREFIX}.roles has unknown role: {name}") from exc
    table = _table(value, field, {"model_profile", "workers"}, {"require_distinct_from_roles"})
    profile = _str(table["model_profile"], f"{field}.model_profile", _PROFILE)
    if profile not in profiles:
        raise ValueError(f"{field}.model_profile names an unconfigured model profile: {profile}")
    distinct = _choices(table.get("require_distinct_from_roles", []), f"{field}.require_distinct_from_roles",
                        tuple(item.value for item in Role), empty=True)
    if role.value in distinct:
        raise ValueError(f"{field}.require_distinct_from_roles must not name the role itself")
    return role, RoleSettings(profile, _int(table["workers"], f"{field}.workers", 1, 64),
                              tuple(Role(item) for item in distinct))


def _scoring(value: object) -> ScoringSettings:
    field = f"{_PREFIX}.scoring"
    table = _table(value, field, {"enabled_providers", "priority_policy", "override_policy", "providers",
                                  "cwe_impact_classes"})
    enabled = _choices(table["enabled_providers"], f"{field}.enabled_providers", SCORING_PROVIDERS)
    providers_value = table["providers"]
    if not isinstance(providers_value, Mapping):
        raise ValueError(f"{field}.providers must be a table")
    providers: dict[str, ScoringProviderSettings] = {}
    for name, provider_value in providers_value.items():
        provider_field = f"{field}.providers.{name}"
        if name not in SCORING_PROVIDERS:
            raise ValueError(f"{field}.providers has unknown provider: {name}")
        if name not in enabled:
            raise ValueError(f"{provider_field} configures a provider that is not enabled")
        is_cvss = name in {"cvss_v4", "cvss_v31_compat"}
        provider = _table(provider_value, provider_field, {"implementation"},
                          {"metric_groups"} if is_cvss else set())
        groups = _choices(provider.get("metric_groups", ["base"] if is_cvss else []),
                          f"{provider_field}.metric_groups", CVSS_METRIC_GROUPS, empty=not is_cvss)
        if is_cvss and "base" not in groups:
            raise ValueError(f"{provider_field}.metric_groups must include base")
        providers[name] = ScoringProviderSettings(
            _str(provider["implementation"], f"{provider_field}.implementation", _RULE_ID), groups)
    classes_value = table["cwe_impact_classes"]
    if not isinstance(classes_value, Mapping):
        raise ValueError(f"{field}.cwe_impact_classes must be a table")
    classes: dict[str, str] = {}
    for cwe, impact in classes_value.items():
        if not isinstance(cwe, str) or not _CWE.fullmatch(cwe):
            raise ValueError(f"{field}.cwe_impact_classes has an invalid CWE id: {cwe}")
        if impact not in IMPACT_CLASSES:
            raise ValueError(f"{field}.cwe_impact_classes.{cwe} must be one of: {', '.join(IMPACT_CLASSES)}")
        classes[cwe] = impact
    if "application_risk_matrix" in enabled and not classes:
        raise ValueError(f"{field}.cwe_impact_classes is required by application_risk_matrix")
    return ScoringSettings(
        enabled_providers=enabled,
        priority_policy=_str(table["priority_policy"], f"{field}.priority_policy", _RULE_ID),
        override_policy=_str(table["override_policy"], f"{field}.override_policy", _RULE_ID),
        providers=MappingProxyType(providers),
        cwe_impact_classes=MappingProxyType(dict(sorted(classes.items()))),
    )


_POC_DENY_ONLY = ("allow_host_execution", "allow_production_services", "allow_real_credentials",
                  "allow_privileged_containers", "allow_docker_socket", "allow_deploy_sign_publish")
_POC_REQUIRED_TRUE = ("require_target_authorization", "require_isolation", "read_only_target")


def _poc(value: object, enabled_providers: tuple[str, ...]) -> PocSettings:
    field = f"{_PREFIX}.poc"
    table = _table(value, field, {"execution_enabled", "network", "max_attempts_per_claim", "cpu_limit",
                                  "memory_mb", "timeout_seconds", "scratch_mb", "eligibility_rules",
                                  *_POC_DENY_ONLY, *_POC_REQUIRED_TRUE})
    flags = {name: _bool(table[name], f"{field}.{name}")
             for name in ("execution_enabled", *_POC_DENY_ONLY, *_POC_REQUIRED_TRUE)}
    # Configuration may narrow, never widen, the default-deny proof-of-trigger policy.
    for name in _POC_DENY_ONLY:
        if flags[name]:
            raise ValueError(f"{field}.{name} must be false; the proof-of-trigger policy cannot be widened")
    for name in _POC_REQUIRED_TRUE:
        if not flags[name]:
            raise ValueError(f"{field}.{name} must be true; the proof-of-trigger policy cannot be widened")
    if table["network"] != "none":
        raise ValueError(f"{field}.network must be none")
    cpu = table["cpu_limit"]
    if type(cpu) not in {int, float} or not math.isfinite(cpu) or not 0 < cpu <= 8:
        raise ValueError(f"{field}.cpu_limit must be a number in (0, 8]")
    rules_value = table["eligibility_rules"]
    if not isinstance(rules_value, list) or len(rules_value) > 32:
        raise ValueError(f"{field}.eligibility_rules must be an array of at most 32 tables")
    rules: list[PocEligibilityRule] = []
    for index, rule_value in enumerate(rules_value):
        rule_field = f"{field}.eligibility_rules[{index}]"
        rule = _table(rule_value, rule_field, {"provider", "field", "operator", "values"})
        if rule["provider"] not in enabled_providers:
            raise ValueError(f"{rule_field}.provider must name an enabled scoring provider")
        if rule["operator"] not in ELIGIBILITY_OPERATORS:
            raise ValueError(f"{rule_field}.operator must be one of: {', '.join(ELIGIBILITY_OPERATORS)}")
        values = rule["values"]
        if (not isinstance(values, list) or not values or len(set(values)) != len(values) or
                any(not isinstance(item, str) or not _IDENTIFIER.fullmatch(item) for item in values)):
            raise ValueError(f"{rule_field}.values must be a non-empty array of distinct strings")
        rules.append(PocEligibilityRule(rule["provider"], _str(rule["field"], f"{rule_field}.field", _FIELD),
                                        rule["operator"], tuple(values)))
    return PocSettings(
        **flags,
        network="none",
        max_attempts_per_claim=_int(table["max_attempts_per_claim"], f"{field}.max_attempts_per_claim", 1, 3),
        cpu_limit=float(cpu),
        memory_mb=_int(table["memory_mb"], f"{field}.memory_mb", 64, 16_384),
        timeout_seconds=_int(table["timeout_seconds"], f"{field}.timeout_seconds", 1, 3_600),
        scratch_mb=_int(table["scratch_mb"], f"{field}.scratch_mb", 1, 16_384),
        eligibility_rules=tuple(rules),
    )


def parse_inference_review_settings(value: Mapping[str, Any]) -> InferenceSecurityReviewSettings:
    """Validate ``jobs.job_inference_security_review.settings`` into frozen typed settings."""
    settings = _table(value, _PREFIX, {"rounds", "teams", "lanes", "packages", "budgets", "retry", "models",
                                       "roles", "routing", "scoring", "poc"})

    field = f"{_PREFIX}.rounds"
    rounds_value = _table(settings["rounds"], field, {"max_rounds", "stable_rounds_required",
                                                      "max_active_claims", "max_attack_chains"})
    rounds = RoundSettings(
        max_rounds=_int(rounds_value["max_rounds"], f"{field}.max_rounds", 1, 16),
        stable_rounds_required=_int(rounds_value["stable_rounds_required"],
                                    f"{field}.stable_rounds_required", 1, 16),
        max_active_claims=_int(rounds_value["max_active_claims"], f"{field}.max_active_claims", 1, 100_000),
        max_attack_chains=_int(rounds_value["max_attack_chains"], f"{field}.max_attack_chains", 0, 10_000),
    )

    field = f"{_PREFIX}.teams"
    teams_value = _table(settings["teams"], field, {"review_teams", "red_per_team", "blue_per_team",
                                                    "verifier_per_team"})
    teams = TeamSettings(
        review_teams=_int(teams_value["review_teams"], f"{field}.review_teams", 1, 64),
        red_per_team=_int(teams_value["red_per_team"], f"{field}.red_per_team", 1, 16),
        blue_per_team=_int(teams_value["blue_per_team"], f"{field}.blue_per_team", 1, 16),
        verifier_per_team=_int(teams_value["verifier_per_team"], f"{field}.verifier_per_team", 1, 16),
    )

    field = f"{_PREFIX}.lanes"
    lanes_value = _table(settings["lanes"], field, {
        "lead_admission", "lead_budget_share", "lead_max_claims_per_package", "hunt_max_units",
        "hunt_max_claims_per_package", "hunt_panel_rule", "incomplete_gap_ratio"})
    lanes = LaneSettings(
        lead_admission=_choices(lanes_value["lead_admission"], f"{field}.lead_admission", REPORTED_SEVERITIES),
        lead_budget_share=_ratio(lanes_value["lead_budget_share"], f"{field}.lead_budget_share"),
        lead_max_claims_per_package=_int(lanes_value["lead_max_claims_per_package"],
                                         f"{field}.lead_max_claims_per_package", 1, 100),
        hunt_max_units=_int(lanes_value["hunt_max_units"], f"{field}.hunt_max_units", 0, 100_000),
        hunt_max_claims_per_package=_int(lanes_value["hunt_max_claims_per_package"],
                                         f"{field}.hunt_max_claims_per_package", 1, 100),
        hunt_panel_rule=_str(lanes_value["hunt_panel_rule"], f"{field}.hunt_panel_rule", _RULE_ID),
        incomplete_gap_ratio=_ratio(lanes_value["incomplete_gap_ratio"], f"{field}.incomplete_gap_ratio"),
    )

    field = f"{_PREFIX}.packages"
    packages_value = _table(settings["packages"], field, {
        "hunt_menu_partition_size", "unit_max_files", "max_context_entries", "max_package_bytes",
        "max_page_size", "max_pages", "max_depth"})
    packages = PackageAssemblySettings(
        hunt_menu_partition_size=_int(packages_value["hunt_menu_partition_size"],
                                      f"{field}.hunt_menu_partition_size", 1, 10_000),
        unit_max_files=_int(packages_value["unit_max_files"], f"{field}.unit_max_files", 1, 100_000),
        max_context_entries=_int(packages_value["max_context_entries"], f"{field}.max_context_entries", 1, 10_000),
        max_package_bytes=_int(packages_value["max_package_bytes"], f"{field}.max_package_bytes", 1, 16 * 1024 * 1024),
        max_page_size=_int(packages_value["max_page_size"], f"{field}.max_page_size", 1, 100),
        max_pages=_int(packages_value["max_pages"], f"{field}.max_pages", 1, 100),
        max_depth=_int(packages_value["max_depth"], f"{field}.max_depth", 1, 8),
    )

    field = f"{_PREFIX}.budgets"
    if isinstance(settings["budgets"], Mapping) and "max_cost_usd" in settings["budgets"]:
        raise ValueError(f"{field}.max_cost_usd is not supported: model results report tokens, not cost; "
                         "bound spend with max_input_tokens and max_output_tokens")
    budgets_value = _table(settings["budgets"], field, {
        "budget_team_packages", "max_model_turns", "max_input_tokens", "max_output_tokens",
        "max_retrieval_queries", "timeout_seconds"})
    budgets = BudgetSettings(**{name: _int(budgets_value[name], f"{field}.{name}") for name in budgets_value})

    field = f"{_PREFIX}.retry"
    retry_value = _table(settings["retry"], field, {"max_attempts", "retry_on_timeout", "retry_on_provider_error",
                                                    "retry_on_invalid_output", "backoff_seconds"})
    backoff = retry_value["backoff_seconds"]
    if (not isinstance(backoff, list) or len(backoff) > 16 or
            any(type(item) is not int or not 0 <= item <= 3_600 for item in backoff) or
            list(backoff) != sorted(backoff)):
        raise ValueError(f"{field}.backoff_seconds must be a non-decreasing array of seconds in [0, 3600]")
    retry = RetrySettings(
        max_attempts=_int(retry_value["max_attempts"], f"{field}.max_attempts", 1, 10),
        retry_on_timeout=_bool(retry_value["retry_on_timeout"], f"{field}.retry_on_timeout"),
        retry_on_provider_error=_bool(retry_value["retry_on_provider_error"], f"{field}.retry_on_provider_error"),
        retry_on_invalid_output=_bool(retry_value["retry_on_invalid_output"], f"{field}.retry_on_invalid_output"),
        backoff_seconds=tuple(backoff),
    )

    models_value = settings["models"]
    if not isinstance(models_value, Mapping) or "default" not in models_value:
        raise ValueError(f"{_PREFIX}.models must be a table with a default profile")
    models = {_str(name, f"{_PREFIX}.models profile name", _PROFILE): _model_profile(name, profile)
              for name, profile in sorted(models_value.items())}

    roles_value = settings["roles"]
    if not isinstance(roles_value, Mapping):
        raise ValueError(f"{_PREFIX}.roles must be a table")
    roles = dict(_role(str(name), role_value, models) for name, role_value in sorted(roles_value.items()))

    field = f"{_PREFIX}.routing"
    routing_value = _table(settings["routing"], field, {"persona_rule", "stack_rule"})
    routing = RoutingSettings(_str(routing_value["persona_rule"], f"{field}.persona_rule", _RULE_ID),
                              _str(routing_value["stack_rule"], f"{field}.stack_rule", _RULE_ID))

    scoring = _scoring(settings["scoring"])
    return InferenceSecurityReviewSettings(
        rounds=rounds, teams=teams, lanes=lanes, packages=packages, budgets=budgets, retry=retry,
        models=MappingProxyType(models), roles=MappingProxyType(roles), routing=routing,
        scoring=scoring, poc=_poc(settings["poc"], scoring.enabled_providers),
    )
