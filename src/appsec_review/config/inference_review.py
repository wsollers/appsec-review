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
from appsec_review.review.ranking import RankWeights
from appsec_review.review.lead_families import FAMILIES as LEAD_FAMILIES
from appsec_review.review.lead_triage_settings import TriageSettings
from appsec_review.review.red_discovery import LEAD_ACCOUNTING_CEILING, RED_ROLES, RedOutputLimits
from appsec_review.review.scoring.cwe_impact import MAX_REASON_CHARS as MAX_OVERRIDE_REASON, ImpactOverride
from appsec_review.review.scoring.risk_model import DEFAULT_MODEL_DOCUMENT, DimensionModel, RiskModel
from appsec_review.review.ship_block import ShipBlockSettings


JOB_ID = "job_inference_security_review"
REVIEW_TEAMS_KEY = f"jobs.{JOB_ID}.settings.teams.review_teams"
POOLS_KEY = "orchestration.dagster.pools.*"
CAPACITY_KEYS: tuple[str, ...] = (REVIEW_TEAMS_KEY, POOLS_KEY)
SEMANTIC_VIEW_SCHEMA = "appsec-review/inference-review-semantic-settings/1"

REPORTED_SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
REASONING_LEVELS = ("low", "medium", "high", "xhigh", "max")
SCORING_PROVIDERS = ("cvss_v4", "cvss_v31_compat", "application_risk_matrix", "ssvc_decision")
RISK_MATRIX_IMPLEMENTATIONS = ("application_risk_matrix/1", "application_risk_matrix/3")
RISK_MODEL_KEYS = ("exploitability", "environmental", "technical_severity")
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
    # Lane A also admits every KEV-listed advisory lead, whatever its reported severity. EPSS is
    # context only and has no admission effect.
    lead_admission_kev: bool = True

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
    max_memory_context_entries: int
    max_callers: int
    caller_depth: int
    # Model-facing package view (review-protocol-v2.md section 4): byte budget of one view, the longest
    # function source excerpt in lines, and how many type declarations a view may embed.
    max_view_bytes: int
    max_view_source_lines: int
    max_view_type_declarations: int


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


JUDGE_WHEN = ("all", "disagreement")
POC_RATINGS = ("low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class JudgeSettings(RoleSettings):
    """``settings.roles.adjudication_judge`` (docs/architecture/review-judge-and-poc.md section 3).

    ``when`` selects the claims that get a judge cell: ``all`` (every claim on which red affirmed a predicate) or
    ``disagreement`` (red affirmed and a blue cell contradicts, qualifies, leaves a predicate unresolved, or the blue
    cells disagree). The judge never sets a claim state. The bounds limit what each side may show the judge.
    """

    when: str = "all"
    judges_per_claim: int = 1
    enabled: bool = True
    max_why_chars: int = 600
    max_cited_rows_per_side: int = 12
    max_cited_row_chars: int = 400


@dataclass(frozen=True, slots=True)
class PocCandidateSettings:
    """``settings.poc_candidates`` (review-judge-and-poc.md section 4): which claims the handoff lists for a PoC.

    A claim is a candidate when it is ``supported`` or ``confirmed``, the judge sided with red (``red_correct``, or
    also ``partly`` when ``accept_partly``), it carries a resolved ``poc_basis``, and its risk-matrix technical
    severity is one of ``risk_ratings``.
    """

    accept_partly: bool = False
    risk_ratings: tuple[str, ...] = ("medium", "high", "critical")

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "PocCandidateSettings":
        if value is None:
            return cls()
        table = _table(value, field, set(), {"accept_partly", "risk_ratings"})
        return cls(_bool(table.get("accept_partly", False), f"{field}.accept_partly"),
                   _choices(table.get("risk_ratings", ["medium", "high", "critical"]), f"{field}.risk_ratings",
                            POC_RATINGS, empty=True))


@dataclass(frozen=True, slots=True)
class RoutingSettings:
    persona_rule: str
    stack_rule: str


@dataclass(frozen=True, slots=True)
class ScoringProviderSettings:
    implementation: str
    metric_groups: tuple[str, ...] = ()
    # application_risk_matrix/3 only: the declarative exploitability/environmental/severity model.
    model: RiskModel | None = None


@dataclass(frozen=True, slots=True)
class ScoringSettings:
    enabled_providers: tuple[str, ...]
    priority_policy: str
    override_policy: str
    providers: Mapping[str, ScoringProviderSettings]
    # Exceptions to cwe-impact-derivation/1 (decision 11); every other CWE's impact class is derived
    # from the run's pinned MITRE CWE catalog.
    cwe_impact_overrides: Mapping[str, ImpactOverride]


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
class VerificationSettings:
    """``settings.verification`` (decision 2).

    ``require_distinct_model_for_ship_blocking``: a ship-blocking candidate is published as
    ``ship_blocking`` only when its verifier's model profile (provider and model) differs from every
    red cell's on the claim; otherwise ``ship-block-policy/1`` publishes it as
    ``ship_blocking_pending_distinct_verification``. Confirmation itself (R5/R6) never depends on it.
    """

    require_distinct_model_for_ship_blocking: bool = True

    @classmethod
    def from_mapping(cls, value: object, field: str) -> "VerificationSettings":
        if value is None:
            return cls()
        table = _table(value, field, set(), {"require_distinct_model_for_ship_blocking"})
        return cls(_bool(table.get("require_distinct_model_for_ship_blocking", True),
                         f"{field}.require_distinct_model_for_ship_blocking"))


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
    # Lane B review-unit rank weights (``settings.ranking``); semantic, defaults reproduce rank/2.
    ranking: RankWeights = RankWeights()
    # Closed red-discovery-result/1 limits (``settings.red_output``); semantic: they decide admission.
    red_output: RedOutputLimits = RedOutputLimits()
    # ship-block-policy/1 thresholds (``settings.ship_block``, decision 1) and verifier model
    # distinctness (``settings.verification``, decision 2); both semantic.
    ship_block: ShipBlockSettings = ShipBlockSettings()
    verification: VerificationSettings = VerificationSettings()
    # Lead severity triage (``settings.triage``, review/lead_triage.py); semantic. Absent means off.
    triage: TriageSettings = TriageSettings()
    # PoC candidates the handoff lists (review-judge-and-poc.md section 4); semantic.
    poc_candidates: PocCandidateSettings = PocCandidateSettings()

    @property
    def judge(self) -> JudgeSettings | None:
        """The adjudication judge's settings when the role is configured and enabled, else ``None``."""
        configured = self.roles.get(Role.ADJUDICATION_JUDGE)
        return configured if isinstance(configured, JudgeSettings) and configured.enabled else None

    def verifier_distinctness(self) -> dict[str, Any]:
        """How the configured verifier profile relates to the red roles' profiles.

        ``distinct`` is true when the ``independent_verifier`` profile's (provider, model) differs
        from every red role's. With the requirement on and ``distinct`` false, every ship-blocking
        candidate is published pending distinct verification; ``warning`` names that state.
        """
        verifier = self.profile_for(Role.INDEPENDENT_VERIFIER)
        reds = {role.value: self.profile_for(role) for role in sorted(RED_ROLES, key=lambda item: item.value)}
        same = sorted(role for role, profile in reds.items()
                      if (profile.provider, profile.model) == (verifier.provider, verifier.model))
        required = self.verification.require_distinct_model_for_ship_blocking
        warning = None
        if required and same:
            warning = (f"verification.require_distinct_model_for_ship_blocking is on but the independent_verifier "
                       f"profile resolves to the same model ({verifier.provider}/{verifier.model}) as "
                       f"{', '.join(same)}; ship-blocking candidates will be published as "
                       "ship_blocking_pending_distinct_verification")
        return {"require_distinct_model_for_ship_blocking": required,
                "verifier": {"provider": verifier.provider, "model": verifier.model},
                "red": {role: {"provider": profile.provider, "model": profile.model} for role, profile in reds.items()},
                "distinct": not same, "warning": warning}

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
    judge_keys = {"when", "judges_per_claim", "enabled", "max_why_chars", "max_cited_rows_per_side",
                  "max_cited_row_chars"}
    table = _table(value, field, {"model_profile", "workers"},
                   {"require_distinct_from_roles"} | (judge_keys if role is Role.ADJUDICATION_JUDGE else set()))
    profile = _str(table["model_profile"], f"{field}.model_profile", _PROFILE)
    if profile not in profiles:
        raise ValueError(f"{field}.model_profile names an unconfigured model profile: {profile}")
    distinct = _choices(table.get("require_distinct_from_roles", []), f"{field}.require_distinct_from_roles",
                        tuple(item.value for item in Role), empty=True)
    if role.value in distinct:
        raise ValueError(f"{field}.require_distinct_from_roles must not name the role itself")
    workers = _int(table["workers"], f"{field}.workers", 1, 64)
    if role is Role.ADJUDICATION_JUDGE:
        when = table.get("when", "all")
        if when not in JUDGE_WHEN:
            raise ValueError(f"{field}.when must be one of: {', '.join(JUDGE_WHEN)}")
        return role, JudgeSettings(
            profile, workers, tuple(Role(item) for item in distinct), when,
            _int(table.get("judges_per_claim", 1), f"{field}.judges_per_claim", 1, 5),
            _bool(table.get("enabled", True), f"{field}.enabled"),
            _int(table.get("max_why_chars", 600), f"{field}.max_why_chars", 1, 2000),
            _int(table.get("max_cited_rows_per_side", 12), f"{field}.max_cited_rows_per_side", 1, 32),
            _int(table.get("max_cited_row_chars", 400), f"{field}.max_cited_row_chars", 50, 2000))
    return role, RoleSettings(profile, workers, tuple(Role(item) for item in distinct))


def _scoring(value: object) -> ScoringSettings:
    field = f"{_PREFIX}.scoring"
    if isinstance(value, Mapping) and "cwe_impact_classes" in value:
        raise ValueError(f"{field}.cwe_impact_classes was replaced by {field}.cwe_impact_overrides: impact classes "
                         "are derived from the pinned MITRE CWE catalog and the table lists only exceptions")
    table = _table(value, field, {"enabled_providers", "priority_policy", "override_policy", "providers"},
                   {"cwe_impact_overrides"})
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
        is_matrix = name == "application_risk_matrix"
        provider = _table(provider_value, provider_field, {"implementation"},
                          {"metric_groups"} if is_cvss else set(RISK_MODEL_KEYS) if is_matrix else set())
        groups = _choices(provider.get("metric_groups", ["base"] if is_cvss else []),
                          f"{provider_field}.metric_groups", CVSS_METRIC_GROUPS, empty=not is_cvss)
        if is_cvss and "base" not in groups:
            raise ValueError(f"{provider_field}.metric_groups must include base")
        implementation = _str(provider["implementation"], f"{provider_field}.implementation", _RULE_ID)
        model = None
        if is_matrix:
            if implementation not in RISK_MATRIX_IMPLEMENTATIONS:
                raise ValueError(f"{provider_field}.implementation must be one of: "
                                 f"{', '.join(RISK_MATRIX_IMPLEMENTATIONS)}")
            if implementation == "application_risk_matrix/3":
                model = _risk_model(provider, provider_field)
            elif set(provider) & set(RISK_MODEL_KEYS):
                raise ValueError(f"{provider_field}: application_risk_matrix/1 takes no "
                                 f"{'/'.join(RISK_MODEL_KEYS)} tables")
        providers[name] = ScoringProviderSettings(implementation, groups, model)
    return ScoringSettings(
        enabled_providers=enabled,
        priority_policy=_str(table["priority_policy"], f"{field}.priority_policy", _RULE_ID),
        override_policy=_str(table["override_policy"], f"{field}.override_policy", _RULE_ID),
        providers=MappingProxyType(providers),
        cwe_impact_overrides=_impact_overrides(table.get("cwe_impact_overrides", {}),
                                               f"{field}.cwe_impact_overrides"),
    )


def _impact_overrides(value: object, field: str) -> Mapping[str, ImpactOverride]:
    """Exceptions to ``cwe-impact-derivation/1``: ``"CWE-n" = { impact_class = "...", reason = "..." }``."""
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a table")
    overrides: dict[str, ImpactOverride] = {}
    for cwe, entry_value in value.items():
        if not isinstance(cwe, str) or not _CWE.fullmatch(cwe):
            raise ValueError(f"{field} has an invalid CWE id: {cwe}")
        entry = _table(entry_value, f"{field}.{cwe}", {"impact_class", "reason"})
        if entry["impact_class"] not in IMPACT_CLASSES:
            raise ValueError(f"{field}.{cwe}.impact_class must be one of: {', '.join(IMPACT_CLASSES)}")
        reason = entry["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_OVERRIDE_REASON:
            raise ValueError(f"{field}.{cwe}.reason must be a non-empty string of at most "
                             f"{MAX_OVERRIDE_REASON} characters")
        overrides[cwe] = ImpactOverride(entry["impact_class"], reason)
    return MappingProxyType(dict(sorted(overrides.items())))


def _risk_model(provider: Mapping[str, Any], field: str) -> RiskModel:
    """``application_risk_matrix/3`` model; an absent table keeps its documented default whole."""
    dimensions: dict[str, DimensionModel] = {}
    for name in ("exploitability", "environmental"):
        default = DEFAULT_MODEL_DOCUMENT[name]
        value = _table(provider.get(name, default), f"{field}.{name}", {"points", "bands"})
        points = value["points"]
        if not isinstance(points, Mapping) or any(not isinstance(table, Mapping) for table in points.values()):
            raise ValueError(f"{field}.{name}.points must be a table of factor tables")
        try:
            dimensions[name] = DimensionModel(name, points, value["bands"])
        except ValueError as exc:
            raise ValueError(f"{field}.{exc}") from exc
    matrix = provider.get("technical_severity", DEFAULT_MODEL_DOCUMENT["technical_severity"])
    if not isinstance(matrix, Mapping):
        raise ValueError(f"{field}.technical_severity must be a table")
    try:
        return RiskModel(dimensions["exploitability"], dimensions["environmental"], matrix)
    except ValueError as exc:
        raise ValueError(f"{field}.{exc}") from exc


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
                                       "roles", "routing", "scoring", "poc"},
                      {"ranking", "red_output", "ship_block", "verification", "triage", "poc_candidates"})

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
        "hunt_max_claims_per_package", "hunt_panel_rule", "incomplete_gap_ratio"}, {"lead_admission_kev"})
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
        lead_admission_kev=_bool(lanes_value.get("lead_admission_kev", True), f"{field}.lead_admission_kev"),
    )

    field = f"{_PREFIX}.packages"
    packages_value = _table(settings["packages"], field, {
        "hunt_menu_partition_size", "unit_max_files", "max_context_entries", "max_package_bytes",
        "max_page_size", "max_pages", "max_depth", "max_memory_context_entries", "max_callers", "caller_depth",
        "max_view_bytes", "max_view_source_lines", "max_view_type_declarations"})
    packages = PackageAssemblySettings(
        hunt_menu_partition_size=_int(packages_value["hunt_menu_partition_size"],
                                      f"{field}.hunt_menu_partition_size", 1, 10_000),
        unit_max_files=_int(packages_value["unit_max_files"], f"{field}.unit_max_files", 1, 100_000),
        max_context_entries=_int(packages_value["max_context_entries"], f"{field}.max_context_entries", 1, 10_000),
        max_package_bytes=_int(packages_value["max_package_bytes"], f"{field}.max_package_bytes", 1, 16 * 1024 * 1024),
        max_page_size=_int(packages_value["max_page_size"], f"{field}.max_page_size", 1, 100),
        max_pages=_int(packages_value["max_pages"], f"{field}.max_pages", 1, 100),
        max_depth=_int(packages_value["max_depth"], f"{field}.max_depth", 1, 8),
        max_memory_context_entries=_int(packages_value["max_memory_context_entries"],
                                        f"{field}.max_memory_context_entries", 1, 1_000),
        max_callers=_int(packages_value["max_callers"], f"{field}.max_callers", 1, 1_000),
        caller_depth=_int(packages_value["caller_depth"], f"{field}.caller_depth", 1, 4),
        max_view_bytes=_int(packages_value["max_view_bytes"], f"{field}.max_view_bytes", 4096, 1024 * 1024),
        max_view_source_lines=_int(packages_value["max_view_source_lines"], f"{field}.max_view_source_lines", 10, 2000),
        max_view_type_declarations=_int(packages_value["max_view_type_declarations"],
                                        f"{field}.max_view_type_declarations", 0, 32),
    )
    if packages.hunt_menu_partition_size > LEAD_ACCOUNTING_CEILING:
        raise ValueError(f"{field}.hunt_menu_partition_size must not exceed {LEAD_ACCOUNTING_CEILING}: every lead "
                         "of a package needs one red-discovery-result/1 lead accounting entry")

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
    triage = TriageSettings.from_mapping(settings.get("triage"), f"{_PREFIX}.triage")
    if triage.enabled and triage.model_profile not in models:
        raise ValueError(f"{_PREFIX}.triage.model_profile names an unconfigured model profile: "
                         f"{triage.model_profile}")
    if triage.enabled and models[triage.model_profile].max_queries != 0:
        raise ValueError(f"{_PREFIX}.models.{triage.model_profile}.max_queries must be 0: lead triage grants no "
                         "retrieval")
    return InferenceSecurityReviewSettings(
        rounds=rounds, teams=teams, lanes=lanes, packages=packages, budgets=budgets, retry=retry,
        models=MappingProxyType(models), roles=MappingProxyType(roles), routing=routing,
        scoring=scoring, poc=_poc(settings["poc"], scoring.enabled_providers),
        ranking=RankWeights.from_mapping(settings.get("ranking", {}), f"{_PREFIX}.ranking"),
        red_output=RedOutputLimits.from_mapping(settings.get("red_output", {}), f"{_PREFIX}.red_output"),
        ship_block=ShipBlockSettings.from_mapping(settings.get("ship_block"), f"{_PREFIX}.ship_block",
                                                  known_families=LEAD_FAMILIES),
        verification=VerificationSettings.from_mapping(settings.get("verification"), f"{_PREFIX}.verification"),
        triage=triage,
        poc_candidates=PocCandidateSettings.from_mapping(settings.get("poc_candidates"), f"{_PREFIX}.poc_candidates"),
    )
