from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import (
    CAPACITY_KEYS, PENDING_JOBS, InferenceSecurityReviewSettings, load_config, overlay_capacity_keys,
    semantic_settings_sha256, semantic_settings_view,
)
from appsec_review.config.loader import OVERLAY_ENVIRONMENT
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.review.models import Role
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).parents[1]
JOB = "job_inference_security_review"
SECTION = f"[jobs.{JOB}.settings"


def _variant(tmp_path: Path, *replacements: tuple[str, str], suffix: str = "", overlay: str | None = None):
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    for old, new in replacements:
        assert old in source, old
        source = source.replace(old, new, 1)
    path = tmp_path / "appsec-review.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source + suffix, encoding="utf-8")
    overlay_path = None
    if overlay is not None:
        overlay_path = tmp_path / "local-overlay.toml"
        overlay_path.write_text(overlay, encoding="utf-8")
    return load_config(path, overlay=overlay_path)


def _settings(config) -> InferenceSecurityReviewSettings:
    settings = config.job(JOB).typed_settings
    assert isinstance(settings, InferenceSecurityReviewSettings)
    return settings


# ---------------------------------------------------------------- defaults


def test_repository_defaults_load_as_typed_frozen_settings() -> None:
    config = load_config(ROOT / "appsec-review.toml")
    settings = _settings(config)
    assert (settings.teams.review_teams, settings.teams.red_per_team, settings.teams.blue_per_team,
            settings.teams.verifier_per_team) == (5, 3, 2, 1)
    assert settings.lanes.lead_budget_share == 0.5 and settings.lanes.hunt_budget_share == 0.5
    assert settings.lanes.lead_admission == ("critical", "high", "unknown")
    assert (settings.lanes.lead_max_claims_per_package, settings.lanes.hunt_max_units,
            settings.lanes.hunt_max_claims_per_package) == (3, 50, 5)
    assert settings.budgets.budget_team_packages == 200
    assert settings.budgets.max_model_turns == 12000
    assert (settings.budgets.max_input_tokens, settings.budgets.max_output_tokens) == (60_000_000, 6_000_000)
    assert settings.retry.backoff_seconds == (2, 10)
    assert settings.rounds.max_rounds == 3
    assert settings.models["default"].max_queries == 40
    verifier = settings.roles[Role.INDEPENDENT_VERIFIER]
    assert verifier.model_profile == "default" and verifier.workers == 4
    assert Role.BLUE_TEAM_REFUTER in verifier.require_distinct_from_roles
    assert settings.profile_for(Role.HYPOTHESIS_HUNTER) is settings.models["default"]
    # Only exceptions to cwe-impact-derivation/1 are configured; CWE-89 is derived from the catalog.
    overrides = settings.scoring.cwe_impact_overrides
    assert set(overrides) == {"CWE-79", "CWE-190", "CWE-209", "CWE-476", "CWE-502", "CWE-601"}
    assert overrides["CWE-79"].impact_class == "medium" and overrides["CWE-79"].reason
    assert "CWE-89" not in overrides
    assert settings.as_document()["scoring"]["cwe_impact_overrides"]["CWE-601"]["impact_class"] == "low"
    assert settings.poc.execution_enabled is False and settings.poc.network == "none"
    assert settings.poc.eligibility_rules[0].values == ("HIGH", "CRITICAL")
    with pytest.raises(AttributeError):
        settings.teams.review_teams = 1  # type: ignore[misc]
    assert config.dagster.pool_limits["inference_teams"] == 2
    assert config.dagster.pool_limits["inference_score"] == 4
    assert "max_cost_usd" not in json.dumps(settings.as_document())


def test_registered_job_is_resolved_with_the_registry_set_and_package_bounds() -> None:
    from appsec_review.runtime.registry import builtin_registry

    config = load_config(ROOT / "appsec-review.toml")
    assert JOB in config.jobs and not config.pending_jobs and not PENDING_JOBS
    assert set(config.jobs) == set(builtin_registry().job_ids())
    resolved = json.loads(config.resolved_json)
    assert "pending_jobs" not in resolved
    assert resolved["jobs"][JOB]["settings"]["teams"]["review_teams"] == 5
    assert tuple(config.job(JOB).steps) == ("scope", "packages", "lead_review", "hunt_review", "merge",
                                            "adjudicate", "scoring", "completeness", "publication")
    from appsec_review.review.packages import PackageSettings
    packages = PackageSettings.from_review_settings(_settings(config))
    assert packages.admit_severities == ("critical", "high", "unknown")
    assert (packages.hunt_max_units, packages.hunt_menu_partition_size, packages.max_package_bytes) == (50, 25, 65536)


# ---------------------------------------------------------------- rejection


@pytest.mark.parametrize("replacement, message", [
    ((f"{SECTION}.teams]\n", f"{SECTION}.teams]\nsurplus = 1\n"), "teams has unknown settings: surplus"),
    ((f"{SECTION}.rounds]\n", f"{SECTION}.rounds]\nmode = 1\n"), "rounds has unknown settings: mode"),
    ((f"{SECTION}.models.default]\n", f"{SECTION}.models.default]\ntemperature = 1\n"),
     "models.default has unknown settings: temperature"),
    ((f"{SECTION}.scoring.providers.cvss_v4]\n", f"{SECTION}.scoring.providers.cvss_v4]\nflavour = \"x\"\n"),
     "providers.cvss_v4 has unknown settings: flavour"),
    ((f"{SECTION}.poc]\n", f"{SECTION}.poc]\nallow_anything = false\n"), "poc has unknown settings"),
    ((f"{SECTION}.routing]\n", f"{SECTION}.extra]\nx = 1\n{SECTION}.routing]\n"),
     "settings has unknown settings: extra"),
    ((f"{SECTION}.budgets]\n", f"{SECTION}.budgets]\nmax_cost_usd = 50.0\n"),
     "max_cost_usd is not supported: model results report tokens, not cost"),
])
def test_unknown_and_legacy_keys_are_rejected_at_every_level(tmp_path: Path, replacement, message) -> None:
    with pytest.raises(ValueError, match=message):
        _variant(tmp_path, replacement)


@pytest.mark.parametrize("old, new, message", [
    ("lead_budget_share = 0.5", "lead_budget_share = 1.5", "lead_budget_share must be a number between 0 and 1"),
    ("incomplete_gap_ratio = 0.25", "incomplete_gap_ratio = -0.1", "incomplete_gap_ratio must be"),
    ("review_teams = 5", "review_teams = 0", "review_teams must be an integer"),
    ("red_per_team = 3", "red_per_team = 0", "red_per_team must be an integer"),
    ("budget_team_packages = 200", "budget_team_packages = 0", "budget_team_packages must be an integer"),
    ("max_model_turns = 12000", "max_model_turns = true", "max_model_turns must be an integer"),
    ('lead_admission = ["critical", "high", "unknown"]', 'lead_admission = ["critical", "high"]',
     "must admit unknown severity"),
    ('lead_admission = ["critical", "high", "unknown"]', 'lead_admission = ["critical", "severe", "unknown"]',
     "lead_admission has unknown values: severe"),
    ("stable_rounds_required = 1", "stable_rounds_required = 9", "must not exceed max_rounds"),
    (f"{SECTION}.roles.independent_verifier]", f"{SECTION}.roles.chief_reviewer]", "unknown role: chief_reviewer"),
    ('model_profile = "default"\nrequire', 'model_profile = "deep"\nrequire', "unconfigured model profile: deep"),
    ('require_distinct_from_roles = ["hypothesis_hunter"', 'require_distinct_from_roles = ["independent_verifier"',
     "must not name the role itself"),
    ('require_distinct_from_roles = ["hypothesis_hunter"', 'require_distinct_from_roles = ["oracle"',
     "require_distinct_from_roles has unknown values: oracle"),
    ('reasoning = "high"\nmax_input_tokens = 32000\nmax_output_tokens = 8000\nmax_queries',
     'reasoning = "extreme"\nmax_input_tokens = 32000\nmax_output_tokens = 8000\nmax_queries',
     "reasoning must be one of"),
    ('"CWE-209" = { impact_class = "low"', '"CWE-209" = { impact_class = "severe"',
     "cwe_impact_overrides.CWE-209.impact_class must be one of"),
    ('"CWE-209" = { impact_class = "low"', '"SQLi" = { impact_class = "low"',
     "cwe_impact_overrides has an invalid CWE id: SQLi"),
    ('"CWE-209" = { impact_class = "low", reason = "error messages disclose diagnostic detail, not bulk '
     'application data" }', '"CWE-209" = { impact_class = "low", reason = " " }',
     "cwe_impact_overrides.CWE-209.reason must be a non-empty string"),
    ('"CWE-209" = { impact_class = "low", reason = "error messages disclose diagnostic detail, not bulk '
     'application data" }', '"CWE-209" = { impact_class = "low" }',
     "cwe_impact_overrides.CWE-209 is missing settings: reason"),
    ('"CWE-209" = { impact_class = "low"', '"CWE-209" = { weight = 1, impact_class = "low"',
     "cwe_impact_overrides.CWE-209 has unknown settings: weight"),
    ('"CWE-209" = { impact_class = "low"', '"CWE-209" = "low"\n"CWE-210" = { impact_class = "low"',
     "cwe_impact_overrides.CWE-209 must be a table"),
    ("[jobs.job_inference_security_review.settings.scoring.cwe_impact_overrides]",
     '[jobs.job_inference_security_review.settings.scoring.cwe_impact_classes]\n"CWE-89" = "critical"\n\n'
     "[jobs.job_inference_security_review.settings.scoring.cwe_impact_overrides]",
     "cwe_impact_classes was replaced by .*cwe_impact_overrides"),
    ("allow_docker_socket = false", "allow_docker_socket = true", "allow_docker_socket must be false"),
    ('network = "none"', 'network = "bridge"', "network must be none"),
    ('provider = "cvss_v4"\nfield', 'provider = "ssvc_v9"\nfield', "must name an enabled scoring provider"),
    ("backoff_seconds = [2, 10]", "backoff_seconds = [10, 2]", "backoff_seconds must be a non-decreasing"),
])
def test_ranges_and_references_are_validated(tmp_path: Path, old: str, new: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _variant(tmp_path, (old, new))


# ---------------------------------------------------------------- local capacity overlay


OVERLAY = f"""
[jobs.{JOB}.settings.teams]
review_teams = 1

[orchestration.dagster.pools]
inference_teams = 1
scanner = 2
"""


def test_capacity_overlay_is_merged_frozen_and_hashed_as_its_own_layer(tmp_path: Path) -> None:
    base = _variant(tmp_path / "base")
    config = _variant(tmp_path / "overlaid", overlay=OVERLAY)
    overlay_path = tmp_path / "overlaid" / "local-overlay.toml"
    assert _settings(config).teams.review_teams == 1
    assert config.dagster.pool_limits["inference_teams"] == 1 and config.dagster.pool_limits["scanner"] == 2
    assert config.dagster.pool_limits["inference_score"] == 4
    expected_sha = hashlib.sha256(overlay_path.read_bytes()).hexdigest()
    assert config.overlay_sha256 == expected_sha and config.source_sha256 == base.source_sha256
    assert config.layers[1] == {"path": str(overlay_path.resolve()), "sha256": expected_sha,
                                "layer": "capacity_overlay"}
    assert len(base.layers) == 1
    resolved = json.loads(config.resolved_json)
    assert resolved["configuration_overlay"]["sha256"] == expected_sha
    assert resolved["configuration_overlay"]["keys"] == [
        f"jobs.{JOB}.settings.teams.review_teams", "orchestration.dagster.pools.inference_teams",
        "orchestration.dagster.pools.scanner"]
    assert resolved["jobs"][JOB]["settings"]["teams"]["review_teams"] == 1
    assert resolved["orchestration"]["dagster"]["pools"]["inference_teams"] == 1
    assert config.resolved_sha256 != base.resolved_sha256
    assert "configuration_overlay" not in json.loads(base.resolved_json)


def test_capacity_overlay_can_be_named_by_environment(tmp_path: Path, monkeypatch) -> None:
    overlay = tmp_path / "env-overlay.toml"
    overlay.write_text("[orchestration.dagster.pools]\ninference_teams = 1\n", encoding="utf-8")
    monkeypatch.setenv(OVERLAY_ENVIRONMENT, overlay.as_uri())
    config = load_config(ROOT / "appsec-review.toml")
    assert config.dagster.pool_limits["inference_teams"] == 1
    assert config.overlay_path == overlay.resolve()


@pytest.mark.parametrize("overlay, message", [
    (f"[jobs.{JOB}.settings.budgets]\nbudget_team_packages = 999\n", "rejected: jobs.job_inference_security_review"
                                                                   ".settings.budgets"),
    (f"[jobs.{JOB}.settings.teams]\nred_per_team = 1\n", "rejected: .*teams.red_per_team"),
    ("[jobs.job_review_intake.settings.model_preflight]\ntimeout_seconds = 1\n", "rejected: jobs.job_review_intake"),
    ("[runtime]\nruns_dir = \"elsewhere\"\n", "rejected: runtime"),
    ("[orchestration.dagster]\nmax_concurrent = 64\n", "rejected: orchestration.dagster.max_concurrent"),
    (f"[jobs.{JOB}]\nworkers = 1\n", "rejected: jobs.job_inference_security_review.workers"),
    (f"[jobs.{JOB}.settings.teams]\nreview_teams = \"1\"\n", "review_teams must be an integer"),
    ("[orchestration.dagster.pools]\ninference_teams = 1.5\n", "pool limit is invalid"),
    ("", "must be a non-empty table"),
])
def test_capacity_overlay_rejects_every_other_key(tmp_path: Path, overlay: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _variant(tmp_path, overlay=overlay)


def test_capacity_overlay_values_are_still_range_checked(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="review_teams must be an integer between 1 and 64"):
        _variant(tmp_path, overlay=f"[jobs.{JOB}.settings.teams]\nreview_teams = 0\n")
    with pytest.raises(ValueError, match="pool limits must be between 1 and 64"):
        _variant(tmp_path, overlay="[orchestration.dagster.pools]\ninference_teams = 0\n")


def test_capacity_key_allowlist_is_exposed() -> None:
    assert CAPACITY_KEYS == (f"jobs.{JOB}.settings.teams.review_teams", "orchestration.dagster.pools.*")
    assert overlay_capacity_keys({"orchestration": {"dagster": {"pools": {"index": 2}}}}) == (
        "orchestration.dagster.pools.index",)


def test_review_intake_records_the_overlay_layer(tmp_path: Path) -> None:
    config = _variant(tmp_path, overlay=OVERLAY)
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    outcome = GraphRunner(config, [build_intake()]).run(target_root=target,
                                                        source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    manifest = json.loads((run_root / "data/configuration/manifest.json").read_text(encoding="utf-8"))
    assert manifest["sources"] == [dict(layer) for layer in config.layers]
    intake = json.loads(next(run_root.rglob("review-intake.json")).read_text(encoding="utf-8"))
    layers = intake["configuration"]["layers"]
    assert [layer.get("layer") for layer in layers] == [None, "capacity_overlay"]
    assert layers[1]["sha256"] == config.overlay_sha256


def test_review_intake_without_overlay_keeps_a_single_layer(tmp_path: Path) -> None:
    config = _variant(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("x = 1\n", encoding="utf-8")
    outcome = GraphRunner(config, [build_intake()]).run(target_root=target,
                                                        source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / outcome["run_id"]
    intake = json.loads(next(run_root.rglob("review-intake.json")).read_text(encoding="utf-8"))
    assert intake["configuration"]["layers"] == [{"path": str(config.source_path), "sha256": config.source_sha256}]


# ---------------------------------------------------------------- semantic view


def test_capacity_keys_are_excluded_from_the_semantic_view(tmp_path: Path) -> None:
    base = _settings(_variant(tmp_path / "base"))
    fewer_teams = _settings(_variant(tmp_path / "teams", overlay=OVERLAY))
    larger_budget = _settings(_variant(tmp_path / "budget", ("budget_team_packages = 200",
                                                             "budget_team_packages = 300")))
    other_share = _settings(_variant(tmp_path / "share", ("lead_budget_share = 0.5", "lead_budget_share = 0.6")))
    assert "review_teams" not in semantic_settings_view(base)["settings"]["teams"]
    assert semantic_settings_view(base)["settings"]["teams"]["red_per_team"] == 3
    assert semantic_settings_sha256(fewer_teams) == semantic_settings_sha256(base)
    assert semantic_settings_sha256(larger_budget) != semantic_settings_sha256(base)
    assert semantic_settings_sha256(other_share) != semantic_settings_sha256(base)
    assert base.as_document()["teams"]["review_teams"] == 5   # the full view still carries capacity


# ---------------------------------------------------------------- Dagster pools


def test_pool_mapping_is_job_aware() -> None:
    from appsec_review.orchestration.dagster.adapter import _pool_for

    assert _pool_for("lead_review.teams", JOB) == "inference_teams"
    assert _pool_for("hunt_review.teams", JOB) == "inference_teams"
    assert _pool_for("scoring.score_claims", JOB) == "inference_score"
    assert _pool_for("publication.publish_claim_ledger", JOB) == "lifecycle"
    assert _pool_for("publication.publish_handoff", JOB) == "lifecycle"
    for unit in ("scope.accept_manifest", "packages.assemble_hunt_packages", "merge.claims",
                 "adjudicate.apply_policy", "completeness.audit"):
        assert _pool_for(unit, JOB) == "application"
    # Existing mappings for every other job are unchanged, with or without a job id.
    for job_id in (None, "job_owasp_control_assessment", "job_cpp_compiled_analysis"):
        assert _pool_for("validation.validate", job_id) == "owasp_validator"
        assert _pool_for("verification.verify", job_id) == "owasp_verification"
        assert _pool_for("compile.run", job_id) == "cpp_build"
        assert _pool_for("inference.review", job_id) == "cpp_analysis"
        assert _pool_for("ci_analysis.actionlint_scan", job_id) == "ci_linter"
        assert _pool_for("collection.semgrep_scan", job_id) == "scanner"
        assert _pool_for("build.symbol_index", job_id) == "index"
        assert _pool_for("__begin", job_id) == "lifecycle"
        assert _pool_for("publication.publish_handoff", job_id) == "application"
        assert _pool_for("scoring.score_claims", job_id) == "application"


def test_kev_lane_a_admission_is_typed_and_defaults_on(tmp_path: Path) -> None:
    assert _settings(load_config(ROOT / "appsec-review.toml")).lanes.lead_admission_kev is True
    disabled = _variant(tmp_path / "off", ("lead_admission_kev = true", "lead_admission_kev = false"))
    assert _settings(disabled).lanes.lead_admission_kev is False
    omitted = _variant(tmp_path / "omitted", ("lead_admission_kev = true\n", ""))
    assert _settings(omitted).lanes.lead_admission_kev is True
    with pytest.raises(ValueError, match="lead_admission_kev must be a Boolean"):
        _variant(tmp_path / "bad", ("lead_admission_kev = true", 'lead_admission_kev = "yes"'))


# ---------------------------------------------------------------- scoring model and rank weights (B1, B2)

MATRIX = f"{SECTION}.scoring.providers.application_risk_matrix"


def test_scoring_model_and_rank_weights_default_to_the_documented_values(tmp_path: Path) -> None:
    from appsec_review.review.packages import PackageSettings
    from appsec_review.review.ranking import RankWeights
    from appsec_review.review.scoring import registry_from_settings
    from appsec_review.review.scoring.risk_model import DEFAULT_RISK_MODEL

    settings = _settings(load_config(ROOT / "appsec-review.toml"))
    matrix = settings.scoring.providers["application_risk_matrix"]
    assert matrix.implementation == "application_risk_matrix/2"
    assert matrix.model.document() == DEFAULT_RISK_MODEL.document()
    assert settings.ranking == RankWeights()
    assert PackageSettings.from_review_settings(settings).rank_weights == RankWeights()
    registry = registry_from_settings(settings.scoring)
    assert registry.ids() == ("application_risk_matrix",)       # cvss_v4/ssvc_decision are not implemented
    assert registry.get("application_risk_matrix").model.document() == DEFAULT_RISK_MODEL.document()
    document = semantic_settings_view(settings)["settings"]
    assert document["ranking"]["advisory_kev"] == 250
    assert document["scoring"]["providers"]["application_risk_matrix"]["model"]["exploitability"]["bands"] == {
        "medium": 40, "high": 75}
    # Omitting the tables keeps the same defaults; application_risk_matrix/1 stays selectable without a model.
    from appsec_review.config.inference_review import parse_inference_review_settings

    raw = json.loads(load_config(ROOT / "appsec-review.toml").resolved_json)["jobs"][JOB]["settings"]
    raw.pop("ranking")
    raw["scoring"]["providers"]["application_risk_matrix"] = {"implementation": "application_risk_matrix/2"}
    parsed = parse_inference_review_settings(raw)
    assert parsed.ranking == RankWeights()
    assert parsed.scoring.providers["application_risk_matrix"].model.document() == DEFAULT_RISK_MODEL.document()
    raw["scoring"]["providers"]["application_risk_matrix"] = {"implementation": "application_risk_matrix/1"}
    legacy = parse_inference_review_settings(raw)
    assert legacy.scoring.providers["application_risk_matrix"].model is None
    assert registry_from_settings(legacy.scoring).get("application_risk_matrix").implementation_version == (
        "application_risk_matrix/1")


def test_scoring_and_ranking_tuning_changes_the_semantic_fingerprint(tmp_path: Path) -> None:
    base = _settings(_variant(tmp_path / "base"))
    ranking = _settings(_variant(tmp_path / "ranking", ("advisory_kev = 250", "advisory_kev = 400")))
    bands = _settings(_variant(tmp_path / "bands", ("medium = 40\nhigh = 75", "medium = 45\nhigh = 75")))
    assert ranking.ranking.advisory_kev == 400
    assert bands.scoring.providers["application_risk_matrix"].model.exploitability.bands["medium"] == 45
    hashes = {semantic_settings_sha256(item) for item in (base, ranking, bands)}
    assert len(hashes) == 3


@pytest.mark.parametrize("old, new, message", [
    ("advisory_kev = 250", "advisory_kev = 2500", "ranking.advisory_kev must be an integer between 0 and 1000"),
    ("lps = 1000", "lps = 1000\nbogus = 1", "ranking has unknown settings: bogus"),
    ("lps = 1000", "lps = 0.5", "ranking.lps must be an integer"),
    ('implementation = "application_risk_matrix/2"', 'implementation = "application_risk_matrix/7"',
     "implementation must be one of"),
    ('implementation = "application_risk_matrix/2"', 'implementation = "application_risk_matrix/1"',
     "application_risk_matrix/1 takes no"),
    ('implementation = "application_risk_matrix/2"', 'implementation = "application_risk_matrix/2"\nweights = 1',
     "providers.application_risk_matrix has unknown settings: weights"),
    ("verification = { supported = 20, confirmed = 40 }", "verification = { supported = 50, confirmed = 40 }",
     "exploitability.points.verification must not decrease"),
    ("verification = { supported = 20, confirmed = 40 }", "verification = { supported = 20 }",
     "points.verification must give points for exactly: supported, confirmed"),
    ("verification = { supported = 20, confirmed = 40 }",
     "verification = { supported = 20, confirmed = 40 }\nepss = { high = 10 }",
     "exploitability.points has an unknown factor: epss"),
    ("verification = { supported = 20, confirmed = 40 }",
     "verification = { supported = 20, confirmed = 40 }\nthreat = { not_listed = 0, kev_listed = 10 }",
     "may not use factor threat"),
    ("medium = 40\nhigh = 75", "medium = 80\nhigh = 75", "exploitability.bands.medium must be below bands.high"),
    ("medium = 40\nhigh = 75", "medium = 40\nhigh = 75\ncritical = 99", "exactly medium and high"),
    ('high = { low = "low", medium = "medium", high = "high" }',
     'high = { low = "low", medium = "medium", high = "low" }', "must not decrease as exploitability rises"),
])
def test_scoring_model_and_rank_weights_are_validated(tmp_path: Path, old: str, new: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _variant(tmp_path, (old, new))


# ---------------------------------------------------------------- ship-block policy and verifier distinctness

VERIFIER_PROFILE = f"""
{SECTION}.models.verifier]
provider = "claude-cli"
model = "claude-verifier-model"
reasoning = "high"
max_input_tokens = 32000
max_output_tokens = 8000
max_queries = 40
max_turns = 12
timeout_seconds = 600
"""


def test_ship_block_and_verification_default_to_the_recorded_decisions(tmp_path: Path) -> None:
    settings = _settings(load_config(ROOT / "appsec-review.toml"))
    assert settings.ship_block.blocking_technical_severities == ("high", "critical")
    assert settings.ship_block.kev_dependency_blocks is True
    assert settings.ship_block.dependency_lead_families == ("dependency_advisory", "artifact_scanner")
    assert settings.verification.require_distinct_model_for_ship_blocking is True
    # Every checked-in profile is claude-haiku-5-5, so the verifier is not distinct and a warning is recorded.
    assert {profile.model for profile in settings.models.values()} == {"claude-haiku-5-5"}
    record = settings.verifier_distinctness()
    assert record["distinct"] is False and "ship_blocking_pending_distinct_verification" in record["warning"]
    # Omitting both tables keeps the same defaults.
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    start = source.index(f"{SECTION}.verification]")
    end = source.index(f"{SECTION}.routing]")
    assert source.index(f"{SECTION}.ship_block]") < end
    omitted = _settings(_variant(tmp_path / "omitted", (source[start:end], "")))
    assert omitted.ship_block == settings.ship_block and omitted.verification == settings.verification


def test_a_distinct_verifier_profile_clears_the_warning_and_changes_the_fingerprint(tmp_path: Path) -> None:
    base = _settings(_variant(tmp_path / "base"))
    distinct = _settings(_variant(tmp_path / "distinct", ('workers = 4\nmodel_profile = "default"',
                                                         'workers = 4\nmodel_profile = "verifier"'),
                                  suffix=VERIFIER_PROFILE))
    record = distinct.verifier_distinctness()
    assert record["distinct"] is True and record["warning"] is None
    assert record["verifier"] == {"provider": "claude-cli", "model": "claude-verifier-model"}
    assert set(record["red"]) == {"hypothesis_hunter", "red_team_analyst"}
    off = _settings(_variant(tmp_path / "off", ("require_distinct_model_for_ship_blocking = true",
                                                "require_distinct_model_for_ship_blocking = false")))
    assert off.verifier_distinctness()["warning"] is None and off.verifier_distinctness()["distinct"] is False
    critical = _settings(_variant(tmp_path / "critical", ('blocking_technical_severities = ["high", "critical"]',
                                                          'blocking_technical_severities = ["critical"]')))
    assert critical.ship_block.blocking_technical_severities == ("critical",)
    assert len({semantic_settings_sha256(item) for item in (base, distinct, off, critical)}) == 4


@pytest.mark.parametrize("old, new, message", [
    ('blocking_technical_severities = ["high", "critical"]', 'blocking_technical_severities = ["urgent"]',
     "ship_block.blocking_technical_severities has unknown bands"),
    ('blocking_technical_severities = ["high", "critical"]', "blocking_technical_severities = []",
     "at least one band"),
    ("kev_dependency_blocks = true", 'kev_dependency_blocks = "yes"', "kev_dependency_blocks must be a Boolean"),
    ('dependency_lead_families = ["dependency_advisory", "artifact_scanner"]', 'dependency_lead_families = ["pip"]',
     "unknown lead families: pip"),
    ("kev_dependency_blocks = true", "kev_dependency_blocks = true\ncvss_threshold = 7",
     "ship_block has unknown settings: cvss_threshold"),
    ("require_distinct_model_for_ship_blocking = true", "require_distinct_model_for_ship_blocking = 1",
     "require_distinct_model_for_ship_blocking must be a Boolean"),
    ("require_distinct_model_for_ship_blocking = true",
     "require_distinct_model_for_ship_blocking = true\nrequire_distinct_provider = true",
     "verification has unknown settings: require_distinct_provider"),
])
def test_ship_block_and_verification_settings_are_validated(tmp_path: Path, old: str, new: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _variant(tmp_path, (old, new))
