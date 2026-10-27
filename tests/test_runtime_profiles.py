"""Runtime profiles: dev (the checked-in file) is the default; prod is an opt-in, allowlisted layer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from appsec_review.acceptance import model_contract
from appsec_review.acceptance.normalize import Masks
from appsec_review.config import PROFILE_ENVIRONMENT, load_config, profile_override_keys, resolve_profile_name
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_model_connectivity import build_job as build_connectivity
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.review.cells import cell_fingerprint
from appsec_review.runtime import GraphRunner

from tests.review.test_cells import capability, spec

ROOT = Path(__file__).parents[1]
JOB = "job_inference_security_review"
OVERLAY = "[orchestration.dagster.pools]\ninference_teams = 1\n"
MODEL_JOBS = ("job_target_analysis_plan", "job_post_build_security_assessment", "job_dependency_intelligence",
              "job_owasp_control_assessment")


def _checkout(tmp_path: Path, *, profile_text: str | None = None) -> Path:
    """A copy of the base file with its profiles directory, as load_config finds it beside the file."""
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    if profile_text is None:
        shutil.copyfile(ROOT / "profiles" / "prod.toml", tmp_path / "profiles" / "prod.toml")
    else:
        (tmp_path / "profiles" / "prod.toml").write_text(profile_text, encoding="utf-8")
    return tmp_path / "appsec-review.toml"


def _model(config, job_id: str):
    return config.job(job_id).settings["model"]


def _review(config):
    return config.job(JOB).typed_settings


# ---------------------------------------------------------------- selection

def test_dev_is_the_default_and_keeps_todays_values(monkeypatch) -> None:
    monkeypatch.delenv(PROFILE_ENVIRONMENT, raising=False)
    config = load_config(ROOT / "appsec-review.toml")
    assert config.profile == "dev" and config.profile_path is None and len(config.layers) == 1
    assert json.loads(config.resolved_json)["configuration_profile"] == {
        "name": "dev", "path": None, "sha256": None, "keys": []}
    for job_id in MODEL_JOBS:
        assert _model(config, job_id)["model"] == "claude-haiku-5-5"
    assert _model(config, "job_project_build")["max_input_tokens"] == 16000
    review = _review(config)
    assert review.models["default"].model == "claude-haiku-5-5" and "strong" not in review.models
    assert review.roles[next(iter(r for r in review.roles if r == "independent_verifier"))].model_profile == "default"
    assert review.budgets.max_model_turns == 12000 and review.budgets.timeout_seconds == 28800


def test_profile_argument_environment_and_default(monkeypatch) -> None:
    monkeypatch.delenv(PROFILE_ENVIRONMENT, raising=False)
    assert resolve_profile_name() == "dev"
    monkeypatch.setenv(PROFILE_ENVIRONMENT, "prod")
    assert resolve_profile_name() == "prod" and load_config(ROOT / "appsec-review.toml").profile == "prod"
    assert load_config(ROOT / "appsec-review.toml", profile="dev").profile == "dev"
    monkeypatch.setenv(PROFILE_ENVIRONMENT, "")
    assert resolve_profile_name() == "dev"


@pytest.mark.parametrize("value", ["staging", "PROD", " prod", "none"])
def test_unknown_profiles_are_rejected(value: str, monkeypatch) -> None:
    with pytest.raises(ValueError, match="unknown runtime profile"):
        load_config(ROOT / "appsec-review.toml", profile=value)
    monkeypatch.setenv(PROFILE_ENVIRONMENT, value)
    with pytest.raises(ValueError, match="unknown runtime profile"):
        load_config(ROOT / "appsec-review.toml")


def test_cli_profile_flag_is_global_and_defaults_to_the_environment() -> None:
    from appsec_review.cli import parser

    assert parser().parse_args(["schedules"]).profile is None
    assert parser().parse_args(["--profile", "prod", "schedules"]).profile == "prod"
    assert parser().parse_args(["--profile", "copilot-prod", "schedules"]).profile == "copilot-prod"
    with pytest.raises(SystemExit):
        parser().parse_args(["--profile", "staging", "schedules"])


# ---------------------------------------------------------------- the prod values

def test_prod_loads_the_exact_models_and_limits(monkeypatch) -> None:
    monkeypatch.delenv(PROFILE_ENVIRONMENT, raising=False)
    config = load_config(ROOT / "appsec-review.toml", profile="prod")
    expected = {"job_target_analysis_plan": (900, 64000, "high"), "job_post_build_security_assessment": (600, 32000, "high"),
                "job_dependency_intelligence": (600, 32000, "high"), "job_owasp_control_assessment": (600, 32000, "high")}
    for job_id, (timeout, output, reasoning) in expected.items():
        model = _model(config, job_id)
        assert (model["model"], model["reasoning"], model["max_input_tokens"], model["max_output_tokens"],
                model["timeout_seconds"]) == ("claude-sonnet-5-5", reasoning, 200000, output, timeout)
        assert model["provider"] == "claude-cli"
    build = _model(config, "job_project_build")
    assert (build["model"], build["reasoning"], build["max_input_tokens"], build["max_output_tokens"],
            build["timeout_seconds"]) == ("claude-sonnet-5-5", "medium", 128000, 16000, 600)
    review = _review(config)
    default, strong = review.models["default"], review.models["strong"]
    assert (default.model, default.reasoning, default.max_input_tokens, default.max_output_tokens, default.max_queries,
            default.max_turns, default.timeout_seconds) == ("claude-sonnet-5-5", "high", 200000, 64000, 60, 16, 1800)
    assert (strong.provider, strong.model, strong.reasoning, strong.max_input_tokens, strong.max_output_tokens,
            strong.max_queries, strong.max_turns, strong.timeout_seconds) == (
        "claude-cli", "claude-opus-5-5", "high", 200000, 64000, 60, 16, 2400)
    assert review.roles["independent_verifier"].model_profile == "strong"
    for role, settings in review.roles.items():
        if role != "independent_verifier" and role != "adjudication_judge":
            assert settings.model_profile == "default"
    budgets = review.budgets
    assert (budgets.max_model_turns, budgets.max_input_tokens, budgets.max_output_tokens, budgets.max_retrieval_queries,
            budgets.timeout_seconds) == (60000, 600000000, 60000000, 200000, 86400)
    if "adjudication_judge" in review.roles:
        assert review.roles["adjudication_judge"].model_profile == "strong"
    poc = config.job("job_poc_generation").settings["models"]["default"]
    assert (poc["model"], poc["reasoning"], poc["max_input_tokens"], poc["max_output_tokens"]) == (
        "claude-sonnet-5-5", "high", 200000, 32000)
    assert "claude-fable-5-1" not in (ROOT / "profiles" / "prod.toml").read_text(encoding="utf-8")


def test_the_real_prod_file_passes_the_allowlist() -> None:
    import tomllib

    keys = profile_override_keys(tomllib.loads((ROOT / "profiles" / "prod.toml").read_text(encoding="utf-8")))
    assert f"jobs.{JOB}.settings.models.strong.model" in keys
    assert f"jobs.{JOB}.settings.roles.independent_verifier.model_profile" in keys
    assert "jobs.job_poc_generation.settings.models.default.model" in keys


# ---------------------------------------------------------------- layer, freeze, fingerprints

def test_prod_is_a_hashed_layer_frozen_in_the_resolved_document(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    dev = load_config(path, profile="dev")
    prod = load_config(path, profile="prod")
    expected = hashlib.sha256((tmp_path / "profiles" / "prod.toml").read_bytes()).hexdigest()
    assert prod.profile_sha256 == expected and prod.source_sha256 == dev.source_sha256
    assert prod.layers[1] == {"path": str((tmp_path / "profiles" / "prod.toml").resolve()), "sha256": expected,
                              "layer": "runtime_profile"}
    record = json.loads(prod.resolved_json)["configuration_profile"]
    assert (record["name"], record["sha256"], record["layer"]) == ("prod", expected, "runtime_profile")
    assert record["keys"] and record["document"]["jobs"][JOB]["settings"]["models"]["strong"]["model"] == "claude-opus-5-5"
    assert json.loads(prod.resolved_json)["jobs"][JOB]["settings"]["models"]["default"]["model"] == "claude-sonnet-5-5"
    assert prod.resolved_sha256 != dev.resolved_sha256


def test_profile_and_capacity_overlay_produce_both_layers_in_order(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    overlay = tmp_path / "overlay.toml"
    overlay.write_text(OVERLAY, encoding="utf-8")
    config = load_config(path, profile="prod", overlay=overlay)
    assert [layer.get("layer") for layer in config.layers] == [None, "runtime_profile", "capacity_overlay"]
    assert config.dagster.pool_limits["inference_teams"] == 1 and _review(config).models["strong"].model == "claude-opus-5-5"
    resolved = json.loads(config.resolved_json)
    assert resolved["configuration_profile"]["name"] == "prod" and resolved["configuration_overlay"]["keys"]


def test_a_prod_cell_fingerprint_differs_from_dev_for_the_same_inputs(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    prints = {}
    for name in ("dev", "prod"):
        review = _review(load_config(path, profile=name))
        profile = review.models["default"]
        prints[name] = cell_fingerprint(spec(
            provider=profile.provider, model=profile.model, reasoning=profile.reasoning,
            max_input_tokens=profile.max_input_tokens, max_output_tokens=profile.max_output_tokens,
            timeout_seconds=profile.timeout_seconds), capability())
    assert prints["dev"] != prints["prod"]


def test_the_semantic_settings_hash_differs_between_profiles() -> None:
    from appsec_review.config import semantic_settings_sha256

    assert (semantic_settings_sha256(_review(load_config(ROOT / "appsec-review.toml", profile="dev"))) !=
            semantic_settings_sha256(_review(load_config(ROOT / "appsec-review.toml", profile="prod"))))


# ---------------------------------------------------------------- the allowlist

BAD = [
    ("[runtime]\nruns_dir = 'elsewhere'\n", "rejected: runtime"),
    ("[jobs.job_review_intake.settings.model_preflight]\ntimeout_seconds = 1\n", "rejected: jobs.job_review_intake"),
    (f"[jobs.{JOB}.settings.teams]\nreview_teams = 1\n", f"rejected: jobs.{JOB}.settings.teams"),
    (f"[jobs.{JOB}.settings.verification]\nrequire_distinct_model_for_ship_blocking = false\n",
     "settings.verification"),
    (f"[jobs.{JOB}.settings.budgets]\nbudget_team_packages = 1\n", "budgets.budget_team_packages"),
    (f"[jobs.{JOB}.workers]\n", "rejected: jobs.job_inference_security_review.workers"),
    ("[jobs.job_target_analysis_plan.settings.model]\nenabled = false\n", "model.enabled"),
    ("[jobs.job_target_analysis_plan.settings.model]\nworkers = 1\n", "model.workers"),
    ("[jobs.job_target_analysis_plan.settings.steps]\nx = 1\n", "rejected: jobs.job_target_analysis_plan.settings.steps"),
    ("[jobs.job_codeql_analysis.settings.model]\nmodel = 'x'\n", "rejected: jobs.job_codeql_analysis"),
    ("[jobs.job_project_build.settings.model]\nmax_input_tokens = '1'\n", "max_input_tokens must be a non-negative integer"),
    ("[jobs.job_project_build.settings.model]\nmodel = 5\n", "model must be a non-empty string"),
    ("[jobs.job_project_build.settings.model]\nmax_output_tokens = true\n", "max_output_tokens must be"),
    (f"[jobs.{JOB}.settings.models.strong]\nweights = 1\n", "models.strong.weights"),
    (f"[jobs.{JOB}.settings.models.Strong]\nmodel = 'x'\n", "model profile name is invalid"),
    (f"[jobs.{JOB}.settings.roles.independent_verifier]\nworkers = 9\n", "roles.independent_verifier.workers"),
    (f"[jobs.{JOB}.settings.budgets]\nmax_model_turns = 1.5\n", "max_model_turns must be"),
    (f"[jobs.{JOB}.settings.budgets]\n", "non-empty table"),
    ("", "non-empty table"),
]


@pytest.mark.parametrize("text, message", BAD)
def test_profile_keys_outside_the_allowlist_are_rejected(tmp_path: Path, text: str, message: str) -> None:
    path = _checkout(tmp_path, profile_text=text)
    with pytest.raises(ValueError, match=message):
        load_config(path, profile="prod")


def test_typed_validation_still_runs_after_the_merge(tmp_path: Path) -> None:
    unknown_role = f"[jobs.{JOB}.settings.roles.independent_verifier]\nmodel_profile = 'nonexistent'\n"
    with pytest.raises(ValueError, match="nonexistent"):
        load_config(_checkout(_dir(tmp_path, "a"), profile_text=unknown_role), profile="prod")
    no_role = f"[jobs.{JOB}.settings.roles.invented_role]\nmodel_profile = 'default'\n"
    with pytest.raises(ValueError, match="no such table"):
        load_config(_checkout(_dir(tmp_path, "b"), profile_text=no_role), profile="prod")
    incomplete = f"[jobs.{JOB}.settings.models.extra]\nmodel = 'x'\n"
    with pytest.raises(ValueError):
        load_config(_checkout(_dir(tmp_path, "c"), profile_text=incomplete), profile="prod")


def _dir(base: Path, name: str) -> Path:
    (base / name).mkdir()
    return base / name


def test_a_missing_profile_file_is_a_clear_error(tmp_path: Path) -> None:
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "appsec-review.toml", profile="prod")
    assert load_config(tmp_path / "appsec-review.toml", profile="dev").profile == "dev"


# ---------------------------------------------------------------- runs

def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    return target


def _everything_available(calls: list):
    def check(provider: str, names, *, timeout_seconds: int):
        calls.append((provider, tuple(sorted(names))))
        return {"provider": provider, "transport": True, "method": "catalog", "listed": sorted(names), "error": None,
                "models": {name: {"available": True, "detail": "listed"} for name in names}}
    return check


def test_model_preflight_and_connectivity_list_the_active_profiles_models(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    target = _target(tmp_path)
    for name, expected in (("dev", ("claude-haiku-5-5",)), ("prod", ("claude-opus-5-5", "claude-sonnet-5-5"))):
        config = load_config(path, profile=name)
        calls: list = []
        check = _everything_available(calls)
        outcome = GraphRunner(config, [build_connectivity(check_models=check), build_intake(check_models=check)]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
        assert outcome["status"] == "SUCCEEDED", outcome
        assert calls and all(models == expected for _, models in calls), (name, calls)
        run_root = config.runtime.runs_dir / outcome["run_id"]
        document = json.loads(next(run_root.rglob("model-preflight.json")).read_text(encoding="utf-8"))
        assert sorted({item["model"] for item in document["required"]}) == list(expected)


def test_review_intake_freezes_the_profile_layer(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    target = _target(tmp_path)
    config = load_config(path, profile="prod")
    outcome = GraphRunner(config, [build_intake()]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    assert outcome["status"] == "SUCCEEDED"
    run_root = config.runtime.runs_dir / outcome["run_id"]
    manifest = json.loads((run_root / "data/configuration/manifest.json").read_text(encoding="utf-8"))
    assert manifest["sources"] == [dict(layer) for layer in config.layers]
    intake = json.loads(next(run_root.rglob("review-intake.json")).read_text(encoding="utf-8"))["configuration"]
    assert intake["profile"] == "prod" and [layer.get("layer") for layer in intake["layers"]] == [None, "runtime_profile"]
    assert intake["layers"][1]["sha256"] == config.profile_sha256


def test_review_intake_with_profile_and_overlay_and_with_dev(tmp_path: Path) -> None:
    path = _checkout(tmp_path)
    target = _target(tmp_path)
    overlay = tmp_path / "overlay.toml"
    overlay.write_text(OVERLAY, encoding="utf-8")
    config = load_config(path, profile="prod", overlay=overlay)
    outcome = GraphRunner(config, [build_intake()]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    intake = json.loads(next((config.runtime.runs_dir / outcome["run_id"]).rglob("review-intake.json")).read_text(
        encoding="utf-8"))["configuration"]
    assert [layer.get("layer") for layer in intake["layers"]] == [None, "runtime_profile", "capacity_overlay"]
    dev = load_config(path, profile="dev")
    outcome = GraphRunner(dev, [build_intake()]).run(target_root=target, source_fingerprint=source_fingerprint(target))
    intake = json.loads(next((dev.runtime.runs_dir / outcome["run_id"]).rglob("review-intake.json")).read_text(
        encoding="utf-8"))["configuration"]
    assert intake["profile"] == "dev" and len(intake["layers"]) == 1


# ---------------------------------------------------------------- the model contract

def _call(job: str = "job_a"):
    request = {"schema": "appsec-review/x/1", "summary": {"n": 1}}
    return model_contract.Call(job, request, {"schema": "appsec-review/x/1"}, None)


def test_a_contract_is_bound_to_the_profile_it_was_recorded_under() -> None:
    masks = Masks.for_run("2026-10-21-0001")
    prod = model_contract.baseline_document([_call()], masks, run_id="2026-10-21-0001", profile="prod")
    assert prod["profile"] == "prod"
    assert not model_contract.check(prod, [_call()], masks, ROOT, profile="prod").failed
    mismatch = model_contract.check(prod, [_call()], masks, ROOT, profile="dev")
    assert mismatch.failed and "profile mismatch" in mismatch.input_problems[0]
    dev = model_contract.baseline_document([_call()], masks, run_id="2026-10-21-0001")
    assert dev["profile"] == "dev" and model_contract.check(dev, [_call()], masks, ROOT).failed is False
    legacy = {key: value for key, value in dev.items() if key != "profile"}
    assert not model_contract.check(legacy, [_call()], masks, ROOT, profile="dev").failed
    assert "profile mismatch" in model_contract.check(legacy, [_call()], masks, ROOT, profile="prod").input_problems[0]


def test_run_profile_reads_the_frozen_configuration(tmp_path: Path) -> None:
    configuration = tmp_path / "data" / "configuration"
    configuration.mkdir(parents=True)
    (configuration / "resolved.json").write_text(json.dumps({"configuration_profile": {"name": "prod"}}), encoding="utf-8")
    assert model_contract.run_profile(tmp_path) == "prod"
    (configuration / "resolved.json").write_text("{}", encoding="utf-8")
    assert model_contract.run_profile(tmp_path) == "dev"
    with pytest.raises(ValueError):
        model_contract.run_profile(tmp_path / "missing")
