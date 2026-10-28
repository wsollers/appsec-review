"""Per-run profile/overlay selection: launch tags, the code-location resolver, the executor and the budget guard."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.config import OVERLAY_ENVIRONMENT, PROFILE_ENVIRONMENT, load_config
from appsec_review.config.assurance import ResourceBudget
from appsec_review.config.run_selection import (
    OVERLAY_TAG, PROFILE_TAG, RunConfigurations, reject_run_selection, requested_selection,
)
from appsec_review.orchestration.dagster.fail_fast import SafetyExecutor
from appsec_review.runtime.resources import budget_conflicts
from appsec_review.runtime.runner import JobRunner

from tests.operator_support import REPOSITORY

import ops  # noqa: E402  (tests.operator_support puts deploy/dagster/bin on sys.path)

CAPACITY = "[orchestration.dagster.pools]\ninference_teams = 1\n"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch):
    for name in (PROFILE_ENVIRONMENT, OVERLAY_ENVIRONMENT):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    """A copy of the base file, its profiles and one acceptance overlay."""
    root = tmp_path / "checkout"
    shutil.copytree(REPOSITORY / "profiles", root / "profiles")
    shutil.copyfile(REPOSITORY / "appsec-review.toml", root / "appsec-review.toml")
    (root / "test" / "acceptance").mkdir(parents=True)
    (root / "test" / "acceptance" / "cap.toml").write_text(CAPACITY, encoding="utf-8")
    return root


def _overlay(root: Path) -> str:
    return str((root / "test" / "acceptance" / "cap.toml").resolve())


def test_an_empty_overlay_argument_overrides_the_environment(checkout: Path, monkeypatch) -> None:
    monkeypatch.setenv(OVERLAY_ENVIRONMENT, _overlay(checkout))
    assert load_config(checkout / "appsec-review.toml").overlay_path is not None
    assert load_config(checkout / "appsec-review.toml", overlay="").overlay_path is None


def test_untagged_or_matching_runs_keep_the_base_configuration(checkout: Path) -> None:
    configs = RunConfigurations(load_config(checkout / "appsec-review.toml"))
    assert configs.for_tags({}) is configs.base
    assert configs.for_tags({PROFILE_TAG: "dev", OVERLAY_TAG: "none"}) is configs.base
    assert configs.for_run(SimpleNamespace(tags={"other": "x"})) is configs.base


def test_tags_select_the_runs_profile_and_overlay(checkout: Path) -> None:
    configs = RunConfigurations(load_config(checkout / "appsec-review.toml"))
    prod = configs.for_tags({PROFILE_TAG: "prod", OVERLAY_TAG: _overlay(checkout)})
    assert prod.profile == "prod" and prod.overlay_path == Path(_overlay(checkout))
    assert prod.dagster.pool_limits["inference_teams"] == 1 != configs.base.dagster.pool_limits["inference_teams"]
    assert prod.selection_source == "run_tags" and configs.base.selection_source == "environment"
    assert prod.resolved_sha256 == load_config(checkout / "appsec-review.toml", profile="prod",
                                               overlay=_overlay(checkout)).resolved_sha256
    assert configs.for_tags({PROFILE_TAG: "prod", OVERLAY_TAG: _overlay(checkout)}) is prod


def test_none_drops_the_containers_overlay(checkout: Path) -> None:
    base = load_config(checkout / "appsec-review.toml", overlay=_overlay(checkout))
    selected = RunConfigurations(base).for_tags({OVERLAY_TAG: "none"})
    assert selected.overlay_path is None and selected.profile == base.profile


@pytest.mark.parametrize(("tags", "message"), [
    ({PROFILE_TAG: "staging"}, "not a runtime profile"),
    ({PROFILE_TAG: "copilot-dev"}, "provider is fixed"),
    ({OVERLAY_TAG: "relative.toml"}, "absolute path"),
    ({OVERLAY_TAG: "MISSING"}, "no readable file"),
])
def test_invalid_selections_are_refused(checkout: Path, tags: dict, message: str) -> None:
    if tags.get(OVERLAY_TAG) == "MISSING":
        tags = {OVERLAY_TAG: str((checkout / "test" / "acceptance" / "missing.toml").resolve())}
    with pytest.raises(ValueError, match=message):
        RunConfigurations(load_config(checkout / "appsec-review.toml")).for_tags(tags)


def test_an_overlay_outside_test_acceptance_is_refused(checkout: Path) -> None:
    outside = checkout / "cap.toml"
    outside.write_text(CAPACITY, encoding="utf-8")
    with pytest.raises(ValueError, match="must be a file under"):
        RunConfigurations(load_config(checkout / "appsec-review.toml")).for_tags({OVERLAY_TAG: str(outside)})


def test_overlay_allowlist_is_still_enforced(checkout: Path) -> None:
    bad = checkout / "test" / "acceptance" / "bad.toml"
    bad.write_text("[runtime]\nruns_dir = \"elsewhere\"\n", encoding="utf-8")
    with pytest.raises(ValueError):
        RunConfigurations(load_config(checkout / "appsec-review.toml")).for_tags({OVERLAY_TAG: str(bad.resolve())})


def test_native_execution_refuses_a_per_run_selection(checkout: Path, monkeypatch) -> None:
    base = load_config(checkout / "appsec-review.toml")
    monkeypatch.setenv("APPSEC_NATIVE_TEST", "1")
    assert requested_selection(base, {PROFILE_TAG: "dev"}) is None
    with pytest.raises(ValueError, match="native execution"):
        requested_selection(base, {PROFILE_TAG: "prod"})


def test_jobs_with_a_fixed_executor_refuse_another_selection(checkout: Path) -> None:
    base = load_config(checkout / "appsec-review.toml")
    reject_run_selection(base, {PROFILE_TAG: "dev"}, "tree_sitter_ast")
    with pytest.raises(ValueError, match="tree_sitter_ast"):
        reject_run_selection(base, {PROFILE_TAG: "prod"}, "tree_sitter_ast")


def test_the_executor_applies_the_runs_own_pool_limits(checkout: Path) -> None:
    class Delegate:
        def __init__(self, name):
            self.name = name

        def execute(self, _context, _plan):
            yield self.name

    configs = RunConfigurations(load_config(checkout / "appsec-review.toml"))
    built = []

    def rebuild(config):
        built.append(config.dagster.pool_limits["inference_teams"])
        return Delegate("per-run")

    executor = SafetyExecutor(Delegate("base"), configs, rebuild=rebuild)

    def context(tags):
        return SimpleNamespace(dagster_run=SimpleNamespace(tags=tags, run_config={}, run_id="r"))

    assert list(executor.execute(context({}), None)) == ["base"]
    assert list(executor.execute(context({PROFILE_TAG: "prod"}), None)) == ["base"]  # same pools: no rebuild
    assert list(executor.execute(context({OVERLAY_TAG: _overlay(checkout)}), None)) == ["per-run"]
    assert built == [1]


def test_the_run_manifest_records_the_selection(checkout: Path, tmp_path: Path) -> None:
    config = RunConfigurations(load_config(checkout / "appsec-review.toml")).for_tags(
        {PROFILE_TAG: "prod", OVERLAY_TAG: _overlay(checkout)})
    run_root = tmp_path / "run"
    JobRunner(config)._bind_configuration(run_root)
    manifest = json.loads((run_root / "data" / "configuration" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["selection"] == {"profile": "prod", "overlay": _overlay(checkout), "source": "run_tags"}
    with pytest.raises(ValueError, match="profile prod, overlay .*cap.toml; this attempt resolved profile dev"):
        JobRunner(load_config(checkout / "appsec-review.toml"))._bind_configuration(run_root)


def _ledger(metadata: Path, **limits: int) -> None:
    path = metadata / "resource-admission" / "leases.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema": "appsec-review/resource-leases/1", "leases": {"lease-1": {
        "pid": 7, "containers": [], "reservation": {"cpu": 1, "memory_mb": 256, "io_slots": 1},
        "limits": limits, "action": "codeql.database"}}}), encoding="utf-8")


def test_budget_conflicts_name_leases_with_other_limits(tmp_path: Path) -> None:
    budget = ResourceBudget(cpu=8, memory_mb=10240, io_slots=1)
    assert budget_conflicts(tmp_path, budget) == []
    _ledger(tmp_path, cpu=8, memory_mb=10240, io_slots=1)
    assert budget_conflicts(tmp_path, budget) == []
    _ledger(tmp_path, cpu=4, memory_mb=10240, io_slots=1)
    [conflict] = budget_conflicts(tmp_path, budget)
    assert "active lease lease-1 (codeql.database, pid 7)" in conflict and "'cpu': 4" in conflict


def _code(**settings: str) -> ops.Container:
    return ops.Container(id="c", name="code", service="code-location", state="running", health="healthy",
                         image="i", config_files=(), settings=settings)


def test_the_launch_guard_refuses_a_budget_that_would_clamp_even_with_force(checkout: Path, monkeypatch) -> None:
    monkeypatch.setattr(ops, "ROOT", checkout)
    code = _code()
    ops.guard_resource_budget([], code, "dev", "")  # nothing active, no ledger: no load at all
    budget = load_config(checkout / "appsec-review.toml").review_policy.resources
    _ledger(checkout / "runs" / "metadata", cpu=budget.cpu, memory_mb=budget.memory_mb, io_slots=budget.io_slots)
    ops.guard_resource_budget([], code, "prod", "/opt/app/test/acceptance/cap.toml")
    _ledger(checkout / "runs" / "metadata", cpu=budget.cpu + 1, memory_mb=budget.memory_mb, io_slots=budget.io_slots)
    with pytest.raises(ops.OpsError, match="lease-1") as refused:
        ops.guard_resource_budget([], code, "dev", "")
    assert refused.value.code == ops.REFUSED and "--force does not override" in str(refused.value)


def test_the_launch_guard_compares_active_runs_by_their_tags(checkout: Path, monkeypatch) -> None:
    monkeypatch.setattr(ops, "ROOT", checkout)
    active = [{"runId": "r1", "tags": [{"key": PROFILE_TAG, "value": "prod"}, {"key": OVERLAY_TAG, "value": "none"}]}]
    ops.guard_resource_budget(active, _code(), "dev", "")  # same budget: allowed
    budgets = {"dev": ResourceBudget(cpu=8), "prod": ResourceBudget(cpu=4)}
    real = ops.host_budget

    def fake(profile, overlay):
        loaded = real(profile, overlay)
        return SimpleNamespace(runtime=loaded.runtime, review_policy=SimpleNamespace(resources=budgets[profile]))

    monkeypatch.setattr(ops, "host_budget", fake)
    with pytest.raises(ops.OpsError, match="run r1 \\(profile prod, overlay none\\)"):
        ops.guard_resource_budget(active, _code(), "dev", "")


def test_a_resumed_run_defaults_to_its_recorded_selection(checkout: Path, monkeypatch) -> None:
    monkeypatch.setattr(ops, "ROOT", checkout)
    configuration = checkout / "runs" / "2026-10-21-0003" / "data" / "configuration"
    configuration.mkdir(parents=True)
    (configuration / "manifest.json").write_text(json.dumps({"selection": {
        "profile": "prod", "overlay": "/opt/app/test/acceptance/cap.toml", "source": "run_tags"}}), encoding="utf-8")
    args = SimpleNamespace(run_id="2026-10-21-0003", profile=None, overlay=None)
    assert ops.run_selection(args, _code()) == (("prod", "recorded by run 2026-10-21-0003"),
                                                ("/opt/app/test/acceptance/cap.toml", "recorded by run 2026-10-21-0003"))
    explicit = SimpleNamespace(run_id="2026-10-21-0003", profile="dev", overlay=None)
    assert ops.run_selection(explicit, _code())[0] == ("dev", "requested")
    fresh = SimpleNamespace(run_id=None, profile=None, overlay=None)
    assert ops.run_selection(fresh, _code(**{ops.PROFILE_VARIABLE: "prod"})) == (
        ("prod", "container default"), ("", "container default"))
    with pytest.raises(ops.OpsError, match="stack-restart --profile copilot-dev"):
        ops.run_selection(SimpleNamespace(run_id=None, profile="copilot-dev", overlay=None), _code())
