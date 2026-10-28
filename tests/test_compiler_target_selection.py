from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from appsec_review.cli import parser
from appsec_review.config import load_config
from appsec_review.config.compiler_target import (
    COMPILER_TARGET_TAG, CompilerTarget, compiler_target,
)
from appsec_review.config.run_selection import RunConfigurations, reject_run_selection
from appsec_review.debug_symbols.contract import AddressRange, record_fingerprint, selected_path
from appsec_review.runtime.runner import JobRunner


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("value", ["gcc", "MSVC", "", None, 1, True])
def test_compiler_target_is_a_closed_enum(value) -> None:
    with pytest.raises(ValueError, match="clang or msvc"):
        compiler_target(value)


@pytest.mark.parametrize("target", list(CompilerTarget))
def test_start_accepts_a_compiler_target_without_overloading_the_checkout(target) -> None:
    args = parser().parse_args(["start", "--target", "customer", "--compiler-target", target.value])
    assert args.target == Path("customer")
    assert args.compiler_target == target.value


def test_target_is_frozen_in_configuration_and_changes_its_identity(monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    clang = load_config(ROOT / "appsec-review.toml", profile="dev", compiler_target="clang")
    msvc = load_config(ROOT / "appsec-review.toml", profile="dev", compiler_target="msvc")
    assert clang.compiler_target is CompilerTarget.CLANG
    assert msvc.compiler_target is CompilerTarget.MSVC
    assert clang.resolved_sha256 != msvc.resolved_sha256
    assert json.loads(msvc.resolved_json)["compiler_target"] == "msvc"
    assert msvc.job("job_debug_symbol_indexing").settings["compiler_target"] == "msvc"


def test_launch_tags_compose_with_profile_selection_and_cache(monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    base = load_config(ROOT / "appsec-review.toml", profile="dev")
    configs = RunConfigurations(base)
    assert configs.for_tags({}) is base
    assert configs.for_tags({COMPILER_TARGET_TAG: "clang"}) is base
    tags = {COMPILER_TARGET_TAG: "msvc", "appsec/profile": "prod"}
    selected = configs.for_run(SimpleNamespace(tags=tags))
    assert selected.compiler_target is CompilerTarget.MSVC
    assert selected.profile == "prod"
    assert selected.selection_source == "run_tags"
    assert configs.for_tags(tags) is selected
    assert configs.for_tags({COMPILER_TARGET_TAG: "msvc"}).profile == "dev"
    with pytest.raises(ValueError, match="clang or msvc"):
        configs.for_tags({COMPILER_TARGET_TAG: "gcc"})
    with pytest.raises(ValueError, match="fixed_job"):
        reject_run_selection(base, {COMPILER_TARGET_TAG: "msvc"}, "fixed_job")


def test_a_run_cannot_change_its_compiler_target(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    clang = load_config(ROOT / "appsec-review.toml", profile="dev", compiler_target="clang")
    msvc = load_config(ROOT / "appsec-review.toml", profile="dev", compiler_target="msvc")
    JobRunner(msvc)._bind_configuration(tmp_path)
    manifest = json.loads((tmp_path / "data" / "configuration" / "manifest.json").read_text())
    assert manifest["selection"]["compiler_target"] == "msvc"
    JobRunner(msvc)._bind_configuration(tmp_path)
    with pytest.raises(ValueError, match="different configuration"):
        JobRunner(clang)._bind_configuration(tmp_path)


def test_native_execution_refuses_compiler_only_tag_changes(monkeypatch) -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    monkeypatch.setenv("APPSEC_NATIVE_TEST", "1")
    with pytest.raises(ValueError, match="native execution"):
        RunConfigurations(config).for_tags({COMPILER_TARGET_TAG: "msvc"})
    assert RunConfigurations(config).for_tags({COMPILER_TARGET_TAG: "clang"}) is config


def test_safety_envelope_refuses_a_compiler_tag_different_from_submission() -> None:
    from appsec_review.orchestration.dagster.fail_fast import _envelope
    from appsec_review.runtime import execution_safety

    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    resolved = json.loads(config.resolved_json)
    envelope = execution_safety.policy(str(uuid4()), {
        "source_commit": "a" * 40, "target_commit": "b" * 40,
        "configuration": {
            "base_sha256": config.source_sha256, "profile": "dev",
            "profile_sha256": resolved["configuration_profile"]["sha256"],
            "overlay_sha256": resolved.get("configuration_overlay", {}).get("sha256"),
            "compiler_target": "clang",
        }})
    run = SimpleNamespace(
        run_id=envelope["dagster_run_id"],
        run_config={"execution": {"config": {"safety": envelope}}},
        tags={"dagster/max_retries": "0", "appsec/safety_identity": execution_safety.identity(envelope)})
    assert _envelope(run, RunConfigurations(config)) == envelope
    run.tags[COMPILER_TARGET_TAG] = "msvc"
    with pytest.raises(ValueError, match="frozen safety envelope"):
        _envelope(run, RunConfigurations(config))


def test_compiler_routes_are_explicit_and_ranges_are_unsigned_half_open() -> None:
    assert selected_path(CompilerTarget.CLANG) == "clang_dwarf"
    assert selected_path(CompilerTarget.MSVC) == "msvc_pdb"
    assert AddressRange(2**64 - 1, 2**64).end == 2**64
    for pair in ((0, 0), (-1, 1), (0, 2**64 + 1), (True, 2)):
        with pytest.raises(ValueError):
            AddressRange(*pair)
    assert record_fingerprint("a" * 64, "b" * 64, "42") != record_fingerprint(
        "a" * 64, "c" * 64, "42")
    with pytest.raises(ValueError):
        record_fingerprint("A" * 64, "b" * 64, "42")


def test_operator_launch_selection_restores_and_refuses_target_drift(tmp_path, monkeypatch) -> None:
    import tests.operator_support  # noqa: F401
    import ops

    monkeypatch.setattr(ops, "ROOT", tmp_path)
    args = SimpleNamespace(run_id=None, compiler_target=None)
    assert ops.run_compiler_target(args) == "clang"
    args.compiler_target = "msvc"
    assert ops.run_compiler_target(args) == "msvc"
    args.run_id = "2026-10-28-0001"
    configuration = tmp_path / "runs" / args.run_id / "data" / "configuration"
    configuration.mkdir(parents=True)
    (configuration / "manifest.json").write_text(json.dumps({
        "selection": {"compiler_target": "msvc"}}))
    args.compiler_target = None
    assert ops.run_compiler_target(args) == "msvc"
    args.compiler_target = "clang"
    with pytest.raises(ops.OpsError, match="cannot change"):
        ops.run_compiler_target(args)


def test_cli_resume_restores_frozen_target_before_constructing_the_graph(tmp_path, monkeypatch) -> None:
    import appsec_review.cli as cli

    configuration = tmp_path / "2026-10-28-0001" / "data" / "configuration"
    configuration.mkdir(parents=True)
    (configuration / "manifest.json").write_text(json.dumps({
        "selection": {"compiler_target": "msvc"}}))
    real_load = load_config
    selected = []

    def load(path, **kwargs):
        config = real_load(path, **kwargs)
        return replace(config, runtime=replace(config.runtime, runs_dir=tmp_path))

    def graph(config, jobs):
        selected.append(config.compiler_target)
        return SimpleNamespace(plan=lambda *_args, **_kwargs: [])

    monkeypatch.setattr(cli, "load_config", load)
    monkeypatch.setattr(cli, "active_job_ids", lambda *_args: ())
    monkeypatch.setattr(cli, "builtin_registry", lambda: SimpleNamespace())
    monkeypatch.setattr(cli, "GraphRunner", graph)
    monkeypatch.setattr(cli, "source_fingerprint", lambda *_args: "test-source")
    assert cli.main(["--config", str(ROOT / "appsec-review.toml"),
                     "plan-resume", "--run-id", "2026-10-28-0001",
                     "--target", str(tmp_path)]) == 0
    assert selected == [CompilerTarget.MSVC]
