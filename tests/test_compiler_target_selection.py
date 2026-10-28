from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

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
