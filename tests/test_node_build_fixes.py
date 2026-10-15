"""Focused regressions for live Node build failures (TS2688, EROFS, false artifact gaps)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.applicability import (
    ProcessingFeature, evaluate_applicability, facts_from_build_unit,
)
from appsec_review.config import load_config
from appsec_review.container_runtime.project_images import _restore_command
from appsec_review.inference import ModelResult
from appsec_review.jobs.build_discovery import normalize_build_recipe, validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build.job import _has_build_output
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_project_build.job import _node_recipe_restores_dependencies
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from tests.capture_fakes import capturing_fake
from tests.test_language_build_node import _ImageResolver, _NodeExecutor, _NodeRecipeModel


ROOT = Path(__file__).parents[1]


def _node_unit(root: str, manifest: dict) -> dict:
    return {"build_unit_id": "unit", "family": "node", "root": root, "build_system": "node",
            "markers": [{"path": f"{root}/package.json"}],
            "descriptor_package": {"gaps": [], "documents": [{
                "path": f"{root}/package.json", "sha256": "1" * 64,
                "content": json.dumps(manifest)}]}}


def _node_recipe(root: str) -> dict:
    return {"schema": "appsec-review/build-recipe/1", "build_unit_id": "unit",
            "image_profile": "node", "source_dir": root, "build_dir": f"{root}/dist",
            "system_packages": [], "environment": {},
            "dependency_files": [f"{root}/package.json"], "configure_commands": [],
            "build_commands": [["npm", "run", "build"]], "expected_outputs": [f"{root}/dist"],
            "network_required": False, "reason": "fixture"}


def test_lockless_manifest_with_declared_packages_requires_the_dependency_restore() -> None:
    # Live signature: typescript/case-012 declares typescript and @types/node as devDependencies
    # without a lockfile. The recipe skipped the restore and tsc failed with TS2688 for 'node'.
    declared = _node_unit("web", {"scripts": {"build": "tsc"},
                                  "devDependencies": {"typescript": "^5.5.0", "@types/node": "^20"}})
    normalized = normalize_build_recipe(_node_recipe("web"), declared)
    assert normalized["network_required"] is True
    restore = _restore_command({**normalized, "build_system": "node"})
    assert restore[:2] == ("npm", "install") and "--ignore-scripts" in restore
    assert validate_build_recipe(normalized, declared) == []

    syntax_only = _node_unit("web", {"scripts": {"build": "node --check index.js"}})
    assert normalize_build_recipe(_node_recipe("web"), syntax_only)["network_required"] is False
    empty = _node_unit("web", {"scripts": {"build": "tsc"}, "devDependencies": {}})
    assert normalize_build_recipe(_node_recipe("web"), empty)["network_required"] is False


def test_installer_detection_accepts_prefixed_package_manager_commands() -> None:
    assert _node_recipe_restores_dependencies({"configure_commands": [["npm", "ci"]]})
    assert _node_recipe_restores_dependencies(
        {"configure_commands": [["npm", "--prefix", "web", "ci", "--ignore-scripts"]]})
    assert _node_recipe_restores_dependencies(
        {"configure_commands": [["pnpm", "--dir", "web", "install"]]})
    assert not _node_recipe_restores_dependencies({"configure_commands": [["npm", "run", "ci"]]})
    assert not _node_recipe_restores_dependencies({"configure_commands": []})


def test_compiler_artifact_validation_ignores_retained_accepted_inputs() -> None:
    assert not _has_build_output(
        {"artifacts": [{"kind": "package-metadata", "artifact_origin": "accepted-input"}]})
    assert _has_build_output(
        {"artifacts": [{"kind": "generated-code", "artifact_origin": "build-output"}]})
    assert not _has_build_output({"artifacts": []})


@pytest.mark.parametrize(("manifest", "action"), (
    ({"scripts": {"build": "node --check index.js"}}, "skip"),
    ({"scripts": {"postinstall": "node scripts/postinstall.js",
                  "build": "node --check index.js"}}, "skip"),
    ({"scripts": {"build": "tsc"}, "devDependencies": {"typescript": "^5.5.0"}}, "run"),
    ({"scripts": {"build": "esbuild src/index.js --bundle --outfile=dist/bundle.js"},
      "devDependencies": {"esbuild": "0.28.2"}}, "run"),
    ({"scripts": {"build": "node-gyp rebuild"}, "dependencies": {"node-addon-api": "8.3.0"}}, "run"),
))
def test_configured_node_artifact_policy_skips_only_units_without_compiler_output(
        manifest: dict, action: str) -> None:
    # Live signature: `node --check` units succeeded but were recorded as
    # compiler-artifact-collection ARTIFACT_VALIDATION_FAILED under the "required" default.
    settings = load_config(ROOT / "appsec-review.toml").job("job_language_build").typed_settings
    decision = evaluate_applicability(
        feature=ProcessingFeature.COMPILER_ARTIFACTS,
        policy=settings.compiler_artifact_mode("node").value,
        facts=facts_from_build_unit(_node_unit(".", manifest)), configuration_sha256="a" * 64)
    assert decision.action.value == action.upper()
    if action == "skip":
        assert decision.disposition.value == "SKIPPED_NA"


class _InstallingNodeModel(_NodeRecipeModel):
    def complete(self, request, *, timeout_seconds):
        result = super().complete(request, timeout_seconds=timeout_seconds)
        recipes = [{**recipe, "configure_commands": [["npm", "ci"]],
                    "build_commands": [["npm", "run", "build"]]}
                   for recipe in result.proposal["build_recipes"]]
        return ModelResult({**result.proposal, "build_recipes": recipes})


def test_recipe_installer_owns_node_modules_in_probe_and_language_build(tmp_path: Path) -> None:
    # Live signature: `npm ci` failed with EROFS removing node_modules/.bin because the
    # workspace node_modules had been linked to the read-only image dependency tree.
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target"
    root = target / "web"
    (root / "src").mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({
        "scripts": {"build": "webpack --mode production"},
        "devDependencies": {"webpack": "5.95.0"},
    }), encoding="utf-8")
    (root / "package-lock.json").write_text(json.dumps({
        "name": "fixture", "lockfileVersion": 3, "packages": {},
    }), encoding="utf-8")
    (root / "src" / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    config = load_config(config_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=_InstallingNodeModel().complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, ...]] = []
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: capturing_fake(profile, _NodeExecutor(calls)),
        image_resolver_factory=lambda unit: _ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: _NodeExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    receipts = load_accepted_language_build(config.runtime.runs_dir / upstream["run_id"])["receipts"]
    assert outcome["status"] == "SUCCEEDED", [item.get("gaps") for item in receipts]
    assert ("npm", "ci") in calls
    assert not [call for call in calls if call[0] == "prepare-node-dependencies"]
    assert receipts[0]["terminal_status"] == "SUCCEEDED"


def test_dependency_restore_policy_generalizes_across_synthetic_workspace_roots() -> None:
    """A non-multivuln monorepo: a pnpm workspace member, a Yarn tool, and a script-only root."""
    pnpm_lock = {"path": "pnpm-lock.yaml", "sha256": "3" * 64, "content": "lockfileVersion: '9.0'\n"}
    root_manifest = {"path": "package.json", "sha256": "4" * 64,
                     "content": json.dumps({"private": True, "workspaces": ["packages/*"]})}

    def unit(root: str, manifest: dict, *extra: dict) -> dict:
        value = _node_unit(root, manifest)
        value["descriptor_package"]["documents"].extend(extra)
        return value

    web = unit("packages/web", {"scripts": {"build": "vite build"},
                                "dependencies": {"react": "18.3.1"},
                                "devDependencies": {"vite": "5.4.11"}}, root_manifest, pnpm_lock)
    cli = unit("tools/cli", {"scripts": {"build": "node --check bin.js"}},
               {"path": "tools/cli/yarn.lock", "sha256": "5" * 64, "content": ""})
    script_only = unit("docs", {"scripts": {"build": "node --check build.js"}}, root_manifest)

    web_recipe = normalize_build_recipe(
        {**_node_recipe("packages/web"), "build_commands": [["pnpm", "run", "build"]]}, web)
    assert web_recipe["network_required"] is True
    assert {"package.json", "pnpm-lock.yaml"} <= set(web_recipe["dependency_files"])
    restore = _restore_command({**web_recipe, "build_system": "node"})
    assert restore[:3] == ("pnpm", "--dir", "/opt/project") and "--ignore-scripts" in restore

    cli_recipe = normalize_build_recipe(
        {**_node_recipe("tools/cli"),
         "dependency_files": ["tools/cli/package.json", "tools/cli/yarn.lock"],
         "configure_commands": [["yarn", "--cwd", "tools/cli", "install"]],
         "build_commands": [["yarn", "run", "build"]]}, cli)
    assert cli_recipe["network_required"] is False  # nothing declared: the recipe's choice stands
    assert _node_recipe_restores_dependencies(cli_recipe)
    assert normalize_build_recipe(_node_recipe("docs"), script_only)["network_required"] is False

    settings = load_config(ROOT / "appsec-review.toml").job("job_language_build").typed_settings
    policy = settings.compiler_artifact_mode("node").value
    actions = {
        name: evaluate_applicability(
            feature=ProcessingFeature.COMPILER_ARTIFACTS, policy=policy,
            facts=facts_from_build_unit(value), configuration_sha256="a" * 64).action.value
        for name, value in (("web", web), ("cli", cli), ("docs", script_only))}
    assert actions == {"web": "RUN", "cli": "SKIP", "docs": "SKIP"}
