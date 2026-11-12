"""Focused regressions for live Node build failures (TS2688, EROFS, false artifact gaps)."""

from __future__ import annotations

import json
from pathlib import Path

from appsec_review.applicability import (
    ProcessingFeature, evaluate_applicability, facts_from_build_unit,
)
from appsec_review.config import load_config
from appsec_review.container_runtime.project_images import _restore_command
from appsec_review.jobs.build_discovery import normalize_build_recipe, validate_build_recipe
from appsec_review.jobs.job_project_build.job import _node_recipe_restores_dependencies


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
