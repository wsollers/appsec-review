"""npm, pnpm and Yarn workspace dependency inventory: discovery, applicability, recipes, images."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from appsec_review.applicability import (
    ApplicabilityAction, ProcessingFeature, ReasonCode, evaluate_applicability, facts_from_build_unit,
)
from appsec_review.config import load_config
from appsec_review.container_runtime import BuildProfile, ProjectImageResolver, project_recipe_identity
from appsec_review.container_runtime.build_executor import BuildCommandResult, BuildContainerExecutor
from appsec_review.container_runtime.project_images import _restore_command, node_dependency_root
from appsec_review.jobs.build_discovery import (
    BUILD_RECIPE_SCHEMA, copied_source_symlink, descriptor_package, discover_build_units,
    normalize_build_recipe, validate_build_recipe,
)
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from tests.capture_fakes import capturing_fake
from tests.test_language_build_node import _ImageResolver, _NodeExecutor


ROOT = Path(__file__).parents[1]
CONFIGURATION = "a" * 64
# Larger than the 64 KiB descriptor content bound, as real workspace lockfiles are.
LARGE_LOCK = "# " + "x" * (80 * 1024) + "\n"
PROFILE = BuildProfile("node", "node-base:local", "sha256:" + "a" * 64, "10001:10001")


def _write(target: Path, values: dict[str, str]) -> list[dict[str, object]]:
    files = []
    for relative, content in sorted(values.items()):
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        data = content.encode()
        files.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(),
                      "size_bytes": len(data)})
    return files


def _members() -> dict[str, str]:
    return {
        "packages/api/package.json": json.dumps({
            "name": "@mono/api", "scripts": {"build": "tsc"},
            "dependencies": {"@mono/shared": "*"}, "devDependencies": {"typescript": "5.7.3"}}),
        "packages/api/tsconfig.json": "{}",
        "packages/shared/package.json": json.dumps({"name": "@mono/shared", "scripts": {"build": "tsc"}}),
        "apps/web/package.json": json.dumps({
            "name": "@mono/web", "scripts": {"build": "vite build"},
            "devDependencies": {"vite": "5.4.11"}}),
        "tools/standalone/package.json": json.dumps({"name": "standalone"}),
    }


def _monorepo(manager: str, *, lockfile: bool = True) -> dict[str, str]:
    """A synthetic workspace: packages/* and apps/web are members, tools/standalone is not."""
    root: dict[str, object] = {"name": "mono", "private": True,
                               "devDependencies": {"typescript": "5.7.3"}}
    values = _members()
    if manager == "pnpm":
        values["pnpm-workspace.yaml"] = "packages:\n  - 'packages/*'\n  - apps/web  # the SPA\n"
    elif manager == "yarn":
        root["workspaces"] = {"packages": ["packages/*", "apps/web"]}
    else:
        root["workspaces"] = ["packages/*", "./apps/web"]
    values["package.json"] = json.dumps(root)
    if lockfile:
        values[{"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}[manager]] = LARGE_LOCK
    return values


def _units(target: Path, files: list[dict[str, object]]) -> dict[str, dict]:
    return {str(unit["root"]): {**unit, "descriptor_package": descriptor_package(target, unit, files)}
            for unit in discover_build_units(files) if unit["family"] == "node"}


def _decision(unit: dict):
    return evaluate_applicability(feature=ProcessingFeature.BUILD_CAPTURE, policy="required",
                                  facts=facts_from_build_unit(unit), configuration_sha256=CONFIGURATION)


def _recipe(unit: dict, manager: str) -> dict:
    root = str(unit["root"])
    return {"schema": BUILD_RECIPE_SCHEMA, "build_unit_id": unit["build_unit_id"],
            "image_profile": "node", "source_dir": root, "build_dir": root,
            "system_packages": [], "environment": {},
            "dependency_files": [("" if root == "." else root + "/") + "package.json"],
            "configure_commands": [], "build_commands": [[manager, "run", "build"]],
            "expected_outputs": [], "network_required": False, "reason": "synthetic workspace"}


@pytest.mark.parametrize(("manager", "lockfile", "restore"), (
    ("npm", "package-lock.json", ("npm", "--prefix", "/opt/project", "ci")),
    ("pnpm", "pnpm-lock.yaml", ("pnpm", "--dir", "/opt/project", "install", "--frozen-lockfile")),
    ("yarn", "yarn.lock", ("yarn", "--cwd", "/opt/project", "install", "--frozen-lockfile")),
))
def test_workspace_root_and_members_share_one_complete_inventory(
        tmp_path: Path, manager: str, lockfile: str, restore: tuple[str, ...]) -> None:
    target = tmp_path / "target"
    files = _write(target, _monorepo(manager))
    units = _units(target, files)
    members = ["apps/web", "packages/api", "packages/shared"]
    member_manifests = {f"{member}/package.json" for member in members}
    declaration = "pnpm-workspace.yaml" if manager == "pnpm" else "package.json"

    for root in (".", *members):
        package = units[root]["descriptor_package"]
        assert package["gaps"] == [], (root, package["gaps"])
        assert package["workspace"] == {
            "root": ".", "role": "root" if root == "." else "member", "manager": manager,
            "declaration": declaration, "lockfile": lockfile, "members": members}
        # The oversized lockfile is identity-only inventory, not a byte-bound gap.
        inventory = {item["path"] for item in package["inventory"]}
        assert {lockfile, "package.json", *member_manifests} <= inventory
        assert lockfile not in {item["path"] for item in package["documents"]}
        facts = facts_from_build_unit(units[root])
        assert facts.inventory_complete is True
        assert lockfile in {item.path for item in facts.sources}
        decision = _decision(units[root])
        assert decision.action is ApplicabilityAction.RUN, decision.reason_code

        recipe = normalize_build_recipe(_recipe(units[root], manager), units[root])
        assert validate_build_recipe(recipe, units[root]) == []
        assert recipe["network_required"] is True
        assert {lockfile, "package.json", *member_manifests} <= set(recipe["dependency_files"])
        if manager == "pnpm":
            assert "pnpm-workspace.yaml" in recipe["dependency_files"]
        assert node_dependency_root(recipe) == "."
        command = _restore_command({**recipe, "build_system": "node"})
        if root == ".":
            assert command[0] == manager and "/opt/project" not in command
        else:
            assert command[:len(restore)] == restore

    # A nested project the workspace does not claim keeps its own, standalone inventory.
    standalone = units["tools/standalone"]["descriptor_package"]
    assert "workspace" not in standalone
    assert standalone["gaps"] == []


@pytest.mark.parametrize("manager", ("npm", "pnpm", "yarn"))
def test_workspace_without_a_root_lockfile_stays_an_inventory_gap(tmp_path: Path, manager: str) -> None:
    target = tmp_path / "target"
    files = _write(target, _monorepo(manager, lockfile=False))
    units = _units(target, files)
    for root in (".", "apps/web", "packages/api", "packages/shared"):
        package = units[root]["descriptor_package"]
        assert any("workspace dependency inventory unavailable" in gap for gap in package["gaps"]), (
            root, package["gaps"])
        assert facts_from_build_unit(units[root]).inventory_complete is False
        decision = _decision(units[root])
        assert decision.action is ApplicabilityAction.GAP
        assert decision.reason_code is ReasonCode.INVENTORY_UNAVAILABLE
    # The standalone project was never part of the workspace and has nothing missing.
    assert units["tools/standalone"]["descriptor_package"]["gaps"] == []


def test_member_lockfile_never_comes_from_beyond_the_workspace_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    values = {f"repo/{path}": content for path, content in _monorepo("npm", lockfile=False).items()}
    values["package.json"] = json.dumps({"name": "outer"})
    values["package-lock.json"] = '{"lockfileVersion":3}'
    files = _write(target, values)
    units = _units(target, files)
    package = units["repo/packages/api"]["descriptor_package"]
    assert package["workspace"]["root"] == "repo"
    assert "package-lock.json" not in {item["path"] for item in package["documents"]}
    assert any("workspace dependency inventory unavailable" in gap for gap in package["gaps"])


def test_ambiguous_or_symlinked_workspace_inventory_is_a_gap(tmp_path: Path) -> None:
    target = tmp_path / "target"
    values = _monorepo("npm")
    values["yarn.lock"] = "# yarn\n"
    files = _write(target, values)
    package = _units(target, files)["."]["descriptor_package"]
    assert any("workspace dependency inventory is ambiguous" in gap for gap in package["gaps"])

    linked = tmp_path / "linked"
    files = _write(linked, _monorepo("npm"))
    outside = tmp_path / "outside" / "extra"
    outside.mkdir(parents=True)
    (outside / "package.json").write_text("{}", encoding="utf-8")
    os.symlink(outside, linked / "packages" / "extra", target_is_directory=True)
    # The catalog excludes symlinks, so the linked member's manifest is not an accepted file.
    package = _units(linked, files)["."]["descriptor_package"]
    assert "packages/extra: workspace member is a symlink; its manifest is outside the accepted " \
           "inventory" in package["gaps"]
    assert _decision({**discover_build_units(files)[0], "descriptor_package": package}
                     ).reason_code is ReasonCode.INVENTORY_UNAVAILABLE


def test_oversized_standalone_lockfile_is_identity_inventory_but_other_descriptors_stay_gaps(
        tmp_path: Path) -> None:
    target = tmp_path / "target"
    files = _write(target, {"web/package.json": '{"scripts":{"build":"tsc"}}',
                            "web/package-lock.json": LARGE_LOCK})
    unit = _units(target, files)["web"]
    assert unit["descriptor_package"]["gaps"] == []
    assert [item["path"] for item in unit["descriptor_package"]["inventory"]] == ["web/package-lock.json"]
    recipe = {**_recipe(unit, "npm"), "dependency_files": ["web/package.json", "web/package-lock.json"],
              "configure_commands": [["npm", "ci"]], "network_required": True}
    assert validate_build_recipe(normalize_build_recipe(recipe, unit), unit) == []

    files = _write(target, {"web/package.json": '{"scripts":{"build":"tsc"}}',
                            "web/tsconfig.json": "// " + "x" * (80 * 1024)})
    unit = _units(target, files)["web"]
    assert unit["descriptor_package"]["gaps"] == ["web/tsconfig.json: descriptor content omitted by byte bound"]
    assert _decision(unit).reason_code is ReasonCode.INVENTORY_UNAVAILABLE


def test_installed_workspace_links_are_not_build_source_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "packages" / "api").mkdir(parents=True)
    (source / "node_modules" / "@mono").mkdir(parents=True)
    os.symlink("../../packages/api", source / "node_modules" / "@mono" / "api")
    (source / "packages" / "api" / "node_modules").mkdir()
    os.symlink("../../../node_modules/typescript", source / "packages" / "api" / "node_modules" / "ts")
    ignored = frozenset({"node_modules", ".git"})
    assert copied_source_symlink(source, ignored) is None
    os.symlink("api", source / "packages" / "alias")
    assert copied_source_symlink(source, ignored) == source / "packages" / "alias"


def test_workspace_image_lays_out_member_modules_and_relinks_workspace_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    files = _write(target, _monorepo("pnpm"))
    units = _units(target, files)
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=target)
    member = {**normalize_build_recipe(_recipe(units["apps/web"], "pnpm"), units["apps/web"]),
              "build_system": "node"}
    _identity, dockerfile = resolver.definition(member, PROFILE)
    last = dockerfile.decode().splitlines()[-1]
    assert last.startswith('RUN ["node","-e",')
    assert last.endswith('"/opt/project","/workspace","apps/web"]')

    # A standalone project's image (and so its cached identity) is unchanged.
    standalone = {**_recipe(units["tools/standalone"], "npm"), "build_system": "node",
                  "network_required": True}
    _identity, dockerfile = resolver.definition(standalone, PROFILE)
    assert '"node","-e"' not in dockerfile.decode()
    hashes = {"tools/standalone/package.json": "0" * 64}
    assert project_recipe_identity(standalone, PROFILE, hashes) == project_recipe_identity(
        {**standalone, "reason": "other"}, PROFILE, hashes)


def test_workspace_member_build_links_root_and_member_dependency_trees(tmp_path: Path) -> None:
    calls: list[tuple[tuple[str, ...], str]] = []

    class Executor(BuildContainerExecutor):
        def execute(self, argv, *, workspace, working_directory, environment):
            calls.append((tuple(argv), working_directory))
            return BuildCommandResult(tuple(argv), 0, b"", b"", False)

    executor = Executor(PROFILE, timeout_seconds=30, output_bytes=1024)
    executor.prepare_node_dependencies(workspace=tmp_path, source_dir="apps/web", dependency_root=".")
    assert calls == [
        (("ln", "-s", "/opt/project/node_modules", "node_modules"), "."),
        (("ln", "-s", "/opt/project/apps/web/node_modules", "node_modules"), "apps/web"),
    ]
    calls.clear()
    executor.prepare_node_dependencies(workspace=tmp_path, source_dir="web")
    assert calls == [(("ln", "-s", "/opt/project/web/node_modules", "node_modules"), "web")]


NORTHWINDS = ROOT / "targets" / "appsec-multi-vuln" / "projects" / "northwinds-v1"


class _WorkspaceNodeExecutor(_NodeExecutor):
    """The shared fake Node executor, also producing the Vite entry document a SPA emits."""

    def execute(self, argv, *, workspace, working_directory, environment):
        result = super().execute(argv, workspace=workspace, working_directory=working_directory,
                                 environment=environment)
        dist = workspace / working_directory / "dist"
        dist.chmod(0o755)
        (dist / "index.html").write_text("<!doctype html>\n", encoding="utf-8")
        dist.chmod(0o555)
        return result


@pytest.mark.requires_target("appsec-multi-vuln")
def test_northwinds_workspace_units_reach_dispatch_in_the_planning_path(tmp_path: Path) -> None:
    from tests.integration.test_node_project_builds import CASES, _RecipeProvider

    case = next(item for item in CASES if item.project == "northwinds-v1")
    config_path = tmp_path / "appsec-review.toml"
    shutil.copyfile(ROOT / "appsec-review.toml", config_path)
    target = tmp_path / "target" / "northwinds-v1"
    shutil.copytree(NORTHWINDS, target, ignore=shutil.ignore_patterns("node_modules", ".git"))
    config = load_config(config_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=_RecipeProvider(target, case).complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / upstream["run_id"]
    plan = json.loads(next(run_root.glob(
        "data/jobs/job_target_analysis_plan/attempts/*/artifacts/analysis-plan/"
        "accepted-analysis-plan.json")).read_text(encoding="utf-8"))
    assert plan["model"]["status"] == "ACCEPTED", plan.get("contradictions")

    calls: list[tuple[str, ...]] = []
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: capturing_fake(profile, _WorkspaceNodeExecutor(calls)),
        image_resolver_factory=lambda unit: _ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    loaded = json.loads(next(run_root.glob(
        "data/jobs/job_project_build/attempts/*/steps/plan/tasks/load_recipes/result.json")
        ).read_text(encoding="utf-8"))
    assert loaded["gaps"] == [] and loaded["action_count"] == 3
    roots = {str(action["root"]): action for action in loaded["actions"]}
    assert set(roots) == {".", "backend", "frontend"}
    for action in roots.values():
        dependencies = set(action["recipe"]["dependency_files"])
        assert {"package.json", "package-lock.json", "backend/package.json",
                "frontend/package.json"} <= dependencies
    accepted = load_accepted_builds(run_root)
    probes = {str(item.get("root")) for item in accepted.get("probe_receipts", ())
              if item.get("family") == "node"}
    assert probes == {".", "backend", "frontend"}

    GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: capturing_fake(profile, _WorkspaceNodeExecutor(calls)))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    receipts = {str(item["root"]): item for item in load_accepted_language_build(run_root)["receipts"]
                if item.get("family") == "node"}
    for unit in case.units:
        receipt = receipts[unit.root]
        if unit.language_gap is not None:
            assert receipt["terminal_status"] == unit.language_status == "BLOCKED"
            assert any(unit.language_gap in gap for gap in receipt["gaps"]), receipt["gaps"]
        else:
            assert receipt["terminal_status"] != "BLOCKED", receipt["gaps"]
    # The member build sees the workspace root's tree and its own.
    assert ("prepare-node-dependencies", "frontend", ".") in calls
