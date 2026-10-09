from __future__ import annotations

import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import php
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]


class ComposerRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "php", "source_dir": root, "build_dir": f"{root}/build",
                "system_packages": [], "environment": {},
                "dependency_files": [f"{root}/composer.json", f"{root}/composer.lock"],
                "configure_commands": [["composer", "dump-autoload", "--classmap-authoritative"]],
                "build_commands": [["composer", "archive", "--format=zip", "--dir=build"]],
                "expected_outputs": [f"{root}/vendor/autoload.php", f"{root}/build"],
                "network_required": True, "reason": "lockfile-bound Composer fixture",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-php:local", "sha256:" + "d" * 64, "f" * 64,
            True, False, hashes), b"image", b""


class ComposerExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail_roots: set[str] | None = None,
                 truncate: bool = False):
        self.calls, self.fail_roots, self.truncate = calls, fail_roots or set(), truncate

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        failed = working_directory in self.fail_roots and "archive" in argv
        root = workspace / working_directory
        if "dump-autoload" in argv and not failed:
            generated = root / "vendor" / "composer"
            generated.mkdir(parents=True, exist_ok=True)
            (root / "vendor" / "autoload.php").write_text("<?php return true;\n", encoding="utf-8")
            (generated / "autoload_classmap.php").write_text("<?php return [];\n", encoding="utf-8")
            (generated / "installed.json").write_text("[]", encoding="utf-8")
            codegen = root / "generated"
            codegen.mkdir(exist_ok=True)
            (codegen / "Proxy.php").write_text("<?php final class Proxy {}\n", encoding="utf-8")
        if "archive" in argv and not failed:
            build = root / "build"
            build.mkdir(parents=True, exist_ok=True)
            (build / "fixture.zip").write_bytes(b"PK\x03\x04fixture")
            (build / "fixture.so").write_bytes(b"\x7fELFphp-extension")
        payload = b"x" * 32 if self.truncate else b"composer ok"
        return BuildCommandResult(tuple(argv), 2 if failed else 0, payload[:8] if self.truncate else payload,
            b"archive failed" if failed else b"", False, stdout_bytes=len(payload),
            stdout_truncated=self.truncate, stdout_tail=payload[-8:] if self.truncate else b"")


def _fixture(tmp_path: Path, roots=("php",)):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target"
    for root in roots:
        project = target / root
        project.mkdir(parents=True)
        (project / "composer.json").write_text(json.dumps({
            "name": f"fixture/{root}", "require": {"vendor/runtime": "^1.0"},
            "scripts": {"post-autoload-dump": ["php bin/generate.php"]},
        }), encoding="utf-8")
        (project / "composer.lock").write_text(json.dumps({
            "content-hash": root, "packages": [{"name": "vendor/runtime", "version": "1.2.3",
                "require": {"vendor/base": "^2.0"}}], "packages-dev": [],
        }), encoding="utf-8")
        (project / "App.php").write_text("<?php final class App {}\n", encoding="utf-8")
    return load_config(config_path), target


def _accepted(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(model_client=ComposerRecipeModel())]).run(
            target_root=target, source_fingerprint=fingerprint)
    GraphRunner(config, [build_projects(executor_factory=lambda unit, profile: ComposerExecutor(calls),
        image_resolver_factory=lambda unit: ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_php_composer_executor_catalogs_lock_packages_autoload_archives_and_protected_streams(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted(config, target, calls)
    outcome = GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        ComposerExecutor(calls, truncate=True))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    receipt = next(item for item in load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
                   if item["family"] == "php")
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "package-metadata", "generated-autoload", "generated-source",
        "distributable-archive", "native-extension"}
    assert receipt["composer"]["packages"][0]["name"] == "vendor/runtime"
    assert receipt["package_relationships"]
    assert receipt["composer_policy"]["network"] == "allowed"
    assert all("argv" not in command for command in receipt["commands"])
    assert receipt["commands"][0]["stdout"]["truncated"] is True
    assert receipt["commands"][0]["stdout"]["total_bytes"] == 32
    assert receipt["commands"][0]["stdout"]["diagnostic_tail"]
    assert "--no-plugins" in calls[-2]
    mcp = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id))
    response = mcp.call("search", {"query": "distributable-archive", "indexes": ["build"], "limit": 10})
    rendered = json.dumps(response)
    assert "fixture.zip" in rendered
    assert "protected-commands" not in rendered and "--no-plugins" not in rendered
    assert "composer ok" not in rendered and "xxxxxxxx" not in rendered


def test_php_sibling_failure_isolated_checkpoint_reuse_and_dag_family_lane(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, ("good", "bad"))
    run_id, fingerprint = _accepted(config, target, [])
    first = GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        ComposerExecutor([], fail_roots={"bad"}))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert first["status"] == "COMPLETED_WITH_GAPS"
    receipts = [item for item in load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
                if item["family"] == "php"]
    assert {item["root"]: item["terminal_status"] for item in receipts} == {
        "bad": "FAILED", "good": "SUCCEEDED"}
    calls: list[tuple[str, ...]] = []
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: ComposerExecutor(calls))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id, force_from="job_language_build")
    resumed = {item["root"]: item for item in
        load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"] if item["family"] == "php"}
    assert resumed["good"]["checkpoint_reused"] is True
    assert resumed["bad"]["checkpoint_reused"] is False
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: ComposerExecutor([])),), config)
    assert graph.node("job_language_build.execute.php").dependencies == ("job_language_build.load.php",)


def test_php_policy_allows_manifest_only_dependency_resolution(tmp_path: Path) -> None:
    assert php.policy_argv(("composer", "archive"), {
        "composer_plugins": "disabled", "composer_scripts": "disabled"})[-3:] == (
            "--no-plugins", "--no-scripts", "--no-interaction")
    dispatch = {"build_system": "composer", "recipe": {
        "dependency_files": ["composer.json"], "network_required": True}}
    assert php.validate_php_dispatch(dispatch) == []
