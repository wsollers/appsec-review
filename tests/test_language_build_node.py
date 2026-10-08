from __future__ import annotations

import json
from pathlib import Path
import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import (
    _restore_command, dependency_hashes, project_recipe_identity,
)
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build import node
from appsec_review.jobs.job_language_build.job import FrameworkIntegrityError, _validate_checkpoint_artifacts
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256


ROOT = Path(__file__).parents[1]


def _dispatch(lockfile: str = "package-lock.json", manager: str = "npm") -> dict:
    dependencies = {
        "web/package.json": "1" * 64,
        f"web/{lockfile}": "2" * 64,
    }
    return {
        "image": {"dependency_hashes": dependencies},
        "recipe": {
            "configure_commands": [],
            "build_commands": [[manager, "run", "build"]],
        },
    }


def test_node_dependency_identity_binds_npm_pnpm_and_yarn_lockfiles() -> None:
    for lockfile, manager in (("package-lock.json", "npm"), ("pnpm-lock.yaml", "pnpm"),
                              ("yarn.lock", "yarn")):
        selected, identity, gaps = node.dependency_identity(_dispatch(lockfile, manager))
        assert selected == manager and not gaps
        assert identity["lockfile"]["path"] == f"web/{lockfile}"
        assert len(identity["sha256"]) == 64
    selected, _identity, gaps = node.dependency_identity({
        "image": {"dependency_hashes": {"web/package.json": "1" * 64}},
        "recipe": {"configure_commands": [], "build_commands": [["npm", "run", "build"]]},
    })
    assert selected is None and gaps == ["Node build is not lockfile-bound: no supported lockfile"]


def test_node_restore_recipes_are_lockfile_specific_and_disable_install_scripts() -> None:
    base = {"build_system": "node", "source_dir": "web"}
    assert _restore_command({**base, "dependency_files": ["web/package-lock.json"]})[:2] == ("npm", "ci")
    assert _restore_command({**base, "dependency_files": ["web/pnpm-lock.yaml"]})[:2] == ("pnpm", "install")
    assert _restore_command({**base, "dependency_files": ["web/yarn.lock"]})[:2] == ("yarn", "install")
    assert all("--ignore-scripts" in _restore_command({**base, "dependency_files": [f"web/{name}"]})
               for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"))


def test_node_recipe_validation_requires_lock_and_rejects_application_execution() -> None:
    unit = {"build_unit_id": "unit", "family": "node", "root": "web", "build_system": "node",
            "markers": [{"path": "web/package.json"}],
            "descriptor_package": {"documents": [{"path": "web/package.json"},
                                                   {"path": "web/package-lock.json"}]}}
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": "unit",
              "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
              "system_packages": [], "environment": {},
              "dependency_files": ["web/package.json", "web/package-lock.json"],
              "configure_commands": [], "build_commands": [["node", "web/index.js"]],
              "expected_outputs": ["web/dist"], "network_required": True, "reason": "fixture"}
    assert "build_commands[0] may execute a target application" in validate_build_recipe(recipe, unit)
    missing = {**recipe, "build_commands": [["npm", "run", "build"]],
               "dependency_files": ["web/package.json"]}
    assert "Node recipes require package.json and exactly one supported lockfile" in validate_build_recipe(missing, unit)


def test_node_lifecycle_validation_blocks_test_runners_and_target_applications(tmp_path: Path) -> None:
    root = tmp_path / "web"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"scripts": {
        "build": "node index.js", "postbuild": "vitest run",
    }}), encoding="utf-8")
    gaps = node.validate_lifecycle_scripts(tmp_path, "web", [["npm", "run", "build"]])
    assert "package lifecycle script build may execute a target application" in gaps
    assert "package lifecycle script postbuild requests a test runner" in gaps


def test_checkpoint_workspace_manifest_tampering_is_framework_integrity_failure(tmp_path: Path) -> None:
    workspace = tmp_path / "data" / "build" / "node" / "units" / "unit" / "workspace"
    workspace.mkdir(parents=True)
    output = workspace / "dist.js"
    output.write_text("original\n", encoding="utf-8")
    manifest = workspace.parent / "workspace-manifest.json"
    manifest.write_text(json.dumps({"schema": "appsec-review/build-workspace-manifest/1",
                                    "build_unit_id": "unit",
                                    "files": {"dist.js": file_sha256(output)}}), encoding="utf-8")
    receipt = {"workspace": workspace.relative_to(tmp_path).as_posix(), "artifacts": [], "commands": [],
               "workspace_manifest": {"path": manifest.relative_to(tmp_path).as_posix(),
                                      "sha256": file_sha256(manifest)}}
    _validate_checkpoint_artifacts(tmp_path, receipt)
    output.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(FrameworkIntegrityError, match="workspace identity changed"):
        _validate_checkpoint_artifacts(tmp_path, receipt)


def test_node_catalog_and_package_script_provenance_include_maps_packages_and_native_addons(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "web"
    dist = root / "dist"
    dist.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"scripts": {"build": "webpack --mode production"}}),
                                            encoding="utf-8")
    (root / "webpack.config.js").write_text("module.exports = {};\n", encoding="utf-8")
    (root / "index.ts").write_text("export const value = 1;\n", encoding="utf-8")
    bundle = dist / "bundle.js"
    bundle.write_text("const value=1;\n", encoding="utf-8")
    source_map = dist / "bundle.js.map"
    source_map.write_text(json.dumps({"version": 3, "file": "bundle.js", "sources": ["../index.ts"]}),
                          encoding="utf-8")
    addon = dist / "addon.node"
    addon.write_bytes(b"native")
    package = root / "sample-1.0.0.tgz"
    package.write_bytes(b"package")
    after = {path.relative_to(workspace).as_posix(): file_sha256(path)
             for path in workspace.rglob("*") if path.is_file()}
    rows, gaps = node.invocation_rows(workspace, "web", ("npm", "run", "build"), success=True,
                                      before={}, after=after)
    assert not gaps and [row["tool"] for row in rows] == ["npm", "webpack"]
    artifacts, gaps = node.catalog(tmp_path, workspace, {}, 100, "build-unit-fixture")
    assert not gaps
    assert {item["kind"] for item in artifacts} >= {
        "generated-code", "source-map", "native-addon", "package"}
    mapping = next(item for item in artifacts if item["kind"] == "source-map")
    assert mapping["source_map"]["sources"] == ["../index.ts"]


class _NodeRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "node", "source_dir": root, "build_dir": f"{root}/dist",
                "system_packages": [], "environment": {},
                "dependency_files": [f"{root}/package.json", f"{root}/package-lock.json"],
                "configure_commands": [], "build_commands": [["npm", "--prefix", root, "run", "build"]],
                "expected_outputs": [f"{root}/dist"], "network_required": True,
                "reason": "lockfile-bound Node fixture",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class _ImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        image_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-node:local", image_id, "f" * 64, True, False, hashes), b"", b""


class _NodeExecutor:
    def __init__(self, calls: list[tuple[str, ...]]):
        self.calls = calls

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        root = workspace / working_directory
        dist = root / "dist"
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "bundle.js").write_text("const value=1;\n", encoding="utf-8")
        (dist / "bundle.js.map").write_text(json.dumps({
            "version": 3, "file": "bundle.js", "sources": ["../src/index.ts"],
        }), encoding="utf-8")
        (dist / "addon.node").write_bytes(b"native-addon")
        stdout = b"webpack --mode production\n"
        return BuildCommandResult(tuple(argv), 0, stdout, b"warning\n", False,
                                  stdout_bytes=1000, stderr_bytes=8,
                                  stdout_truncated=True, stdout_tail=b"diagnostic tail\n")


def test_node_build_publishes_protected_provenance_and_sanitized_mcp_evidence(tmp_path: Path) -> None:
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
        build_plan(model_client=_NodeRecipeModel())]).run(target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, ...]] = []
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: _NodeExecutor(calls),
        image_resolver_factory=lambda unit: _ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: _NodeExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
    receipt = load_accepted_language_build(config.runtime.runs_dir / upstream["run_id"])["receipts"][0]
    assert receipt["family"] == "node" and receipt["terminal_status"] == "SUCCEEDED"
    assert receipt["dependency_identity"]["manager"] == "npm"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "generated-code", "source-map", "native-addon"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {
        "package-manager", "bundler"}
    command = receipt["commands"][0]
    assert command["stdout"]["total_bytes"] == 1000 and command["stdout"]["truncated"] is True
    assert command["stdout"]["diagnostic_tail"]["sha256"]
    protected = config.runtime.runs_dir / upstream["run_id"] / receipt["protected_compile_commands"]["path"]
    protected_text = protected.read_text(encoding="utf-8")
    assert '"webpack"' in protected_text and '"--mode"' in protected_text
    response = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, upstream["run_id"])).call(
        "search", {"query": "source-map", "indexes": ["build"], "limit": 10})
    rendered = json.dumps(response)
    assert "bundle.js.map" in rendered
    assert "diagnostic tail" not in rendered and "protected-commands" not in rendered
