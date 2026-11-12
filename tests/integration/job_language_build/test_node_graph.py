"""job_language_build (node): the pre-walk whole-graph suite, moved out of the unit path by T-113.

Every case runs the upstream jobs and the language-build job through GraphRunner with fake
executors and image resolvers. They are integration tests pending replacement by the code-level
tests in tests/unit/job_language_build/ and run only when named explicitly
(``scripts/run-tests.sh --allow-heavy -- <file>``).
"""

from __future__ import annotations

import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[3]


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
                # Commands run in source_dir, so no --prefix: `--prefix web` there would name web/web.
                "configure_commands": [], "build_commands": [["npm", "run", "build"]],
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

    def prepare_node_dependencies(self, *, workspace, source_dir, dependency_root=None):
        # The real executor links the image-owned node_modules into the writable source root.
        self.calls.append(("prepare-node-dependencies", source_dir, dependency_root))

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
        dist.chmod(0o555)  # A container-created output tree is not writable by the host UID.
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
        build_plan(infer=_NodeRecipeModel().complete)]).run(target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, ...]] = []
    GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: capturing_fake(profile, _NodeExecutor(calls)),
        image_resolver_factory=lambda unit: _ImageResolver(target))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: capturing_fake(profile, _NodeExecutor(calls)))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    # The probe and the build each exposed the image-owned dependencies before running npm.
    assert calls.count(("prepare-node-dependencies", "web", "web")) == 2
    accepted = load_accepted_language_build(config.runtime.runs_dir / upstream["run_id"])
    [receipt] = accepted["receipts"]
    assert receipt["family"] == "node" and receipt["terminal_status"] == "SUCCEEDED"
    # A successful bundler invocation establishes production, not delivery. The fake
    # supplies no package-membership or delivery facts for these retained candidates.
    expected_gaps = [
        "web/dist/addon.node: delivery status is unknown (delivery_fact_unavailable)",
        "web/dist/bundle.js: delivery status is unknown (delivery_fact_unavailable)",
        "build-execution-capture: EVIDENCE_INCOMPLETE",
        "compiler-artifact-collection: EVIDENCE_INCOMPLETE",
    ]
    assert receipt["gaps"] == expected_gaps
    assert accepted["gaps"] == [
        f"{receipt['build_unit_id']}: {gap}" for gap in expected_gaps
    ]
    assert [(decision["feature"], decision["disposition"], decision["reason_code"])
            for decision in receipt["processing_decisions"]] == [
        ("build-execution-capture", "GAP", "EVIDENCE_INCOMPLETE"),
        ("compiler-artifact-collection", "GAP", "EVIDENCE_INCOMPLETE"),
    ]
    artifacts_by_path = {item["workspace_path"]: item for item in receipt["artifacts"]}
    assert {path: item["scope_role"] for path, item in artifacts_by_path.items()} == {
        "web/dist/addon.node": "unknown",
        "web/dist/bundle.js": "unknown",
        "web/dist/bundle.js.map": "intermediate_evidence",
        "web/package-lock.json": "build_chain",
        "web/package.json": "build_chain",
    }
    for path in ("web/dist/addon.node", "web/dist/bundle.js"):
        artifact = artifacts_by_path[path]
        assert artifact["artifact_origin"] == "build-output"
        assert artifact["delivery_status"] == "unknown"
        assert artifact["analysis_lane"] == "target"
        assert artifact["analysis_reason"] == "delivery-unknown-candidate-review"
    assert receipt["dependency_identity"]["manager"] == "npm"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "generated-code", "source-map", "native-addon"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {
        "package-manager", "bundler"}
    link_database = config.runtime.runs_dir / upstream["run_id"] / receipt["link_database"]["path"]
    workspace = config.runtime.runs_dir / upstream["run_id"] / receipt["workspace"]
    assert link_database.name == "link-commands.json"
    assert workspace not in link_database.parents
    command = receipt["commands"][0]
    # Node language builds run under the same verified execution capture as the probe, which
    # retains complete stdout/stderr files instead of a truncated preview.
    assert command["execution_capture"]["complete"] is True
    assert command["stdout"]["sha256"] and command["stdout"]["truncated"] is False
    protected = config.runtime.runs_dir / upstream["run_id"] / receipt["protected_compile_commands"]["path"]
    protected_text = protected.read_text(encoding="utf-8")
    assert '"webpack"' in protected_text and '"--mode"' in protected_text
    response = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, upstream["run_id"])).call(
        "search", {"query": "source-map", "indexes": ["build"], "limit": 10})
    rendered = json.dumps(response)
    assert "bundle.js.map" in rendered
    assert "diagnostic tail" not in rendered and "protected-commands" not in rendered


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
        executor_factory=lambda unit, profile: capturing_fake(profile, _NodeExecutor(calls)))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    receipts = load_accepted_language_build(config.runtime.runs_dir / upstream["run_id"])["receipts"]
    assert outcome["status"] == "SUCCEEDED", [item.get("gaps") for item in receipts]
    assert ("npm", "ci") in calls
    assert not [call for call in calls if call[0] == "prepare-node-dependencies"]
    assert receipts[0]["terminal_status"] == "SUCCEEDED"
