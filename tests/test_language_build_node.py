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
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.mcp.adapter import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.storage import file_sha256
from tests.capture_fakes import capturing_fake


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
    assert selected == "npm" and not gaps and _identity["lockfile"] is None
    selected, identity, gaps = node.dependency_identity({
        "image": {"dependency_hashes": {
            "web/package.json": "1" * 64, "web/package-lock.json": "2" * 64,
            "web/npm-shrinkwrap.json": "3" * 64,
        }},
        "recipe": {"configure_commands": [], "build_commands": [["npm", "run", "build"]]},
    })
    assert selected == "npm" and not gaps
    assert identity["lockfile"] == {"path": "web/npm-shrinkwrap.json", "sha256": "3" * 64}


def test_node_restore_recipes_are_lockfile_specific_and_disable_install_scripts() -> None:
    base = {"build_system": "node", "source_dir": "web"}
    assert _restore_command({**base, "dependency_files": ["web/package-lock.json"]})[:2] == ("npm", "ci")
    assert _restore_command({**base, "dependency_files": ["web/pnpm-lock.yaml"]})[:2] == ("pnpm", "install")
    assert _restore_command({**base, "dependency_files": ["web/yarn.lock"]})[:2] == ("yarn", "install")
    assert _restore_command({**base, "dependency_files": ["web/package.json"]})[:2] == ("npm", "install")
    assert all("--ignore-scripts" in _restore_command({**base, "dependency_files": [f"web/{name}"]})
               for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"))


def test_node_recipe_validation_matches_restore_to_lock_and_rejects_application_execution() -> None:
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
    manifest_only = {**recipe, "build_commands": [["npm", "run", "build"]],
                     "dependency_files": ["web/package.json"]}
    assert validate_build_recipe(manifest_only, unit) == []
    invalid_ci = {**manifest_only, "configure_commands": [["npm", "ci"]]}
    assert "Node recipes may use npm ci only when package-lock.json is accepted" in validate_build_recipe(
        invalid_ci, unit)


def test_node_lifecycle_validation_blocks_test_runners_and_target_applications(tmp_path: Path) -> None:
    root = tmp_path / "web"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"scripts": {
        "build": "node index.js", "postbuild": "vitest run",
    }}), encoding="utf-8")
    gaps = node.validate_lifecycle_scripts(tmp_path, "web", [["npm", "run", "build"]])
    assert ("package lifecycle script build may execute a target application: "
            "web/package.json#scripts.build → node index.js") in gaps
    assert ("package lifecycle script postbuild requests a test runner: "
            "web/package.json#scripts.postbuild → vitest run") in gaps


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
    assert gaps and all("delivery status is unknown" in gap for gap in gaps)
    assert {item["kind"] for item in artifacts} >= {
        "generated-code", "source-map", "native-addon", "package"}
    mapping = next(item for item in artifacts if item["kind"] == "source-map")
    assert mapping["source_map"]["sources"] == ["../index.ts"]


def test_npm_pack_json_retains_bounded_integrity_without_raw_stdout(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    package_root = workspace / "web"
    package_root.mkdir(parents=True)
    archive = package_root / "fixture-1.0.0.tgz"
    archive.write_bytes(b"package")
    digest = file_sha256(archive)
    stdout = json.dumps([{
        "filename": archive.name, "integrity": "sha512-fixture", "shasum": "a" * 40,
        "size": archive.stat().st_size, "unpackedSize": 12, "totalFiles": 2,
        "files": [{"path": "index.js", "size": 12}],
    }]).encode()

    rows, gaps = node.invocation_rows(
        workspace, "web", ("npm", "pack", "--json"), success=True, before={},
        after={"web/fixture-1.0.0.tgz": digest}, diagnostic_streams=(stdout,),
    )

    assert not gaps
    assert rows[0]["package_integrity"] == [{
        "workspace_path": "web/fixture-1.0.0.tgz", "sha256": digest,
        "source_dir": "web",
        "integrity": "sha512-fixture", "shasum": "a" * 40,
        "size": 7, "unpackedSize": 12, "totalFiles": 2,
    }]
    assert "files" not in json.dumps(rows[0]["package_integrity"])


def test_node_catalog_retains_unchanged_coverage_with_origin_and_excludes_other_inputs(
        tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    coverage = workspace / "coverage-final.json"
    coverage.write_text('{"type":"llvm.coverage.json.export","data":[]}', encoding="utf-8")
    package = workspace / "package.json"
    package.write_text('{"name":"fixture"}', encoding="utf-8")
    generated = workspace / "dist.js"
    generated.write_text("export {};", encoding="utf-8")
    emitted_coverage = workspace / "reports" / "coverage.xml"
    emitted_coverage.parent.mkdir()
    emitted_coverage.write_text("<coverage/>", encoding="utf-8")
    before = {
        "coverage-final.json": file_sha256(coverage),
        "package.json": file_sha256(package),
    }

    artifacts, gaps = node.catalog(tmp_path, workspace, before, 10, "node-unit")

    assert gaps == ["dist.js: delivery status is unknown (delivery_fact_unavailable)"]
    assert [(row["workspace_path"], row["kind"], row["artifact_origin"])
            for row in artifacts] == [
        ("coverage-final.json", "test-coverage", "accepted-input"),
        ("dist.js", "generated-code", "build-output"),
        ("package.json", "package-metadata", "accepted-input"),
        ("reports/coverage.xml", "test-coverage", "build-output"),
    ]


def test_node_catalog_retains_imported_profile_data(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    profile = workspace / "cpu.folded"
    profile.write_text("root;handler 12\n", encoding="utf-8")
    package = workspace / "package.json"
    package.write_text('{"name":"fixture"}', encoding="utf-8")
    before = {"cpu.folded": file_sha256(profile), "package.json": file_sha256(package)}

    artifacts, gaps = node.catalog(tmp_path, workspace, before, 10, "node-unit")

    assert not gaps
    assert [(row["workspace_path"], row["kind"], row["artifact_origin"])
            for row in artifacts] == [
        ("cpu.folded", "execution-profile", "accepted-input"),
        ("package.json", "package-metadata", "accepted-input"),
    ]


def test_node_metadata_only_success_has_bounded_review_artifacts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    manifest = workspace / "package.json"
    manifest.write_text('{"name":"fixture","dependencies":{"left-pad":"1.3.0"}}', encoding="utf-8")
    lock = workspace / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/left-pad": {"version": "1.3.0", "integrity": "sha512-fixture"},
    }}), encoding="utf-8")
    pnp = workspace / ".pnp.cjs"
    pnp.write_text("module.exports = {dependencyTreeRoots: []};", encoding="utf-8")
    before = {path.name: file_sha256(path) for path in (manifest, lock, pnp)}

    artifacts, gaps = node.catalog(tmp_path, workspace, before, 10, "node-unit")

    assert not gaps
    assert [(row["workspace_path"], row["kind"], row["artifact_origin"])
            for row in artifacts] == [
        (".pnp.cjs", "resolved-dependency-metadata", "accepted-input"),
        ("package-lock.json", "resolved-dependency-metadata", "accepted-input"),
        ("package.json", "package-metadata", "accepted-input"),
    ]
    assert artifacts[1]["dependency_metadata"] == {
        "format": "package-lock.json", "manager": "npm", "role": "resolved-dependency-graph",
    }


def test_node_catalog_retains_ambiguous_runtime_outputs_with_named_gaps(
        tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    retained = {
        "dist/app.cjs": b"module.exports = 1;",
        "dist/app.cjs.map": json.dumps({"version": 3, "file": "app.cjs", "sources": []}).encode(),
        "dist/index.d.ts": b"export declare const value: number;",
        "build/Release/addon.node": b"native-addon",
        "build/Release/addon.pdb": b"symbols",
        "pkg/example-1.0.0.tgz": b"package",
        "pkg/example-1.0.0.tgz.sha512": b"sha512-fixture",
        "node_modules/dependency/index.js": b"dependency",
        ".yarn/cache/dependency.zip": b"cache",
        ".cache/generated.js": b"cache",
        "build/Release/helper.dll": b"runtime-library-candidate",
    }
    excluded = {
        "build/obj/addon.o": b"object",
        "build/Release/orphan.pdb": b"unbound-symbols",
        "unrelated.sha512": b"not-package-integrity",
        "notes.log": b"transient",
    }
    for relative, content in {**retained, **excluded}.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    artifacts, gaps = node.catalog(tmp_path, workspace, {}, 100, "node-unit")

    assert gaps and all("delivery status is unknown" in gap for gap in gaps)
    by_path = {row["workspace_path"]: row for row in artifacts}
    assert set(by_path) == set(retained)
    assert by_path["build/Release/helper.dll"]["scope_role"] == "unknown"
    assert any("build/Release/helper.dll: delivery status is unknown" in gap for gap in gaps)
    assert by_path["build/Release/addon.pdb"]["kind"] == "native-symbols"
    assert by_path["pkg/example-1.0.0.tgz.sha512"]["package_archive"] == {
        "workspace_path": "pkg/example-1.0.0.tgz",
        "sha256": by_path["pkg/example-1.0.0.tgz"]["sha256"],
    }


def test_node_catalog_reports_source_map_size_and_count_bounds(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    oversized = workspace / "00-oversized.js.map"
    oversized.write_bytes(b"x" * 17)
    for index in range(2):
        (workspace / f"bundle-{index}.js").write_text("export {};", encoding="utf-8")
    monkeypatch.setattr(node, "_MAX_SOURCE_MAP_BYTES", 16)

    artifacts, gaps = node.catalog(tmp_path, workspace, {}, 1, "node-unit")

    assert len(artifacts) == 1
    assert any("truncated at configured count bound" in gap for gap in gaps)
    assert any("source-map exceeds 16 byte retention bound" in gap for gap in gaps)


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
