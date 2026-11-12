from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.applicability import (
    ProcessingFeature, evaluate_applicability, facts_from_build_unit,
)
from appsec_review.config import load_config
from appsec_review.container_runtime.project_images import _restore_command
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import node
from appsec_review.jobs.job_language_build.job import (
    FrameworkIntegrityError, _has_build_output, _validate_checkpoint_artifacts,
)
from appsec_review.storage import file_sha256
from tests.accepted_topology_fixture import accept_isolated_dispatch


ROOT = Path(__file__).parents[3]


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



def _node_unit(root: str, manifest: dict) -> dict:
    return {"build_unit_id": "unit", "family": "node", "root": root, "build_system": "node",
            "markers": [{"path": f"{root}/package.json"}],
            "descriptor_package": {"gaps": [], "documents": [{
                "path": f"{root}/package.json", "sha256": "1" * 64,
                "content": json.dumps(manifest)}]}}




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
    target = tmp_path / "target"
    (target / "web").mkdir(parents=True)
    (target / "web" / "package.json").write_text('{"scripts": {"build": "tsc"}}\n', encoding="utf-8")
    dispatch = {"build_unit_id": "unit", "root": "web", "family": "node", "build_system": "node",
                "source_fingerprint": source_fingerprint(target),
                "recipe": {"schema": "appsec-review/build-recipe/1", "build_unit_id": "unit",
                           "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
                           "system_packages": [], "environment": {}, "dependency_files": ["web/package.json"],
                           "configure_commands": [], "build_commands": [["npm", "run", "build"]],
                           "expected_outputs": ["web/dist"], "network_required": True,
                           "reason": "checkpoint manifest fixture"}}
    run_root, dispatch = accept_isolated_dispatch(
        tmp_path / "accepted-plan", target, dispatch, ["web/package.json"], releases={})
    workspace = run_root / "data" / "build" / "node" / "units" / "unit" / "workspace"
    workspace.mkdir(parents=True)
    output = workspace / "dist.js"
    output.write_text("original\n", encoding="utf-8")
    manifest = workspace.parent / "workspace-manifest.json"
    manifest.write_text(json.dumps({"schema": "appsec-review/build-workspace-manifest/1",
                                    "build_unit_id": "unit",
                                    "files": {"dist.js": file_sha256(output)}}), encoding="utf-8")
    receipt = {key: dispatch[key] for key in ("build_unit_id", "recipe", "topology_refinement")}
    receipt.update({"workspace": workspace.relative_to(run_root).as_posix(), "artifacts": [], "commands": [],
                    "workspace_manifest": {"path": manifest.relative_to(run_root).as_posix(),
                                           "sha256": file_sha256(manifest)}})
    _validate_checkpoint_artifacts(run_root, receipt)
    output.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(FrameworkIntegrityError, match="workspace identity changed"):
        _validate_checkpoint_artifacts(run_root, receipt)


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

    # node_modules without npm's installer record stays per-file, with its named gap.
    missing = ("node_modules: npm installer record unavailable (missing); "
               "dependency files cataloged per-file in the target lane")
    assert missing in gaps
    assert all("delivery status is unknown" in gap for gap in gaps if gap != missing)
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
