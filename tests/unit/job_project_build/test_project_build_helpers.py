"""job_project_build: code-level tests kept from the pre-walk suite (T-113).

Expected-output validation, probe checkpoint identity, probe output classification, probe
environment, deterministic recipes, workspace copies and the bounded image-repair vocabulary.
Nothing here runs a job graph; the graph suite lives in tests/integration/job_project_build/.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from appsec_review.config import ProcessingMode, load_config
from appsec_review.jobs.build_discovery import ensure_declared_build_dir
from appsec_review.jobs.job_language_build.job import _copy_source as _copy_language_source
from appsec_review.jobs.job_language_build.wasm import _copy_source as _copy_wasm_source
from appsec_review.jobs.job_project_build.job import (
    _copy_source, _deterministic_jvm_recipe, _node_recipe_restores_dependencies,
    _probe_cache, _probe_environment,
    _validate_expected_outputs,
)
from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA, apply_repair, validate_repair_proposal


ROOT = Path(__file__).resolve().parents[3]


def test_android_expected_output_requires_a_structurally_valid_apk(tmp_path: Path) -> None:
    recipe = {"expected_outputs": ["app/build/outputs/apk/debug/app-debug.apk"]}
    apk = tmp_path / recipe["expected_outputs"][0]
    apk.parent.mkdir(parents=True)
    assert _validate_expected_outputs(tmp_path, recipe) == [
        "required build output is missing: app/build/outputs/apk/debug/app-debug.apk"]
    apk.write_bytes(b"not a zip")
    assert _validate_expected_outputs(tmp_path, recipe) == [
        "required APK is not a valid ZIP archive: app/build/outputs/apk/debug/app-debug.apk"]
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    assert _validate_expected_outputs(tmp_path, recipe) == [
        "required APK has invalid Android structure: app/build/outputs/apk/debug/app-debug.apk"]
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("resources.arsc", b"resources")
    assert _validate_expected_outputs(tmp_path, recipe) == []


def test_build_capture_mode_changes_project_probe_checkpoint_identity(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job = config.job("job_project_build")
    context = dict(metadata_root=tmp_path, run_root=tmp_path / "run",
                   source_fingerprint="target", review_policy=config.review_policy)
    unit = SimpleNamespace(job=SimpleNamespace(**context, config=job))
    baseline = _probe_cache(unit, "a" * 64)
    changed_job = replace(job, build_capture=replace(
        job.build_capture, mode=ProcessingMode.AUTO))
    changed = _probe_cache(SimpleNamespace(job=SimpleNamespace(
        **context, config=changed_job)), "a" * 64)
    assert changed != baseline


def test_build_outputs_policy_changes_project_probe_checkpoint_identity(tmp_path: Path) -> None:
    from appsec_review.config.build_outputs import parse_build_outputs
    config = load_config(ROOT / "appsec-review.toml")
    job = config.job("job_project_build")
    assert job.build_outputs is not None
    context = dict(metadata_root=tmp_path, run_root=tmp_path / "run",
                   source_fingerprint="target", review_policy=config.review_policy)
    baseline = _probe_cache(SimpleNamespace(job=SimpleNamespace(**context, config=job)), "a" * 64)
    view = job.build_outputs.view()
    changed_job = replace(job, build_outputs=parse_build_outputs({**view, "exclusions": [
        *view["exclusions"], {"name": "vendored-out", "reason": "vendored outputs",
                              "patterns": ["out/"], "families": ["native"]}]}))
    changed = _probe_cache(SimpleNamespace(job=SimpleNamespace(**context, config=changed_job)), "a" * 64)
    same = _probe_cache(SimpleNamespace(job=SimpleNamespace(**context, config=replace(
        job, build_outputs=parse_build_outputs(view)))), "a" * 64)
    assert changed != baseline and same == baseline


def test_probe_outputs_prune_native_dependency_trees_and_configured_exclusions(tmp_path: Path) -> None:
    from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions
    from appsec_review.jobs.job_project_build.job import _classify_probe_outputs, _outputs
    from tests.test_native_build_output_classification import POLICY, _before, _fetchcontent_build, _write
    workspace = tmp_path / "workspace"
    _write(workspace, "CMakeLists.txt", "project(app)\n")
    _write(workspace, "main.cpp", "int main() { return 0; }\n")
    _fetchcontent_build(workspace)
    before = _before(workspace, "CMakeLists.txt", "main.cpp")
    unit = SimpleNamespace(job=SimpleNamespace(config=SimpleNamespace(build_outputs=POLICY)))
    bookkeeping = BookkeepingExclusions()
    dispositions, gaps = _classify_probe_outputs(
        unit, workspace, before, {"build_dir": "build", "source_dir": "."}, "native", "cmake", bookkeeping)
    artifacts = {item["workspace_path"]: item
                 for item in _outputs(tmp_path, workspace, before, 100, bookkeeping, dispositions=dispositions)}
    assert set(artifacts) == {"build/app", "build/CMakeFiles/app.dir/main.cpp.o", "build/_deps/fmt-build/libfmt.a"}
    roots = {root["root"]: root for root in dispositions.document()["roots"]}
    kept = artifacts["build/_deps/fmt-build/libfmt.a"]
    assert kept["build_output_root"] == "build/_deps/fmt-build"
    assert kept["scope_role"] == roots["build/_deps/fmt-build"]["scope_role"] is not None
    assert "scope_role" not in artifacts["build/app"]
    assert roots["build/_deps/fmt-src"]["disposition"] == "supply_chain"
    assert dispositions.document()["configured_exclusions"] == [{
        "path": "build/_deps/fmt-subbuild", "name": "cmake-fetchcontent-subbuild", "pattern": "*-subbuild/",
        "scope": "build_outputs", "files": 2}]
    assert [gap for gap in gaps if gap.startswith("dependency-content-summarized:")] and not any(
        "subbuild" in gap for gap in gaps)


def test_probe_outputs_record_configured_node_cache_exclusion_without_native_discovery(tmp_path: Path) -> None:
    from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions
    from appsec_review.jobs.job_project_build.job import _classify_probe_outputs, _outputs
    config = load_config(ROOT / "appsec-review.toml")
    workspace = tmp_path / "workspace"
    for relative in ("node_modules/.cache/babel/entry.json", "dist/app.wasm"):
        (workspace / relative).parent.mkdir(parents=True, exist_ok=True)
        (workspace / relative).write_bytes(b"\0asm\x01\0\0\0")
    unit = SimpleNamespace(job=SimpleNamespace(config=config.job("job_project_build")))
    bookkeeping = BookkeepingExclusions()
    dispositions, gaps = _classify_probe_outputs(unit, workspace, {}, {"source_dir": "."}, "node", "npm",
                                                 bookkeeping)
    _outputs(tmp_path, workspace, {}, 100, bookkeeping, dispositions=dispositions)
    document = dispositions.document()
    assert gaps == [] and document["roots"] == [] and document["layout_sources"] == []
    assert document["configured_exclusions"] == [{
        "path": "node_modules/.cache", "name": "node-bundler-cache", "pattern": "node_modules/.cache/",
        "scope": "build_outputs", "files": 1}]


def test_probe_and_repair_identity_bind_relevant_releases_target_and_run(tmp_path: Path) -> None:
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.jobs.job_project_build.job import _repair_cache, _reuse_accepted_repair
    config = load_config(ROOT / "appsec-review.toml")
    releases = {"platform": "fixture-platform", "build_toolchain": "fixture-build",
                "validation": "fixture-validation"}
    context = dict(metadata_root=tmp_path, run_root=tmp_path / "run",
                   source_fingerprint="target", config=config.job("job_project_build"),
                   review_policy=replace(config.review_policy, releases=ComponentReleases(releases)))
    for cache in (_probe_cache, _repair_cache):
        baseline = cache(SimpleNamespace(job=SimpleNamespace(**context)), "recipe")
        for component in releases:
            policy = replace(config.review_policy, releases=ComponentReleases({
                **releases, component: "changed"}))
            assert cache(SimpleNamespace(job=SimpleNamespace(
                **{**context, "review_policy": policy})), "recipe") != baseline
        for field, value in (("run_root", tmp_path / "other-run"), ("source_fingerprint", "other-target")):
            assert cache(SimpleNamespace(job=SimpleNamespace(
                **{**context, field: value})), "recipe") != baseline
        unrelated = replace(config.review_policy, releases=ComponentReleases({
            **releases, "queries_python": "unrelated-query-change"}))
        assert cache(SimpleNamespace(job=SimpleNamespace(
            **{**context, "review_policy": unrelated})), "recipe") == baseline



def test_probe_environment_uses_writable_networked_maven_repository() -> None:
    recipe = {"build_system": "maven", "source_dir": "projects/java/sample",
              "environment": {"MAVEN_OPTS": "-Dmaven.artifact.threads=1"}}
    assert _probe_environment(recipe)["MAVEN_OPTS"] == (
        "-Dmaven.repo.local=/tmp/appsec-review-maven "
        "-Dmaven.repo.local.tail=/opt/project-deps/maven -Dmaven.artifact.threads=1")


def test_probe_environment_supplies_writable_maven_repository_without_user_options() -> None:
    recipe = {"build_system": "maven", "source_dir": ".", "environment": {}}
    assert _probe_environment(recipe)["MAVEN_OPTS"] == (
        "-Dmaven.repo.local=/tmp/appsec-review-maven "
        "-Dmaven.repo.local.tail=/opt/project-deps/maven")


def test_probe_environment_keeps_gradle_home_writable_with_read_only_image_cache() -> None:
    # The derived image restores into /opt/project-deps/gradle, which is read-only at run time.
    # Gradle must lock and write elsewhere while still reading the restored modules.
    for recipe in ({"build_system": "gradle", "source_dir": ".", "environment": {}},
                   {"build_system": "gradle", "source_dir": ".",
                    "environment": {"GRADLE_USER_HOME": "/opt/project-deps/gradle"}}):
        environment = _probe_environment(recipe)
        assert environment["GRADLE_USER_HOME"] == "/tmp/appsec-review-gradle"
        assert environment["GRADLE_RO_DEP_CACHE"] == "/opt/project-deps/gradle/caches"
    assert "GRADLE_USER_HOME" not in _probe_environment(
        {"build_system": "maven", "source_dir": ".", "environment": {}})


def test_networked_node_restore_uses_writable_scratch_caches() -> None:
    environment = _probe_environment({
        "build_system": "node", "source_dir": "projects/javascript-bundler/case-086",
        "network_required": True, "environment": {}, "dependency_files": [
            "projects/javascript-bundler/case-086/package-lock.json"],
    })
    assert environment["NPM_CONFIG_CACHE"] == "/tmp/appsec-npm-cache"
    assert environment["PNPM_STORE_DIR"] == "/tmp/appsec-pnpm-store"
    assert environment["YARN_CACHE_FOLDER"] == "/tmp/appsec-yarn-cache"


def test_node_configure_restore_does_not_mount_immutable_image_dependencies() -> None:
    for root in ("projects/javascript-bundler/case-086", "projects/node-addon/case-087"):
        assert _node_recipe_restores_dependencies({
            "source_dir": root, "configure_commands": [["npm", "ci"]]})
    assert not _node_recipe_restores_dependencies({
        "source_dir": "projects/node/no-restore", "configure_commands": []})


def test_probe_environment_disables_cargo_incremental_state_the_host_cannot_read() -> None:
    environment = _probe_environment({"build_system": "cargo", "source_dir": "rust",
                                      "environment": {"CARGO_INCREMENTAL": "1"}})
    assert environment["CARGO_INCREMENTAL"] == "0"
    assert "CARGO_INCREMENTAL" not in _probe_environment({
        "build_system": "cmake", "source_dir": "native", "environment": {}})


def test_kotlin_direct_recipe_uses_the_profile_image_toolchain(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "kotlin" / "src"
    source.mkdir(parents=True)
    kotlin = source / "Main.kt"
    kotlin.write_text("fun main() = Unit\n", encoding="utf-8")
    action = {"build_unit_id": "build-unit-kotlin", "family": "java",
              "build_system": "javac", "root": "kotlin"}
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))
    recipe = _deterministic_jvm_recipe(unit, action)
    assert recipe is not None
    # The Java image carries kotlinc and its JDK. Packages here would be stripped by planning and
    # a JAVA_HOME would name a JDK the pinned image does not contain.
    assert recipe["system_packages"] == []
    assert recipe["environment"] == {}
    assert recipe["build_commands"][0][:2] == ["kotlinc", "src/Main.kt"]


def test_project_probe_copies_accepted_parent_dependency_files(tmp_path: Path) -> None:
    target = tmp_path / "target"
    member = target / "apps" / "web"
    member.mkdir(parents=True)
    (member / "package.json").write_text("{}\n", encoding="utf-8")
    (target / "tsconfig.base.json").write_text("{}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    workspace = run_root / "data" / "build" / "probes" / "unit" / "attempt-001" / "workspace"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    action = {"root": "apps/web", "recipe": {
        "dependency_files": ["apps/web/package.json", "tsconfig.base.json"]}}
    _copy_source(unit, action, workspace)
    assert (workspace / "apps/web/package.json").is_file()
    assert (workspace / "tsconfig.base.json").is_file()

    language_workspace = tmp_path / "language-workspace"
    _copy_language_source(unit, action, language_workspace)
    assert (language_workspace / "apps/web/package.json").is_file()
    assert (language_workspace / "tsconfig.base.json").is_file()


def test_project_probe_materializes_bounded_legacy_maven_source_layout(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "projects" / "java" / "case-034"
    (source / "src").mkdir(parents=True)
    (source / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (source / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    workspace = run_root / "data" / "build" / "probes" / "unit" / "workspace"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    root = "projects/java/case-034"
    action = {"root": root, "family": "java", "build_system": "maven", "recipe": {
        "source_dir": root, "dependency_files": [f"{root}/pom.xml"]}}
    adaptations = _copy_source(unit, action, workspace)
    materialized = workspace / root / "src" / "main" / "java" / "Main.java"
    assert materialized.read_text(encoding="utf-8") == "class Main {}\n"
    assert adaptations == [
        "materialized legacy Maven src/*.java under src/main/java in the run-owned workspace"]


def test_project_probe_keeps_maven_layout_when_pom_declares_source_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "projects" / "java" / "case-034"
    (source / "src").mkdir(parents=True)
    (source / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><build>'
        "<sourceDirectory>src</sourceDirectory></build></project>\n", encoding="utf-8")
    (source / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    workspace = run_root / "data" / "build" / "probes" / "unit" / "workspace"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    root = "projects/java/case-034"
    action = {"root": root, "family": "java", "build_system": "maven", "recipe": {
        "source_dir": root, "dependency_files": [f"{root}/pom.xml"]}}
    assert _copy_source(unit, action, workspace) == []
    assert not (workspace / root / "src" / "main").exists()
    assert (workspace / root / "src" / "Main.java").is_file()


def test_declared_build_dir_exists_before_recipe_commands_write_into_it(tmp_path: Path) -> None:
    # A recipe like `clang --target=wasm32 -o build/case091.wasm` cannot mkdir its output directory.
    root = "projects/wasm/case-091"
    target = tmp_path / "target"
    (target / root / "src").mkdir(parents=True)
    (target / root / "src" / "case091.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    recipe = {"source_dir": root, "build_dir": f"{root}/build", "dependency_files": [],
              "expected_outputs": [f"{root}/build"]}
    action = {"root": root, "family": "wasm", "build_system": "clang", "recipe": recipe}
    for copy in (_copy_language_source, _copy_wasm_source):
        workspace = tmp_path / copy.__module__ / "workspace"
        copy(unit, action, workspace)
        assert (workspace / root / "build").is_dir()

    workspace = run_root / "data" / "build" / "probes" / "unit" / "workspace"
    _copy_source(unit, action, workspace)
    assert ensure_declared_build_dir(workspace, recipe) == f"{root}/build"
    assert ensure_declared_build_dir(workspace, recipe) is None
    assert _validate_expected_outputs(workspace, recipe, f"{root}/build") == [
        f"required build output is missing: {root}/build"]
    (workspace / root / "build" / "case091.wasm").write_bytes(b"\0asm")
    assert _validate_expected_outputs(workspace, recipe, f"{root}/build") == []

    escape = tmp_path / "escape"
    escape.mkdir()
    linked = tmp_path / "linked"
    (linked / "projects").mkdir(parents=True)
    (linked / "projects" / "wasm").symlink_to(escape, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        ensure_declared_build_dir(linked, recipe)
    assert not any(escape.iterdir())


def _repair(**fields):
    return {"schema": REPAIR_SCHEMA, "system_packages": [], "environment": {},
            "package_manager": None, "dependency_restores": [],
            "reason": "bounded repair", **fields}


def _repair_recipe(profile: str, root: str, dependency_files: list[str], *, build_system: str,
                   commands: list[list[str]], network_required: bool = False) -> dict:
    return {"schema": "appsec-review/build-recipe/1", "build_unit_id": "build-unit-" + "a" * 20,
            "image_profile": profile, "source_dir": root, "build_dir": f"{root}/build",
            "system_packages": [], "environment": {}, "dependency_files": dependency_files,
            "configure_commands": [], "build_commands": commands, "expected_outputs": [f"{root}/build"],
            "network_required": network_required, "reason": "accepted recipe"}


def _repair_unit(recipe: dict, build_system: str) -> dict:
    documents = [{"path": path} for path in recipe["dependency_files"]]
    return {"build_unit_id": recipe["build_unit_id"], "family": recipe["image_profile"],
            "root": recipe["source_dir"], "build_system": build_system,
            "required_image_profile": recipe["image_profile"], "markers": documents,
            "descriptor_package": {"documents": documents}}


def test_image_repair_accepts_only_bounded_apt_package_sets() -> None:
    recipe = _repair_recipe("native", "lib", ["lib/CMakeLists.txt"], build_system="cmake",
                            commands=[["cmake", "--build", "lib/build"]])
    proposal = _repair(system_packages=["libssl-dev", "zlib1g-dev:amd64"])
    assert validate_repair_proposal(proposal, recipe=recipe, build_system="cmake") == ()
    repaired = apply_repair(recipe, proposal, build_system="cmake")
    assert repaired["system_packages"] == ["libssl-dev", "zlib1g-dev:amd64"]
    assert "image_repairs" not in repaired
    invalid = {**proposal, "system_packages": ["libssl-dev;curl attacker"]}
    assert validate_repair_proposal(invalid, recipe=recipe, build_system="cmake")
    legacy = {"schema": "appsec-review/build-image-repair/1", "system_packages": ["libssl-dev"],
              "reason": "old shape"}
    assert validate_repair_proposal(legacy, recipe=recipe, build_system="cmake") == (
        "repair proposal fields are invalid",)


def test_image_repair_environment_is_a_typed_family_allowlist() -> None:
    from appsec_review.jobs.build_discovery import validate_build_recipe

    recipe = _repair_recipe("python", "pkg", ["pkg/pyproject.toml", "pkg/requirements-build.txt"],
                            build_system="python",
                            commands=[["python", "-m", "pip", "wheel", "--no-deps", "."]])
    proposal = _repair(environment={"PIP_BREAK_SYSTEM_PACKAGES": "1",
                                    "SETUPTOOLS_SCM_PRETEND_VERSION": "1.4.0"})
    repaired = apply_repair(recipe, proposal, build_system="python")
    assert repaired["environment"] == {"PIP_BREAK_SYSTEM_PACKAGES": "1",
                                       "SETUPTOOLS_SCM_PRETEND_VERSION": "1.4.0"}
    assert repaired["image_repairs"]["environment"] == repaired["environment"]
    assert validate_build_recipe(repaired, _repair_unit(repaired, "python")) == []
    for environment, message in (
            ({"PIP_INDEX_URL": "https://example.invalid/simple"}, "not repairable for python"),
            ({"LD_PRELOAD": "/tmp/x.so"}, "not repairable for python"),
            ({"PIP_BREAK_SYSTEM_PACKAGES": "1; curl x"}, "value is not allowed"),
            ({"NPM_CONFIG_LEGACY_PEER_DEPS": "true"}, "not repairable for python")):
        errors = validate_repair_proposal(_repair(environment=environment), recipe=recipe,
                                          build_system="python")
        assert any(message in error for error in errors), (environment, errors)
    # A later repair replaces the earlier repair environment rather than accumulating it.
    second = apply_repair(repaired, _repair(environment={"PIP_NO_BUILD_ISOLATION": "0"}),
                          build_system="python")
    assert second["environment"] == {"PIP_NO_BUILD_ISOLATION": "0"}
    # An accepted recipe's own environment is never overwritten by a repair.
    owned = {**recipe, "environment": {"PIP_BREAK_SYSTEM_PACKAGES": "1"}}
    with pytest.raises(ValueError, match="replace accepted recipe environment"):
        apply_repair(owned, proposal, build_system="python")
    with pytest.raises(ValueError, match="repeated the current repair set"):
        apply_repair(repaired, proposal, build_system="python")
    maven = _repair_recipe("java", "svc", ["svc/pom.xml"], build_system="maven",
                           commands=[["mvn", "-B", "package"]])
    assert validate_repair_proposal(_repair(environment={
        "MAVEN_ARGS": "-Denforcer.skip=true -Dmaven.compiler.release=8"}),
        recipe=maven, build_system="maven") == ()
    assert validate_repair_proposal(_repair(environment={"MAVEN_ARGS": "-Dexec.executable=sh"}),
                                    recipe=maven, build_system="maven")


def test_image_repair_dependency_restores_use_the_family_manager_on_accepted_manifests() -> None:
    from appsec_review.container_runtime.project_images import repair_restore_commands
    from appsec_review.jobs.build_discovery import validate_build_recipe

    recipe = _repair_recipe("python", "pkg", ["pkg/pyproject.toml", "pkg/requirements-build.txt"],
                            build_system="python", commands=[["python", "-m", "build", "--wheel"]])
    repaired = apply_repair(recipe, _repair(dependency_restores=[
        {"manifest": "pkg/requirements-build.txt"}]), build_system="python")
    assert repaired["image_repairs"]["dependency_restores"] == [
        {"manager": "pip", "manifest": "pkg/requirements-build.txt"}]
    assert repair_restore_commands({**repaired, "build_system": "python"}) == [(
        "/opt/project/pkg",
        ("python", "-m", "pip", "install", "--target", "/opt/project-deps", "-r",
         "requirements-build.txt"))]
    assert validate_build_recipe(repaired, _repair_unit(repaired, "python")) == []
    for manifest, message in (("pkg/pyproject.toml", "cannot restore dependencies"),
                              ("pkg/../../etc/passwd", "not an accepted dependency file"),
                              ("other/requirements.txt", "not an accepted dependency file")):
        errors = validate_repair_proposal(_repair(dependency_restores=[{"manifest": manifest}]),
                                          recipe=recipe, build_system="python")
        assert any(message in error for error in errors), (manifest, errors)
    errors = validate_repair_proposal(_repair(dependency_restores=[
        {"manifest": "pkg/requirements-build.txt", "argv": ["sh", "-c", "id"]}]),
        recipe=recipe, build_system="python")
    assert "dependency_restores entries must be objects with only manifest" in errors
    # A tampered recorded restore fails recipe validation instead of reaching the Dockerfile.
    tampered = {**repaired, "image_repairs": {**repaired["image_repairs"], "dependency_restores": [
        {"manager": "npm", "manifest": "pkg/requirements-build.txt"}]}}
    assert any("not normalized" in error
               for error in validate_build_recipe(tampered, _repair_unit(tampered, "python")))

    maven = _repair_recipe("java", "svc", ["svc/pom.xml", "svc/tools/pom.xml"],
                           build_system="maven", commands=[["mvn", "-B", "package"]])
    repaired = apply_repair(maven, _repair(dependency_restores=[{"manifest": "svc/tools/pom.xml"}]),
                            build_system="maven")
    assert repair_restore_commands({**repaired, "build_system": "maven"}) == [(
        "/opt/project/svc/tools", ("mvn", "-B", "-DskipTests", "-f", "pom.xml", "dependency:go-offline"))]
    composer = _repair_recipe("php", "web", ["web/composer.json", "web/tools/composer.json"],
                              build_system="composer", commands=[["composer", "dump-autoload"]])
    assert validate_repair_proposal(_repair(dependency_restores=[{"manifest": "web/composer.json"}]),
                                    recipe=composer, build_system="composer") == ()
    assert validate_repair_proposal(_repair(dependency_restores=[
        {"manifest": "web/tools/composer.json"}]), recipe=composer, build_system="composer")


def test_image_repair_package_manager_selects_only_a_pinned_lockless_node_manager() -> None:
    from appsec_review.container_runtime.project_images import (
        PINNED_PACKAGE_MANAGERS, _restore_command, repair_restore_commands)

    recipe = _repair_recipe("node", "web", ["web/package.json", "web/pnpm-workspace.yaml"],
                            build_system="node", commands=[["tsc", "-p", "."]])
    proposal = _repair(package_manager="pnpm", dependency_restores=[{"manifest": "web/package.json"}])
    repaired = apply_repair(recipe, proposal, build_system="node")
    assert repaired["image_repairs"]["package_manager"] == "pnpm"
    assert repair_restore_commands({**repaired, "build_system": "node"}) == [(
        "/opt/project/web", ("pnpm", "install", "--no-frozen-lockfile", "--ignore-scripts"))]
    assert _restore_command({**repaired, "build_system": "node"})[0] == "pnpm"
    for manager in ("bun", "npm@11", "corepack"):
        assert validate_repair_proposal(_repair(package_manager=manager), recipe=recipe,
                                        build_system="node")
    locked = {**recipe, "dependency_files": ["web/package.json", "web/package-lock.json"]}
    assert any("accepted lockfile" in error for error in validate_repair_proposal(
        _repair(package_manager="yarn"), recipe=locked, build_system="node"))
    runs_npm = {**recipe, "build_commands": [["npm", "run", "build"]]}
    assert any("conflicts" in error for error in validate_repair_proposal(
        _repair(package_manager="yarn"), recipe=runs_npm, build_system="node"))
    python = _repair_recipe("python", "pkg", ["pkg/pyproject.toml"], build_system="python",
                            commands=[["python", "-m", "build"]])
    assert validate_repair_proposal(_repair(package_manager="pip"), recipe=python,
                                    build_system="python")
    # The selectable versions are the ones the Node build image pins.
    dockerfile = (ROOT / "containers" / "buildenv" / "typescript" / "Dockerfile").read_text()
    pinned = PINNED_PACKAGE_MANAGERS["node"]
    assert f'version="node{pinned["npm"].rsplit(" ", 1)[1]}-pnpm{pinned["pnpm"]}-yarn{pinned["yarn"]}"' in dockerfile


def test_image_repair_vocabulary_names_no_case_identifiers() -> None:
    source = (ROOT / "src" / "appsec_review" / "jobs" / "job_project_build" / "repair.py").read_text()
    import re

    assert not re.search(r"case-?\d{3}", source) and "multivuln" not in source.lower()
