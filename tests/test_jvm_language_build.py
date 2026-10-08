from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import JvmBuildSettings, LanguageBuildSettings, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build.jvm import _fingerprint as jvm_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_project_build.job import _deterministic_jvm_recipe
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import IndexIdentity, RetrievalCore, write_manifest
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).parents[1]


class JvmRecipeModel:
    def __init__(self, *, gradle: bool = False) -> None:
        self.gradle = gradle

    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            tool = "gradlew" if unit["build_system"] == "gradle" else "mvnw"
            command = ([tool, "--no-daemon", "assemble"] if tool == "gradlew" else
                       [tool, "-B", "-DskipTests", "package"])
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "java", "source_dir": root, "build_dir": f"{root}/target",
                "system_packages": [], "environment": {},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": [], "build_commands": [command],
                "expected_outputs": [f"{root}/target"], "network_required": True,
                "reason": "bounded JVM fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        image_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "jvm-fixture:local", image_id, "f" * 64, True, False, hashes), b"", b""


class JvmExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail_roots: set[str] | None = None,
                 truncate: bool = False):
        self.calls, self.fail_roots, self.truncate = calls, fail_roots or set(), truncate

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        failed = working_directory in self.fail_roots
        if not failed:
            root = workspace / working_directory
            generated = root / "target" / "generated-sources" / "annotations"
            classes = root / "target" / "classes" / "example"
            meta = root / "target" / "classes" / "META-INF"
            for directory in (generated, classes, meta):
                directory.mkdir(parents=True, exist_ok=True)
            (generated / "Generated.java").write_text("class Generated {}\n", encoding="utf-8")
            (generated / "Generated.kt").write_text("class GeneratedKt\n", encoding="utf-8")
            (classes / "Main.class").write_bytes(b"\xca\xfe\xba\xbefixture")
            (meta / "app.kotlin_module").write_bytes(b"kotlin metadata")
            (meta / "pom.properties").write_text("version=1\n", encoding="utf-8")
            (root / "target" / "app.jar").write_bytes(b"PK\x03\x04jar")
            (root / "target" / "app.war").write_bytes(b"PK\x03\x04war")
            trace = root / ".appsec-review-jvm" / "invocations.bin"
            trace.parent.mkdir(parents=True, exist_ok=True)
            parent = environment.get("APPSEC_JVM_PARENT_COMMAND", "unknown")
            fields = ["javac", parent, "4", "-d", "target/classes", "src/main/java/example/Main.java",
                      "target/generated-sources/annotations/Generated.java",
                      "kotlinc", parent, "3", "-d", "target/classes", "src/main/kotlin/example/Mixed.kt",
                      "jar", parent, "3", "cf", "target/app.jar", "target/classes"]
            trace.write_bytes(b"\0".join(item.encode() for item in fields) + b"\0")
        stdout = b"build output contains private detail"
        stderr = b"diagnostic tail " + b"x" * 64
        return BuildCommandResult(tuple(argv), 2 if failed else 0, stdout[:8] if self.truncate else stdout,
            stderr[:8] if self.truncate else stderr, False, len(stdout), len(stderr),
            self.truncate, self.truncate, stdout[-16:] if self.truncate else b"",
            stderr[-16:] if self.truncate else b"")


def _fixture(tmp_path: Path, *, gradle: bool = False, output_bytes: int | None = None):
    config_text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if output_bytes is not None:
        config_text = config_text.replace("output_bytes = 8388608", f"output_bytes = {output_bytes}")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(config_text, encoding="utf-8")
    target = tmp_path / "target"
    root = target / ("gradle" if gradle else "maven")
    (root / "src" / "main" / "java" / "example").mkdir(parents=True)
    (root / "src" / "main" / "kotlin" / "example").mkdir(parents=True)
    (root / "src" / "main" / "java" / "example" / "Main.java").write_text(
        "package example; class Main {}\n", encoding="utf-8")
    (root / "src" / "main" / "kotlin" / "example" / "Mixed.kt").write_text(
        "package example\nclass Mixed\n", encoding="utf-8")
    marker = root / ("build.gradle.kts" if gradle else "pom.xml")
    marker.write_text("plugins { java }\n" if gradle else "<project/>\n", encoding="utf-8")
    return load_config(config_path), target


def _run_to_dispatch(config, target: Path, model: JvmRecipeModel, calls: list[tuple[str, ...]]):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(model_client=model)]).run(
        target_root=target, source_fingerprint=fingerprint)
    project = build_projects(executor_factory=lambda unit, profile: JvmExecutor(calls),
        image_resolver_factory=lambda unit: ImageResolver(target))
    GraphRunner(config, [project]).run(target_root=target, source_fingerprint=fingerprint,
                                       run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_jvm_mixed_maven_build_catalogs_provenance_and_never_executes_wrapper(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _run_to_dispatch(config, target, JvmRecipeModel(), calls)
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: JvmExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "SUCCEEDED"
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["family"] == "java"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "jvm-class", "generated-java-source", "generated-kotlin-source", "jar", "war",
        "kotlin-module-metadata", "dependency-metadata"}
    assert {item["tool"] for item in receipt["tool_invocations"]} == {"javac", "kotlinc", "jar"}
    assert all(call[0] == "mvn" for call in calls) and not any(call[0] == "mvnw" for call in calls)
    assert receipt["commands"][0]["wrapper_resolution"]["policy"] == "pinned-system-tool"
    assert '"argv":' not in json.dumps(receipt["tool_invocations"])


def test_jvm_gradle_wrapper_is_resolved_to_system_tool(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, gradle=True)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _run_to_dispatch(config, target, JvmRecipeModel(gradle=True), calls)
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: JvmExecutor(calls))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert calls and all(call[0] == "gradle" for call in calls)


def test_jvm_streams_are_hashed_bounded_and_retain_diagnostic_tails(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, output_bytes=8)
    run_id, fingerprint = _run_to_dispatch(config, target, JvmRecipeModel(), [])
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        JvmExecutor([], truncate=True))]).run(target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    for stream in (receipt["commands"][0]["stdout"], receipt["commands"][0]["stderr"]):
        assert stream["truncated"] is True and stream["capture_limit"] == 8
        assert stream["byte_count"] > stream["retained_byte_count"] == 8
        assert len(stream["sha256"]) == 64 and len(stream["diagnostic_tail"]["sha256"]) == 64


def test_jvm_failure_isolated_and_success_checkpoint_detects_tampering(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    sibling = target / "sibling"
    (sibling / "src" / "main" / "java").mkdir(parents=True)
    (sibling / "src" / "main" / "java" / "Sibling.java").write_text("class Sibling {}\n", encoding="utf-8")
    (sibling / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    run_id, fingerprint = _run_to_dispatch(config, target, JvmRecipeModel(), [])
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        JvmExecutor([], fail_roots={"sibling"}))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipts = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    assert {item["root"]: item["terminal_status"] for item in receipts} == {
        "maven": "SUCCEEDED", "sibling": "FAILED"}
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: JvmExecutor([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id,
        force_from="job_language_build")
    resumed = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    assert next(item for item in resumed if item["root"] == "maven")["checkpoint_reused"] is True
    successful = next(item for item in resumed if item["root"] == "maven")
    artifact = config.runtime.runs_dir / run_id / successful["artifacts"][0]["path"]
    artifact.write_bytes(b"tampered")
    with pytest.raises(RuntimeError, match="partial failure"):
        GraphRunner(config, [build_language(executor_factory=lambda unit, profile: JvmExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id,
            force_from="job_language_build")


def test_jvm_build_index_is_mcp_queryable_without_protected_streams(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _run_to_dispatch(config, target, JvmRecipeModel(), [])
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: JvmExecutor([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    run_root = config.runtime.runs_dir / run_id
    receipt = load_accepted_language_build(run_root)["receipts"][0]
    raw_identity = receipt["retrieval_index"]["identity"]
    identity = IndexIdentity(**{**raw_identity, "gaps": tuple(raw_identity.get("gaps", ()))})
    manifest = run_root / "data" / "indices" / "manifests" / "jvm-test.json"
    write_manifest(manifest, run_id=run_id, target_snapshot=fingerprint, target_root=target,
                   indexes=(identity,))
    manifest_artifact = {"path": manifest.relative_to(run_root).as_posix(),
        "sha256": file_sha256(manifest), "size_bytes": manifest.stat().st_size}
    handoff = run_root / "data" / "jobs" / "job_language_build" / "jvm-index-handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
        "job_id": "job_language_build", "attempt_id": "jvm-index", "artifacts": [manifest_artifact],
        "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": run_id,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": manifest_artifact["path"], "manifest_sha256": manifest_artifact["sha256"]})
    response = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id)).call(
        "search", {"query": "jar app.jar", "indexes": ["build"], "limit": 10})
    encoded = json.dumps(response)
    assert response["results"] and "app.jar" in encoded
    assert "build output contains private detail" not in encoded
    assert "protected-commands" not in encoded and "stdout" not in encoded and "stderr" not in encoded
    provenance = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id)).call(
        "search", {"query": "observed compiler javac", "indexes": ["build"], "limit": 10})
    assert provenance["results"] and "javac" in json.dumps(provenance)
    assert '"argv":' not in json.dumps(provenance)


def test_jvm_topology_has_independent_dagster_unit(tmp_path: Path) -> None:
    config, _target = _fixture(tmp_path)
    assert isinstance(config.job("job_language_build").typed_settings, LanguageBuildSettings)
    assert isinstance(config.job("job_language_build").typed_settings.jvm, JvmBuildSettings)
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: JvmExecutor([])),), config)
    assert graph.node("job_language_build.execute.java").dependencies == ("job_language_build.load.java",)


def test_jvm_checkpoint_fingerprint_invalidates_on_capture_or_upstream_change() -> None:
    dispatch = {"source_fingerprint": "target", "recipe_identity": "recipe",
        "build_dependencies": ["upstream"], "probe_identity": "probe",
        "image": {"image_id": "sha256:" + "d" * 64, "dependency_hashes": {"pom.xml": "a" * 64}}}
    settings = {"trace_bytes": 8, "provenance_count_limit": 10, "diagnostic_tail_bytes": 4,
        "system_path": "/usr/bin", "tool_paths": {name: f"/usr/bin/{name}" for name in
        ("javac", "kotlinc", "kapt", "ksp", "java", "jar", "javadoc", "protoc")}}
    first = jvm_fingerprint(dispatch, {"project_build_handoff_sha256": "a" * 64}, settings)
    assert first != jvm_fingerprint(dispatch, {"project_build_handoff_sha256": "b" * 64}, settings)
    assert first != jvm_fingerprint(dispatch, {"project_build_handoff_sha256": "a" * 64},
                                    {**settings, "trace_bytes": 9})


def test_jvm_recipe_validation_rejects_test_and_application_tasks_before_probe() -> None:
    unit = {"build_unit_id": "build-unit-" + "a" * 20, "family": "java", "root": "app",
        "build_system": "gradle", "markers": [{"path": "app/build.gradle"}],
        "descriptor_package": {"documents": [{"path": "app/build.gradle"}]}}
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
        "image_profile": "java", "source_dir": "app", "build_dir": "app/build",
        "system_packages": [], "environment": {}, "dependency_files": ["app/build.gradle"],
        "configure_commands": [], "build_commands": [["gradlew", "run"]],
        "expected_outputs": ["app/build"], "network_required": True, "reason": "unsafe fixture"}
    assert any("execution, tests" in error or "not build-only" in error
               for error in validate_build_recipe(recipe, unit))
    recipe["build_commands"] = [["mvnw", "-B", "package"]]
    unit["build_system"] = "maven"
    assert any("disable tests" in error for error in validate_build_recipe(recipe, unit))


def test_direct_mixed_jvm_sources_receive_a_deterministic_build_only_recipe(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "mixed" / "src"
    source.mkdir(parents=True)
    (source / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    (source / "Helper.kt").write_text("class Helper\n", encoding="utf-8")
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))
    action = {"family": "java", "build_system": "javac", "root": "mixed",
              "build_unit_id": "build-unit-" + "d" * 20}

    recipe = _deterministic_jvm_recipe(unit, action)

    assert recipe is not None
    assert [command[0] for command in recipe["build_commands"]] == ["kotlinc", "javac", "jar"]
    assert recipe["network_required"] is False
    assert not any(word in {"run", "test", "exec"} for command in recipe["build_commands"]
                   for word in command)
    assert recipe["expected_outputs"] == ["mixed/build/classes", "mixed/build/appsec-review.jar"]
