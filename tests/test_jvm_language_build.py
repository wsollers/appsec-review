from __future__ import annotations

from dataclasses import asdict, replace
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from appsec_review.config import JvmBuildSettings, LanguageBuildSettings, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.build_discovery import jvm_build_command_errors, validate_build_recipe
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build.jvm import (
    JvmIntegrityError, _fingerprint as jvm_fingerprint, _jvm_argv,
)
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_project_build.job import _deterministic_jvm_recipe
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult, check_models, infer
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import IndexIdentity, RetrievalCore, write_manifest
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import atomic_json, file_sha256
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[1]


def _declare_fixture_releases(text: str) -> str:
    return text.replace("[review_policy.releases]\n", "[review_policy.releases]\n" +
        "".join(f'{key} = "fixture/1"\n' for key in
                ("platform", "validation", "build_toolchain", "jvm_instrumentation")))


class JvmRecipeModel:
    def __init__(self, *, gradle: bool = False) -> None:
        self.gradle = gradle
        self.requests = []

    def complete(self, request, *, timeout_seconds):
        self.requests.append(request)
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            profile = unit["required_image_profile"]
            android = profile == "android"
            tool = ("gradle" if android else "gradlew") if unit["build_system"] == "gradle" else "mvnw"
            command = ([tool, "--no-daemon", ":app:assembleDebug"] if android else
                       [tool, "--no-daemon", "assemble"] if tool == "gradlew" else
                       [tool, "-B", "-DskipTests", "package"])
            build_dir = f"{root}/app/build" if android else f"{root}/target"
            expected = ([f"{root}/app/build/outputs/apk/debug/app-debug.apk"] if android else
                        [f"{root}/target"])
            dependencies = ([item["path"] for item in unit["descriptor_package"]["documents"]]
                            if android else [item["path"] for item in unit["markers"]])
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": profile, "source_dir": root, "build_dir": build_dir,
                "system_packages": [], "environment": {},
                "dependency_files": dependencies,
                "configure_commands": [], "build_commands": [command],
                "expected_outputs": expected, "network_required": True,
                "reason": "bounded JVM fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path, releases=None):
        self.target, self.releases = target, releases

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes, releases=self.releases)
        image_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "jvm-fixture:local", image_id, "f" * 64, True, False, hashes), b"", b""


class JvmExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail_roots: set[str] | None = None,
                 truncate: bool = False, environments: list[dict[str, str]] | None = None):
        self.calls, self.fail_roots, self.truncate = calls, fail_roots or set(), truncate
        self.environments = environments

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment,
                instrumentation_root=None, instrumentation_evidence_root=None):
        self.calls.append(tuple(argv))
        if self.environments is not None:
            self.environments.append(dict(environment))
        failed = working_directory in self.fail_roots
        if not failed:
            root = workspace / working_directory
            if any(str(value).lower().endswith(":assembledebug") for value in argv):
                apk = root / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
                apk.parent.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(apk, "w") as archive:
                    archive.writestr("AndroidManifest.xml", b"manifest")
                    archive.writestr("resources.arsc", b"resources")
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
            trace = ((instrumentation_evidence_root or root / ".fixture-probe-evidence")
                     / "invocations.bin")
            trace.parent.mkdir(parents=True, exist_ok=True)
            parent = environment.get("APPSEC_JVM_PARENT_COMMAND", "unknown")
            fields = ["javac", parent, "4", "-d", "target/classes", "src/main/java/example/Main.java",
                      "target/generated-sources/annotations/Generated.java",
                      "kotlinc", parent, "3", "-d", "target/classes", "src/main/kotlin/example/Mixed.kt",
                      "jar", parent, "3", "cf", "target/app.jar", "target/classes"]
            trace.write_bytes(b"\0".join(item.encode() for item in fields) + b"\0")
            if "--init-script" in argv:
                # Emulate the run-owned Gradle init script: a session record and, for an APK
                # assembly, the in-process D8 dex task it can only declare.
                records = [{"record_kind": "session", "gradle_version": "8.9"}]
                if any(str(value).lower().endswith(":assembledebug") for value in argv):
                    records += [
                        {"record_kind": "dex-task", "task_path": ":app:mergeDexDebug", "compiler": "d8",
                         "task_type": "com.android.build.gradle.internal.tasks.DexMergingTask",
                         "output_files": [f"/workspace/{working_directory}/app/build/intermediates/dex"],
                         "input_file_count": 2},
                        {"record_kind": "completed", "task_path": ":app:mergeDexDebug",
                         "compiler": "d8", "did_work": True}]
                (trace.parent / "gradle-tasks.jsonl").write_text("".join(
                    json.dumps({"schema": "appsec-review/gradle-task-record/1",
                                "parent_command_id": parent, **record}) + "\n" for record in records),
                    encoding="utf-8")
        stdout = b"build output contains private detail"
        stderr = b"diagnostic tail " + b"x" * 64
        return BuildCommandResult(tuple(argv), 2 if failed else 0, stdout[:8] if self.truncate else stdout,
            stderr[:8] if self.truncate else stderr, False, len(stdout), len(stderr),
            self.truncate, self.truncate, stdout[-16:] if self.truncate else b"",
            stderr[-16:] if self.truncate else b"")


def _fixture(tmp_path: Path, *, gradle: bool = False, output_bytes: int | None = None):
    config_text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_text = _declare_fixture_releases(config_text)
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


def _android_fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(_declare_fixture_releases(
        (ROOT / "appsec-review.toml").read_text(encoding="utf-8")), encoding="utf-8")
    target = tmp_path / "target"
    root = target / "android"
    (root / "app" / "src" / "main" / "java" / "example").mkdir(parents=True)
    (root / "build.gradle.kts").write_text(
        'plugins { id("com.android.application") version "8.7.3" apply false }\n', encoding="utf-8")
    (root / "settings.gradle.kts").write_text(
        'rootProject.name = "fixture"\ninclude(":app")\n', encoding="utf-8")
    (root / "app" / "build.gradle.kts").write_text(
        'plugins { id("com.android.application") }\nandroid { compileSdk = 35 }\n', encoding="utf-8")
    (root / "gradle.properties").write_text("org.gradle.daemon=false\n", encoding="utf-8")
    (root / "app" / "src" / "main" / "java" / "example" / "Main.java").write_text(
        "package example; class Main {}\n", encoding="utf-8")
    return load_config(config_path), target


def _run_to_dispatch(config, target: Path, model: JvmRecipeModel, calls: list[tuple[str, ...]]):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=model.complete)]).run(
        target_root=target, source_fingerprint=fingerprint)
    project = build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, JvmExecutor(calls)),
        image_resolver_factory=lambda unit: ImageResolver(target, config.review_policy.releases))
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


def test_android_gradle_dispatch_survives_project_to_language_execution(tmp_path: Path) -> None:
    config, target = _android_fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    model = JvmRecipeModel(gradle=True)
    run_id, fingerprint = _run_to_dispatch(config, target, model, calls)
    run_root = config.runtime.runs_dir / run_id
    request = model.requests[0]
    inferred_unit = request.summary["build_units"][0]
    assert request.allowed_image_profiles == ("android",)
    assert inferred_unit["required_image_profile"] == "android"
    assert inferred_unit["command_policy"]["gradle"]["allowed_task_suffixes"][-1] == "assembleDebug"
    assert {item["path"] for item in inferred_unit["descriptor_package"]["documents"]} == {
        "android/app/build.gradle.kts", "android/build.gradle.kts",
        "android/gradle.properties", "android/settings.gradle.kts",
    }
    plan = load_accepted_plan(run_root)
    inferred_recipe = plan["build_topology"]["build_actions"][0]["recipe"]
    dispatch = load_accepted_builds(run_root)["build_dispatches"][0]
    assert dispatch["recipe"]["image_profile"] == "android"
    assert dispatch["recipe"] == inferred_recipe
    assert dispatch["recipe_provenance"] == "accepted-inference-default-image"
    assert dispatch["descriptor_facts"]["kind"] == "android-gradle-application"

    profiles, environments = [], []

    def executor_factory(unit, profile):
        profiles.append(profile)
        return JvmExecutor(calls, environments=environments)

    outcome = GraphRunner(config, [build_language(executor_factory=executor_factory)]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)

    # In-process D8 dexing is declared by the init script but never observed: a named gap.
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(run_root)["receipts"][0]
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["family"] == "java"
    assert receipt["gaps"][0].startswith(
        "Android dex task :app:mergeDexDebug ran D8 in-process inside Gradle")
    assert not any("not emitted" in gap or "did not report" in gap for gap in receipt["gaps"])
    (dex,) = receipt["declared_compilations"]
    assert dex["tool"] == "d8" and dex["evidence_kind"] == "build-tool-declared"
    assert "declared_arguments" not in dex and dex["declared_arguments_sha256"]
    # Project-build ran the accepted command; language-build ran it with provenance instrumentation.
    assert calls.count(("gradle", "--no-daemon", ":app:assembleDebug")) == 1
    (instrumented,) = [call for call in calls if "--init-script" in call]
    assert instrumented[:3] == ("gradle", "--no-daemon", ":app:assembleDebug")
    assert instrumented[-1] == "/appsec-jvm/gradle/appsec-provenance.init.gradle"
    assert receipt["commands"][0]["instrumentation"]["gradle_init_script"]["path"] == instrumented[-1]
    assert [profile.name for profile in profiles] == ["android"]
    assert environments and "/opt/gradle/gradle-8.9/bin" in environments[0]["PATH"].split(":")
    assert environments[0]["GRADLE_USER_HOME"] == "/tmp/gradle"


@pytest.mark.skipif(
    os.environ.get("APPSEC_RUN_LIVE_INFERENCE") != "1",
    reason="requires the configured authenticated model transport",
)
def test_live_configured_model_returns_android_gradle_recipe_proposals(tmp_path: Path) -> None:
    """Show every model recipe before project-build selects the requested Android image."""
    config, target = _android_fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    proposals: list[dict] = []

    def capture_infer(request, *, timeout_seconds):
        result = infer(request, timeout_seconds=timeout_seconds)
        proposals.append(dict(result.proposal))
        return result

    outcome = GraphRunner(config, [build_intake(check_models=check_models), build_catalog(),
                                   build_plan(infer=capture_infer)]).run(
        target_root=target, source_fingerprint=fingerprint)

    assert outcome["status"] == "SUCCEEDED", outcome
    assert proposals and all("build_recipes" in proposal for proposal in proposals)
    print(json.dumps(proposals, indent=2, sort_keys=True))
    plan = load_accepted_plan(config.runtime.runs_dir / outcome["run_id"])
    action = next(item for item in plan["build_topology"]["build_actions"]
                  if item["build_system"] == "gradle")
    assert action["descriptor_facts"]["kind"] == "android-gradle-application"
    assert action["required_image_profile"] == "android"
    recipe = action["recipe"]
    assert recipe is not None and recipe["image_profile"] == "android"
    unit = {
        "build_unit_id": action["build_unit_id"], "family": action["family"],
        "root": action["root"], "build_system": action["build_system"],
        "markers": action["markers"], "descriptor_package": action["descriptor_package"],
        "descriptor_facts": action["descriptor_facts"],
    }
    assert validate_build_recipe(recipe, unit) == []


@pytest.mark.parametrize("task", [":app:test", ":app:connectedAndroidTest", ":app:installDebug", ":app:run"])
def test_android_gradle_policy_allows_assembly_but_rejects_execution_tasks(task: str) -> None:
    recipe = {"image_profile": "android", "source_dir": "android"}
    accepted = ["gradle", "--no-daemon", ":app:assembleDebug"]
    assert jvm_build_command_errors("android", accepted) == ()
    assert _jvm_argv(recipe, accepted)[0] == tuple(accepted)
    assert "Gradle task is not allowed for java profile" in jvm_build_command_errors(
        "java", accepted)[0]

    rejected = ["gradle", "--no-daemon", task]
    assert "Gradle task is not allowed for android profile" in jvm_build_command_errors(
        "android", rejected)[0]
    with pytest.raises(JvmIntegrityError, match="Gradle task is not allowed for android profile"):
        _jvm_argv(recipe, rejected)


@pytest.mark.parametrize("task", [":app:classes", ":app:jar", ":app:war", "clean", "build"])
def test_android_gradle_policy_rejects_tasks_that_do_not_produce_an_apk(task: str) -> None:
    error = jvm_build_command_errors("android", ["gradle", task])[0]
    assert error == ("Gradle task is not allowed for android profile; "
                     "allowed task suffixes: assemble, assembleDebug")


def test_gradle_build_requires_an_explicit_test_exclusion() -> None:
    recipe = {"image_profile": "java", "source_dir": "java"}
    assert jvm_build_command_errors("java", ["gradle", "build", "-x", "test"]) == ()
    assert _jvm_argv(recipe, ["gradle", "build", "-x", "test"])[0] == (
        "gradle", "build", "-x", "test")
    with pytest.raises(JvmIntegrityError, match="must exclude the test task"):
        _jvm_argv(recipe, ["gradle", "build"])


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
    from appsec_review.runtime.handoff import verify_handoff_integrity
    run_root = config.runtime.runs_dir / run_id
    latest = json.loads((run_root / "data" / "jobs" / "job_language_build" / "latest.json").read_text())
    first_handoff = json.loads((run_root / latest["handoff_path"]).read_text())
    GraphRunner(config, [build_language(executor_factory=lambda unit, profile: JvmExecutor([]))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id,
        force_from="job_language_build")
    resumed = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    verify_handoff_integrity(run_root, first_handoff)
    assert next(item for item in resumed if item["root"] == "maven")["checkpoint_reused"] is True
    first_by_root = {item["root"]: item for item in receipts}
    second_by_root = {item["root"]: item for item in resumed}
    assert second_by_root["maven"]["workspace"] == first_by_root["maven"]["workspace"]
    assert second_by_root["sibling"]["workspace"] != first_by_root["sibling"]["workspace"]
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
    handoff = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "jvm-index" / "handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(run_root, handoff, {"source_fingerprint": fingerprint, "status": "ACCEPTED",
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
        "system_paths": {"java": "/usr/bin", "android": "/opt/gradle/bin:/usr/bin"},
        "tool_paths": {name: f"/usr/bin/{name}" for name in
        ("javac", "kotlinc", "kapt", "ksp", "java", "jar", "javadoc", "protoc")}}
    first = jvm_fingerprint(dispatch, {"project_build_handoff_sha256": "a" * 64}, settings)
    assert first != jvm_fingerprint(dispatch, {"project_build_handoff_sha256": "b" * 64}, settings)
    assert first != jvm_fingerprint(dispatch, {"project_build_handoff_sha256": "a" * 64},
                                    {**settings, "trace_bytes": 9})


def _isolated_jvm_action(tmp_path, monkeypatch, mode, *, missing=None):
    from appsec_review.config.assurance import AssuranceMode, ComponentReleases, ReviewPolicy
    from appsec_review.jobs.job_language_build import job as generic, jvm

    config, target = _fixture(tmp_path)
    declarations = {key: "fixture/1" for key in jvm._RELEASE_COMPONENTS if key != missing}
    policy = ReviewPolicy(mode=AssuranceMode(mode), project_id="fixture",
        approved_first_party_projects=("fixture",), target_root=str(target.resolve()),
        custody="application_private_v1", releases=ComponentReleases(declarations))
    run_root = tmp_path / "run"
    run_root.mkdir()
    records, calls = [], []
    unit = SimpleNamespace(unit_id="execute.java", job=SimpleNamespace(
        config=config.job("job_language_build"), review_policy=policy, run_root=run_root,
        metadata_root=tmp_path / "metadata", target_root=target, source_fingerprint=source_fingerprint(target),
        run_id="fixture-run", attempt_id="fixture-attempt",
        events=SimpleNamespace(write=lambda event, **values: records.append((event, values)))))

    def copy_source(_unit, _dispatch, workspace):
        if workspace.exists():
            shutil.rmtree(workspace)
        shutil.copytree(target, workspace)

    monkeypatch.setattr(generic, "_copy_source", copy_source)
    monkeypatch.setattr(jvm, "_index", lambda *_args: {"fixture": True})
    dispatch = {"build_unit_id": "jvm-fixture", "root": "maven", "family": "java",
        "source_fingerprint": unit.job.source_fingerprint, "recipe_identity": "recipe",
        "probe_identity": "probe", "build_system": "maven",
        "recipe": {"source_dir": "maven", "image_profile": "java", "configure_commands": [],
                   "build_commands": [["mvn", "-B", "-DskipTests", "package"]], "environment": {}},
        "image": {"family": "java", "image_tag": "fixture:local", "image_id": "sha256:" + "d" * 64,
                  "user": "1000:1000", "dependency_hashes": {}}}
    return unit, dispatch, {"project_build_handoff_sha256": "handoff"}, calls, records


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_jvm_detached_instrumentation_is_not_hashed_on_publication_or_resume(tmp_path, monkeypatch, mode):
    from appsec_review.jobs.job_language_build import job as generic, jvm

    unit, dispatch, accepted, calls, _events = _isolated_jvm_action(tmp_path, monkeypatch, mode)
    supplied = (unit.job.run_root / "data" / "build" / "jvm" / "units" /
                dispatch["build_unit_id"] / "attempts" / unit.job.attempt_id / "instrumentation")
    evidence = supplied.with_name("instrumentation-evidence")
    hashed = []
    original = file_sha256

    def hash_target_or_evidence(path):
        assert not Path(path).resolve().is_relative_to(supplied.resolve())
        hashed.append(Path(path))
        return original(path)

    monkeypatch.setattr(jvm, "file_sha256", hash_target_or_evidence)
    monkeypatch.setattr(generic, "file_sha256", hash_target_or_evidence)

    class Fake(JvmExecutor):
        def execute(self, argv, **kwargs):
            assert kwargs["instrumentation_root"] == supplied
            assert kwargs["instrumentation_evidence_root"] == evidence
            result = super().execute(argv, **kwargs)
            lookalike = kwargs["workspace"] / "maven/.appsec-review-jvm/Customer.java"
            lookalike.parent.mkdir(parents=True, exist_ok=True)
            lookalike.write_text("class Customer {}", encoding="utf-8")
            return result

    first = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: Fake(calls))
    assert not first["checkpoint_reused"]
    assert all(row["artifact_origin"] == "build-output" and row["scope_version"]
               for row in first["artifacts"])
    assert any("delivery_fact_unavailable" in gap for gap in first["gaps"])
    manifest = json.loads((unit.job.run_root / first["workspace_manifest"]["path"]).read_text())
    assert "maven/.appsec-review-jvm/Customer.java" in manifest["files"]
    assert any(row["workspace_path"] == "maven/.appsec-review-jvm/Customer.java" for row in first["artifacts"])
    assert evidence / "invocations.bin" in hashed
    generated = json.loads((unit.job.run_root / first["instrumentation_evidence_manifest"]["path"]).read_text())
    assert any(row["path"].endswith("/invocations.bin") for row in generated["files"])
    # Deliberately changing supplied bytes is outside the customer-evidence integrity contract.
    (supplied / "bin/javac").write_text("operator changed supplied wrapper", encoding="utf-8")
    second = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: Fake(calls))
    assert second["checkpoint_reused"] and len(calls) == 1
    (evidence / "invocations.bin").write_bytes(b"changed customer execution evidence")
    with pytest.raises(JvmIntegrityError, match="instrumentation evidence changed"):
        jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: Fake(calls))


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
@pytest.mark.parametrize("missing", ["platform", "validation", "build_toolchain", "jvm_instrumentation"])
def test_jvm_missing_release_denies_checkpoint_reuse(tmp_path, monkeypatch, mode, missing):
    from appsec_review.jobs.job_language_build import jvm

    unit, dispatch, accepted, calls, events = _isolated_jvm_action(
        tmp_path, monkeypatch, mode, missing=missing)
    original_publications = None
    for _ in range(2):
        receipt = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
        assert not receipt["checkpoint_reused"]
        assert receipt["checkpoint_reuse_reason"] == "missing_release_identity"
        publications = {
            item["path"]: ((unit.job.run_root / item["path"]).read_bytes(),
                           (unit.job.run_root / item["path"]).stat().st_ino)
            for item in (receipt["commands"][0]["protected_argv"], receipt["protected_tool_invocations"])}
        if original_publications is None:
            original_publications = publications
        else:
            assert publications == original_publications
    assert len(calls) == 2
    assert not list(unit.job.metadata_root.rglob("accepted.json"))
    assert sum(event == "CHECKPOINT_MISSED" and value["reason"] == "missing_release_identity"
               for event, value in events) == 2


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
@pytest.mark.parametrize("publication", ["command", "invocations"])
@pytest.mark.parametrize("corruption", ["different-content", "symlink"])
def test_jvm_repeated_protected_publication_rejects_conflicts(
        tmp_path, monkeypatch, mode, publication, corruption):
    from appsec_review.jobs.job_language_build import jvm

    unit, dispatch, accepted, calls, _events = _isolated_jvm_action(
        tmp_path, monkeypatch, mode, missing="jvm_instrumentation")
    receipt = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
    identity = (receipt["commands"][0]["protected_argv"] if publication == "command"
                else receipt["protected_tool_invocations"])
    path = unit.job.run_root / identity["path"]
    previous = path.read_bytes()
    retained = tmp_path / "retained-original.json"
    path.rename(retained)
    if corruption == "symlink":
        path.symlink_to(retained)
    else:
        path.write_bytes(b'{"different":"protected evidence"}\n')
    conflict = path.read_bytes()

    with pytest.raises(ValueError, match="immutable shared artifact conflicts|shared artifact symlink"):
        jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
    assert retained.read_bytes() == previous
    assert path.read_bytes() == conflict
    assert path.is_symlink() is (corruption == "symlink")
    assert not list(unit.job.metadata_root.rglob("accepted.json"))


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
@pytest.mark.parametrize("component", ["platform", "validation", "build_toolchain", "jvm_instrumentation"])
def test_jvm_changed_release_invalidates_family_checkpoint(tmp_path, monkeypatch, mode, component):
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.jobs.job_language_build import jvm

    unit, dispatch, accepted, calls, _events = _isolated_jvm_action(tmp_path, monkeypatch, mode)
    first = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
    declarations = {**unit.job.review_policy.releases.view(), component: "fixture/2"}
    unit.job.review_policy = replace(unit.job.review_policy, releases=ComponentReleases(declarations))
    second = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
    assert first["fingerprint"] != second["fingerprint"]
    assert not second["checkpoint_reused"] and len(calls) == 2


@pytest.mark.parametrize("mode", ["strict", "first_party_managed"])
def test_jvm_delivery_policy_invalidates_family_checkpoint(tmp_path, monkeypatch, mode):
    from appsec_review.jobs.job_language_build import jvm

    unit, dispatch, accepted, calls, _events = _isolated_jvm_action(tmp_path, monkeypatch, mode)
    first = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
    monkeypatch.setattr(jvm, "POLICY_IDENTITY", "fixture-delivery-policy/2")
    second = jvm.execute_jvm_one(unit, dispatch, accepted, lambda *_: JvmExecutor(calls))
    assert first["fingerprint"] != second["fingerprint"]
    assert not second["checkpoint_reused"] and len(calls) == 2


def test_jvm_recipe_validation_rejects_test_and_application_tasks_before_probe() -> None:
    unit = {"build_unit_id": "build-unit-" + "a" * 20, "family": "java", "root": "app",
        "build_system": "gradle", "markers": [{"path": "app/build.gradle"}],
        "descriptor_package": {"documents": [{"path": "app/build.gradle"}]}}
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
        "image_profile": "java", "source_dir": "app", "build_dir": "app/build",
        "system_packages": [], "environment": {}, "dependency_files": ["app/build.gradle"],
        "configure_commands": [], "build_commands": [["gradlew", "run"]],
        "expected_outputs": ["app/build"], "network_required": True, "reason": "unsafe fixture"}
    assert any("execution, tests" in error or "not allowed for java profile" in error
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


def _jvm_settings() -> dict:
    config = load_config(ROOT / "appsec-review.toml")
    return dict(config.job("job_language_build").settings["jvm"])


def test_maven_compilation_is_forked_through_the_instrumented_javac(tmp_path: Path) -> None:
    from appsec_review.jobs.job_language_build.jvm import _environment

    # maven-compiler-plugin defaults to in-process javax.tools compilation, which no wrapper can
    # observe; live runs then reported "nested JVM tool provenance was not emitted".
    recipe = {"image_profile": "java", "source_dir": "projects/java/case-034",
              "build_system": "maven", "environment": {}}
    (tmp_path / "projects" / "java" / "case-034").mkdir(parents=True)
    supplied, evidence = tmp_path / "supplied", tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    environment, _trace = _environment(recipe, workspace, _jvm_settings(),
                                       instrumentation_root=supplied, evidence_root=evidence)
    options = environment["MAVEN_OPTS"].split()
    assert "-Dmaven.compiler.fork=true" in options
    assert "-Dmaven.compiler.executable=/appsec-jvm/bin/javac" in options
    assert "-Dmaven.repo.local=/tmp/appsec-review-maven" in options
    assert "-Dmaven.repo.local.tail=/opt/project-deps/maven" in options
    wrapper = supplied / "bin" / "javac"
    # A root orchestrator runs the container as the profile user, which must execute the wrapper.
    assert wrapper.stat().st_mode & 0o777 == 0o755

    direct, _trace = _environment({**recipe, "build_system": "javac"}, workspace, _jvm_settings(),
                                  instrumentation_root=supplied, evidence_root=evidence)
    assert "maven.compiler.fork" not in direct["MAVEN_OPTS"]


def test_build_system_environment_generalizes_to_multi_module_layouts(tmp_path: Path) -> None:
    """Synthetic multi-module Maven reactor and multi-project Gradle build (not multivuln): the
    environment derives only from build_system and the accepted source root, so every reactor
    module's compiler fork and every Gradle subproject's cache use the same unit-level paths."""
    from appsec_review.jobs.job_language_build.jvm import _environment

    reactor = tmp_path / "services" / "billing"
    for module in ("billing-api", "billing-core", "billing-app"):
        (reactor / module / "src" / "main" / "java").mkdir(parents=True)
        (reactor / module / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (reactor / "pom.xml").write_text("<project><modules><module>billing-api</module>"
                                     "<module>billing-core</module><module>billing-app</module>"
                                     "</modules></project>\n", encoding="utf-8")
    maven = {"image_profile": "java", "source_dir": "services/billing", "build_system": "maven",
             "environment": {"MAVEN_OPTS": "-Xmx1g"}}
    supplied, evidence, workspace = tmp_path / "supplied", tmp_path / "evidence", tmp_path / "workspace"
    workspace.mkdir()
    environment, trace = _environment(maven, workspace, _jvm_settings(),
                                      instrumentation_root=supplied, evidence_root=evidence)
    options = environment["MAVEN_OPTS"].split()
    assert options.count("-Dmaven.compiler.fork=true") == 1 and "-Xmx1g" in options
    assert "-Dmaven.compiler.executable=/appsec-jvm/bin/javac" in options
    assert trace == evidence / "invocations.bin"

    gradle_root = tmp_path / "mobile"
    for project in ("app", "feature-login", "core-network"):
        (gradle_root / project).mkdir(parents=True)
        (gradle_root / project / "build.gradle.kts").write_text("plugins { java }\n", encoding="utf-8")
    (gradle_root / "settings.gradle.kts").write_text(
        'include(":app", ":feature-login", ":core-network")\n', encoding="utf-8")
    gradle = {"image_profile": "java", "source_dir": "mobile", "build_system": "gradle",
              "environment": {}}
    environment, _trace = _environment(gradle, workspace, _jvm_settings(),
                                       instrumentation_root=supplied, evidence_root=evidence)
    assert environment["GRADLE_USER_HOME"] == "/tmp/appsec-review-gradle"
    assert environment["GRADLE_RO_DEP_CACHE"] == "/opt/project-deps/gradle/caches"
    assert "maven.compiler.fork" not in environment["MAVEN_OPTS"]


def test_wrapper_execs_the_image_jdk_when_the_configured_path_is_absent(tmp_path: Path) -> None:
    # The Android image has no /usr/bin/javac; its JDK is only under JAVA_HOME.
    import os
    import subprocess
    from appsec_review.jobs.job_language_build import jvm

    java_home = tmp_path / "jdk"
    (java_home / "bin").mkdir(parents=True)
    real = java_home / "bin" / "javac"
    real.write_text("#!/bin/sh\necho jdk-javac \"$@\"\n", encoding="utf-8")
    real.chmod(0o755)
    trace = tmp_path / "trace"
    trace.mkdir()
    wrapper = tmp_path / "javac"
    wrapper.write_text(jvm._wrapper_script("javac", jvm._resolved_tool("javac", str(tmp_path / "missing"))),
                       encoding="utf-8")
    wrapper.chmod(0o755)
    env = {**os.environ, "APPSEC_JVM_TRACE_DIR": str(trace), "JAVA_HOME": str(java_home)}
    result = subprocess.run([str(wrapper), "-version"], capture_output=True, text=True, env=env, check=False)
    assert result.returncode == 0 and result.stdout.strip() == "jdk-javac -version"
    assert len(list(trace.iterdir())) == 1
    present = tmp_path / "present"
    present.write_text("#!/bin/sh\necho configured\n", encoding="utf-8")
    present.chmod(0o755)
    wrapper.write_text(jvm._wrapper_script("javac", jvm._resolved_tool("javac", str(present))), encoding="utf-8")
    assert subprocess.run([str(wrapper)], capture_output=True, text=True, env=env,
                          check=False).stdout.strip() == "configured"
