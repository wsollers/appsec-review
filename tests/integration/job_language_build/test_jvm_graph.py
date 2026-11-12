"""job_language_build JVM family: the pre-walk whole-graph suite, moved out of the unit path by T-113.

Every case runs the intake, catalog, plan, project-build and language-build jobs through
GraphRunner with fake executors and image resolvers. They are integration tests pending
replacement by the code-level tests in tests/unit/job_language_build/ and run only when named
explicitly (``scripts/run-tests.sh --allow-heavy -- <file>``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime import ProjectImage
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.build_discovery import validate_build_recipe
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult, check_models, infer
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan, load_accepted_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import IndexIdentity, RetrievalCore, write_manifest
from appsec_review.runtime import GraphRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.capture_fakes import capturing_fake

from tests.unit.job_language_build.test_jvm import JvmExecutor, ROOT, _declare_fixture_releases, _fixture


pytestmark = pytest.mark.time_budget(
    1800, reason="pre-walk whole-graph suite (T-113): each case runs the build jobs through GraphRunner; "
                 "kept for integration until its claims are covered by code-level tests")


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
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
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
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["terminal_status"] == "SUCCEEDED" and receipt["family"] == "java"
    assert any("delivery_fact_unavailable" in gap for gap in receipt["gaps"])
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
    graph = plan["build_topology"]["executable_graph"]
    assert any(binding["subject"] == ":app" and binding["stage"] == "module_declaration"
               for binding in graph["bindings"])
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
    assert any(gap.startswith("Android dex task :app:mergeDexDebug ran D8 in-process inside Gradle")
               for gap in receipt["gaps"])
    assert not any("not emitted" in gap or "did not report" in gap for gap in receipt["gaps"])
    (dex,) = receipt["declared_compilations"]
    assert dex["tool"] == "d8" and dex["evidence_kind"] == "build-tool-declared"
    assert "declared_arguments" not in dex and dex["declared_arguments_sha256"]
    assert calls.count(("gradle", "--no-daemon", ":app:assembleDebug")) == 0
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
    assert second_by_root["sibling"]["workspace"] == first_by_root["sibling"]["workspace"]
    assert second_by_root["sibling"]["attempt_id"] != first_by_root["sibling"]["attempt_id"]
    successful = next(item for item in resumed if item["root"] == "maven")
    artifact = config.runtime.runs_dir / run_id / successful["artifacts"][0]["path"]
    artifact.write_bytes(b"tampered")
    from appsec_review.jobs.build_workspace import ReconstructionMiss
    with pytest.raises(ReconstructionMiss, match="retained file is missing or changed"):
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
