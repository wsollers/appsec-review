"""Java/Kotlin and Android CodeQL scopes derive a runtime layered on their accepted build image.

Run 2026-10-29-0002 failed every ``java`` scope because the shipped preinstalled-runtime
declarations cover only the CodeQL source image and the native build image. These tests load the
shipped configuration, change only ``preinstalled_undeclared``, and prove which (image, user)
pair a java/android scope requests, that the pair derives (or fails closed naming it), and that
the derived Dockerfile is statically compatible with the pinned java and android environments.
No Docker or other process runs; the Docker CLI boundary is faked where resolution needs it.
"""
from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime
from appsec_review.config import load_config
from appsec_review.container_runtime.build_executor import BuildProfile, profiles_from_settings
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.container_runtime.project_images import (
    SCHEMA as PROJECT_IMAGE_SCHEMA, ProjectImage, ProjectImageResolver,
)
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.planning import SCOPE_SCHEMA, CodeQLScope
from appsec_review.jobs.job_project_build.job import _image_dict, _probe_environment
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[1]
CODEQL_TOOL = ROOT / "containers" / "tools" / "codeql"
BUILDENV = ROOT / "containers" / "buildenv"
PROFILES = ("java", "android")
NUMERIC_NON_ROOT = re.compile(r"[1-9][0-9]*:[1-9][0-9]*")


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("java CodeQL derivation test attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    for key in [key for key in os.environ if key.startswith("APPSEC_NATIVE_")]:
        monkeypatch.delenv(key)


@pytest.fixture(scope="module")
def shipped():
    return load_config(ROOT / "appsec-review.toml", profile="copilot-prod",
                       overlay=ROOT / "test" / "acceptance" / "prod-capacity-overlay.toml")


def profiles(config) -> dict[str, BuildProfile]:
    return profiles_from_settings(config.job("job_project_build").settings["profiles"])


def codeql_settings(config, policy: str):
    return dataclasses.replace(config.job("job_codeql_analysis").typed_settings,
                               preinstalled_undeclared=policy)


def receipt_image(config, name: str, customized: bool) -> dict:
    """The receipt ``image`` the project-build job records for a java/android build unit."""
    profile = profiles(config)[name]
    if customized:
        # A dependency-bearing or image-repaired project image: a new local id and tag, same user.
        tag = f"appsec-review-project-{name}:{'c' * 24}"
        image_id = "sha256:" + hashlib.sha256(f"customized-{name}".encode()).hexdigest()
    else:
        tag, image_id = profile.tag, profile.image_id
    image = ProjectImage(PROJECT_IMAGE_SCHEMA, "f" * 64, profile.name, profile.image_id, tag, image_id,
                         "d" * 64 if customized else None, customized, False, {})
    return _image_dict(image, profile.user)


def resolver(config, policy: str, tmp_path: Path, runner=None, settings=None):
    def no_runner(argv, timeout):
        pytest.fail(f"identity derivation must not run Docker: {argv}")
    return runtime.CodeQLImageResolver(
        repository_root=ROOT, metadata_root=tmp_path / "metadata",
        settings=settings or codeql_settings(config, policy), runner=runner or no_runner,
        releases=config.review_policy.releases)


def instructions(path: Path) -> list[tuple[str, str]]:
    """Dockerfile instructions with continuation lines joined; comments and directives dropped."""
    result, pending = [], ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        text = pending + line
        pending = ""
        keyword, _, rest = text.partition(" ")
        result.append((keyword.upper(), rest.strip()))
    assert not pending
    return result


def environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for keyword, rest in instructions(path):
        if keyword == "ENV":
            values.update(item.split("=", 1) for item in shlex.split(rest))
    return values


def final_stage(path: Path) -> list[tuple[str, str]]:
    items = instructions(path)
    start = max(index for index, (keyword, _) in enumerate(items) if keyword == "FROM")
    return items[start:]


ENVIRONMENTS = [(name, customized) for name in PROFILES for customized in (False, True)]
ENVIRONMENT_IDS = [f"{name}-{'customized' if customized else 'profile'}" for name, customized in ENVIRONMENTS]


def test_shipped_java_and_android_images_are_undeclared_numeric_non_root(shipped):
    settings = shipped.job("job_codeql_analysis").typed_settings
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    # Declarations exist, so the undeclared policy decides every java scope's runtime.
    assert declared
    java = settings.languages["java"]
    assert java.enabled and java.mode.value == "build"
    assert {"Java", "Kotlin"} <= set(java.source_languages)
    for name in PROFILES:
        profile = profiles(shipped)[name]
        assert NUMERIC_NON_ROOT.fullmatch(profile.user)
        assert profile.image_id not in declared
        assert profile.image_id != settings.source_image_id
    releases = shipped.review_policy.releases.values
    assert releases.get("codeql") and releases.get("codeql_runner")


@pytest.mark.parametrize("name,customized", ENVIRONMENTS, ids=ENVIRONMENT_IDS)
def test_derive_policy_selects_derived_identity_for_the_job_user(shipped, tmp_path, name, customized):
    image = receipt_image(shipped, name, customized)
    assert image["user"] == profiles(shipped)[name].user
    settings = codeql_settings(shipped, "derive")
    identity = resolver(shipped, "derive", tmp_path).declared_identity(
        build_image_id=image["image_id"], runtime_user=image["user"])
    releases = shipped.review_policy.releases.values
    assert identity == hashlib.sha256(canonical_json({
        "schema": runtime.IMAGE_SCHEMA, "source_image_id": settings.source_image_id,
        "build_image_id": image["image_id"], "runtime_user": image["user"],
        "component_release_id": releases.get("codeql"),
        "runner_release_id": releases.get("codeql_runner"),
    })).hexdigest()
    undeclared = dataclasses.replace(settings, preinstalled_runtimes=())
    assert resolver(shipped, "derive", tmp_path, settings=undeclared).declared_identity(
        build_image_id=image["image_id"], runtime_user=image["user"]) == identity


@pytest.mark.parametrize("name,customized", ENVIRONMENTS, ids=ENVIRONMENT_IDS)
def test_fail_policy_names_the_undeclared_image_and_effective_user(shipped, tmp_path, name, customized):
    image = receipt_image(shipped, name, customized)
    with pytest.raises(ValueError) as error:
        resolver(shipped, "fail", tmp_path).declared_identity(
            build_image_id=image["image_id"], runtime_user=image["user"])
    message = str(error.value)
    assert f"build_image_id={image['image_id']}" in message
    assert f"effective_user={application_runtime_user(image['user'])}" in message


class FakeDocker:
    """The Docker CLI boundary for local derived-image preparation; nothing else is allowed."""

    def __init__(self, images: dict[str, str]):
        self.images = dict(images)
        self.calls: list[tuple[str, ...]] = []
        self.built: str | None = None

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        assert timeout > 0
        if argv[:3] == ("docker", "image", "inspect"):
            image = self.images.get(argv[3])
            return (0, (image + "\n").encode(), b"", False) if image else (1, b"", b"missing", False)
        if argv[:3] == ("docker", "image", "tag"):
            self.images[argv[4]] = argv[3]
            return 0, b"", b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            tag = argv[argv.index("--tag") + 1]
            self.built = "sha256:" + hashlib.sha256(tag.encode()).hexdigest()
            self.images[tag] = self.built
            return 0, b"built", b"", False
        pytest.fail(f"unexpected Docker operation: {argv}")


class Events:
    def __init__(self):
        self.records: list[tuple[str, dict]] = []

    def write(self, event_type, **fields):
        self.records.append((event_type, fields))


class StopAfterResolution(Exception):
    pass


def java_unit(shipped, tmp_path, policy):
    events = Events()
    job = SimpleNamespace(events=events, repository_root=ROOT, metadata_root=tmp_path / "metadata",
                          run_root=tmp_path / "run", config=SimpleNamespace(
                              typed_settings=codeql_settings(shipped, policy)),
                          review_policy=shipped.review_policy)
    return SimpleNamespace(unit_id="codeql-java-fixture", job=job), events


def java_scope() -> CodeQLScope:
    return CodeQLScope(SCOPE_SCHEMA, "java-scope-fixture", "java", ("Java", "Kotlin"), "manual", "app", (),
                       "build-unit-java", "e" * 64, "f" * 64, True)


@pytest.mark.parametrize("name,customized", ENVIRONMENTS, ids=ENVIRONMENT_IDS)
def test_database_job_derives_runtime_on_the_receipt_image(monkeypatch, shipped, tmp_path, name, customized):
    settings = codeql_settings(shipped, "derive")
    image = receipt_image(shipped, name, customized)
    docker = FakeDocker({settings.source_image_tag: settings.source_image_id,
                         image["image_tag"]: image["image_id"]})
    monkeypatch.setattr(runtime, "_run", docker)
    resolved = []
    original = codeql._resolve_image

    def stop_after_resolution(*args, **kwargs):
        resolved.append((kwargs, original(*args, **kwargs)[0]))
        raise StopAfterResolution
    monkeypatch.setattr(codeql, "_resolve_image", stop_after_resolution)
    unit, events = java_unit(shipped, tmp_path, "derive")
    scope = java_scope()

    with pytest.raises(StopAfterResolution):
        codeql._database_one(unit, scope, {scope.build_unit_id: {"image": image}})

    [(request, derived)] = resolved
    # A customized project image is derived and unsigned; its pinned base carries the signature.
    assert request == {"build_image_tag": image["image_tag"], "build_image_id": image["image_id"],
                       "runtime_user": image["user"], "scope_id": scope.scope_id,
                       "build_image_derived_from": image["base_image_id"] if customized else None}
    identity = resolver(shipped, "derive", tmp_path).declared_identity(
        build_image_id=image["image_id"], runtime_user=image["user"])
    assert (derived.schema, derived.identity, derived.preinstalled) == (runtime.IMAGE_SCHEMA, identity, False)
    assert (derived.build_image_id, derived.build_image_tag) == (image["image_id"], image["image_tag"])
    assert derived.runtime_user == image["user"] and derived.image_build_performed is True
    assert derived.image_tag == f"appsec-review-codeql:{identity[:24]}" and derived.image_id == docker.built

    source_tag = f"appsec-review-codeql-source:{settings.source_image_id[7:31]}"
    base_tag = f"appsec-review-codeql-base:{image['image_id'][7:31]}"
    assert ("docker", "image", "tag", settings.source_image_id, source_tag) in docker.calls
    assert ("docker", "image", "tag", image["image_id"], base_tag) in docker.calls
    [build] = [call for call in docker.calls if call[:3] == ("docker", "buildx", "build")]
    assert build[build.index("--network") + 1] == "none" and "--pull=false" in build
    arguments = {build[index + 1] for index, value in enumerate(build) if value == "--build-arg"}
    assert arguments == {f"CODEQL_SOURCE_IMAGE={source_tag}", f"BUILD_IMAGE={base_tag}",
                         f"RUNTIME_USER={image['user']}"}
    context = tmp_path / "metadata" / "codeql-images" / identity / "context"
    assert (context / "Dockerfile").read_bytes() == (CODEQL_TOOL / "Dockerfile").read_bytes()
    assert (context / "codeql_runner.py").read_bytes() == (CODEQL_TOOL / "codeql_runner.py").read_bytes()

    [resolution] = [fields for event, fields in events.records if event == "CODEQL_RUNTIME_RESOLVED"]
    assert resolution["preparation_kind"] == "derived"
    assert resolution["requested_runtime_user"] == image["user"]
    assert resolution["build_image_id"] == image["image_id"]


def test_database_job_fails_closed_before_docker_under_fail_policy(monkeypatch, shipped, tmp_path):
    image = receipt_image(shipped, "android", True)
    docker = FakeDocker({})
    monkeypatch.setattr(runtime, "_run", docker)
    unit, _events = java_unit(shipped, tmp_path, "fail")
    scope = java_scope()
    with pytest.raises(ValueError, match=re.escape(f"build_image_id={image['image_id']}")):
        codeql._database_one(unit, scope, {scope.build_unit_id: {"image": image}})
    assert docker.calls == []


def test_codeql_layer_preserves_the_build_environment_and_runs_as_the_requested_user():
    dockerfile = CODEQL_TOOL / "Dockerfile"
    items = instructions(dockerfile)
    assert [keyword for keyword, _ in items] == [
        "ARG", "ARG", "FROM", "FROM", "ARG", "USER", "COPY", "COPY", "RUN", "ENV", "USER", "WORKDIR"]
    stage = final_stage(dockerfile)
    assert stage[0] == ("FROM", "${BUILD_IMAGE}")
    assert ("ARG", "RUNTIME_USER=10001:10001") in stage
    assert stage[-2:] == [("USER", "${RUNTIME_USER}"), ("WORKDIR", "/scratch")]
    # Only PATH is changed, so JAVA_HOME, ANDROID_*, GRADLE_* and MAVEN_* of the base survive.
    assert environment(dockerfile) == {"PATH": "/opt/codeql:${PATH}"}
    assert not {"ENTRYPOINT", "CMD", "SHELL"} & {keyword for keyword, _ in items}
    # The single shell-form RUN needs only /bin/sh and coreutils chmod from the build image.
    [run] = [rest for keyword, rest in items if keyword == "RUN"]
    assert {command.split()[0] for command in run.split("&&")} == {"chmod"}
    # The runner starts through the build image's python3 under the effective non-root uid.
    executor = inspect.getsource(runtime.CodeQLExecutor._execute)
    assert '"--entrypoint", "python3"' in executor and '"--workdir", "/scratch"' in executor


@pytest.mark.parametrize("name", PROFILES)
def test_java_and_android_build_images_support_the_codeql_layer(shipped, name):
    dockerfile = BUILDENV / name / "Dockerfile"
    profile = profiles(shipped)[name]
    stage = final_stage(dockerfile)
    base = stage[0][1]
    # The CodeQL linux64 bundle and its JDK need glibc; musl/distroless bases break it.
    assert re.fullmatch(r"(ubuntu:24\.04|eclipse-temurin:[0-9]+-jdk-noble)@sha256:[0-9a-f]{64}", base)
    assert not re.search(r"alpine|musl|distroless|busybox", base)
    runs = " ".join(rest for keyword, rest in stage if keyword == "RUN")
    for package in ("bash=", "coreutils=", "python3="):
        assert package in runs
    assert re.search(r"chown -R " + re.escape(profile.user) + r" [^&]*/scratch", runs)
    assert [rest for keyword, rest in stage if keyword == "USER"][-1] == profile.user
    values = environment(dockerfile)
    assert values["JAVA_HOME"] and values["HOME"] == "/tmp"
    assert "/usr/bin" in values["PATH"].split(":")
    if name == "java":
        assert "-Dorg.gradle.native=false" in values["GRADLE_OPTS"]
        assert "ln -s /opt/kotlin/kotlinc/bin/kotlinc /usr/bin/kotlinc" in runs
    else:
        assert values["ANDROID_HOME"] == values["ANDROID_SDK_ROOT"] == "/opt/android-sdk"
        assert values["GRADLE_USER_HOME"] == "/opt/gradle-user-home"
        assert f"{values['JAVA_HOME']}/bin" in values["PATH"].split(":")
        assert "libc6=" in runs


RECIPES = {
    "java": ({"source_dir": ".", "build_system": "maven", "dependency_files": ["pom.xml"],
              "configure_commands": [], "build_commands": [["mvn", "-B", "-DskipTests", "package"]],
              "system_packages": ["zip"], "network_required": True},
             "ENV MAVEN_OPTS=-Dmaven.repo.local=/opt/project-deps/maven"),
    "android": ({"source_dir": ".", "build_system": "gradle",
                 "dependency_files": ["build.gradle", "settings.gradle"],
                 "configure_commands": [], "build_commands": [["gradle", "--no-daemon", "assembleDebug"]],
                 "system_packages": [], "network_required": True},
                "ENV GRADLE_USER_HOME=/opt/project-deps/gradle"),
}


@pytest.mark.parametrize("name", PROFILES)
def test_customized_project_images_keep_the_profile_os_and_user(shipped, tmp_path, name):
    recipe, dependency_env = RECIPES[name]
    target = tmp_path / "target"
    target.mkdir()
    for relative in recipe["dependency_files"]:
        (target / relative).write_text("fixture\n", encoding="utf-8")
    profile = profiles(shipped)[name]
    _identity, dockerfile = ProjectImageResolver(
        metadata_root=tmp_path / "metadata", target_root=target).definition(recipe, profile)
    lines = dockerfile.decode().splitlines()
    assert lines[0] == f"FROM {profile.tag}"
    assert [line for line in lines if line.startswith("FROM ")] == lines[:1]
    assert [line for line in lines if line.startswith("USER ")][-1] == f"USER {profile.user}"
    assert all(line.startswith("RUN [") for line in lines if line.startswith("RUN"))
    assert dependency_env in lines


def test_replayed_jvm_build_environment_writes_only_tmp_and_reads_image_caches():
    maven = _probe_environment({"environment": {}, "source_dir": ".", "build_system": "maven"})
    assert maven["MAVEN_OPTS"].split() == ["-Dmaven.repo.local=/tmp/appsec-review-maven",
                                           "-Dmaven.repo.local.tail=/opt/project-deps/maven"]
    gradle = _probe_environment({"environment": {}, "source_dir": ".", "build_system": "gradle"})
    assert gradle["GRADLE_USER_HOME"] == "/tmp/appsec-review-gradle"
    assert gradle["GRADLE_RO_DEP_CACHE"] == "/opt/project-deps/gradle/caches"


def test_android_codeql_replay_keeps_gradle_home_executable(tmp_path):
    environment = _probe_environment({"environment": {}, "source_dir": ".", "build_system": "gradle"})
    assert environment["GRADLE_USER_HOME"].startswith("/tmp/")
    command = ["gradle", "--no-daemon", "assembleDebug"]
    (tmp_path / "protected-replay.json").write_text(json.dumps({
        "schema": "appsec-review/codeql-build-replay/1",
        "commands": [{"ordinal": 1, "argv": command, "working_directory": ".",
                      "environment": environment}]}), encoding="utf-8")
    # The replayed Gradle home lives on /tmp, so the executor must mount /tmp executable.
    assert runtime.replay_needs_executable_tmp(tmp_path, ("--replay", "protected-replay.json"))
