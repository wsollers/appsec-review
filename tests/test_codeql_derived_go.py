"""Go CodeQL scopes resolve a derived runtime image under ``preinstalled_undeclared``.

Every Go scope runs CodeQL inside the image recorded by its accepted project-build receipt: the
pinned ``go`` profile image or a per-run customized project image layered on it. Neither has a
``preinstalled_runtimes`` declaration, so the shipped configuration must either derive a runtime
(``derive``) or fail naming the image and effective user (``fail``). These checks use the real
shipped configuration and Dockerfiles and never start Docker.
"""
from dataclasses import replace
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime
from appsec_review.config import load_config
from appsec_review.container_runtime.build_executor import profiles_from_settings
from appsec_review.container_runtime.identity import application_runtime_user
from appsec_review.container_runtime.project_images import (
    ProjectImageResolver, project_dependency_environment,
)
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLScope, SCOPE_SCHEMA
from appsec_review.jobs.job_project_build.repair import REPAIR_ENVIRONMENT
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[1]
CODEQL_TOOL = ROOT / "containers" / "tools" / "codeql"
GO_BUILDENV = ROOT / "containers" / "buildenv" / "go" / "Dockerfile"
NATIVE_TOOLCHAIN = ROOT / "containers" / "buildenv" / "native-toolchain"
BASE_UBUNTU = ROOT / "containers" / "bases" / "ubuntu" / "Dockerfile"
# A per-run customized Go project image has an unpredictable identity; any well-formed id that
# no preinstalled declaration names exercises the same contract.
CUSTOMIZED_GO_ID = "sha256:" + hashlib.sha256(b"customized go project image fixture").hexdigest()
CUSTOMIZED_GO_TAG = "appsec-review-project-go:fixture0000000000000000"
DERIVED_RUNTIME_ID = "sha256:" + "d" * 64


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("go derived-runtime test attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@lru_cache(maxsize=1)
def _shipped():
    return load_config(ROOT / "appsec-review.toml")


def _codeql_settings(policy):
    settings = _shipped().job("job_codeql_analysis").typed_settings
    return replace(settings, preinstalled_undeclared=policy)


def _go_profile():
    return profiles_from_settings(_shipped().job("job_project_build").settings["profiles"])["go"]


def _go_images():
    profile = _go_profile()
    return {"profile": (profile.tag, profile.image_id, profile.user),
            "customized": (CUSTOMIZED_GO_TAG, CUSTOMIZED_GO_ID, profile.user)}


def _resolver(tmp_path, settings, runner=None):
    def unexpected(argv, timeout):
        pytest.fail(f"identity resolution attempted a Docker operation: {argv}")
    return runtime.CodeQLImageResolver(
        repository_root=ROOT, metadata_root=tmp_path / "metadata", settings=settings,
        runner=runner or unexpected, releases=_shipped().review_policy.releases)


def _instructions(path):
    """Dockerfile instructions with continuations joined and comments removed."""
    joined = re.sub(r"\\\n", " ", path.read_text(encoding="utf-8"))
    return [line.strip() for line in joined.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def _env(instructions):
    values = {}
    for line in instructions:
        if line.startswith("ENV "):
            for key, value in re.findall(r"([A-Z_][A-Z0-9_]*)=(\S+)", line[4:]):
                values[key] = value
    return values


def _go_scope():
    entry = {"path": "main.go", "sha256": "a" * 64, "size_bytes": 1}
    return CodeQLScope(SCOPE_SCHEMA, "codeql-unit-" + "9" * 24, "go", ("Go",), "manual", ".",
                       (entry,), "build-unit-go", None, "go-environment", True)


# Shipped configuration and the derive/fail contract.

def test_shipped_go_profile_is_undeclared_and_receipts_carry_the_profile_user():
    settings = _codeql_settings("fail")
    profile = _go_profile()
    declared = {item.build_image_id for item in settings.preinstalled_runtimes}
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", profile.image_id)
    assert profile.image_id not in declared and CUSTOMIZED_GO_ID not in declared
    assert profile.tag == "audit-buildenv-go:local"
    # The project-build receipt records this nominal user; CodeQL resolution receives it.
    assert profile.user == settings.runtime_user == "10001:10001"
    assert "go" in settings.languages and settings.languages["go"].mode == "build"


@pytest.mark.parametrize("kind", ["profile", "customized"])
def test_derive_gives_the_go_image_a_derived_identity_without_docker(tmp_path, kind):
    _tag, image_id, user = _go_images()[kind]
    settings = _codeql_settings("derive")
    releases = _shipped().review_policy.releases.values
    identity = _resolver(tmp_path, settings).declared_identity(build_image_id=image_id, runtime_user=user)
    expected = hashlib.sha256(canonical_json({
        "schema": runtime.IMAGE_SCHEMA, "source_image_id": settings.source_image_id,
        "build_image_id": image_id, "runtime_user": user,
        "component_release_id": releases.get("codeql"),
        "runner_release_id": releases.get("codeql_runner"),
    })).hexdigest()
    assert identity == expected
    # Identical to configuring no preinstalled runtimes at all: derive adds no new identity.
    undeclared = replace(settings, preinstalled_runtimes=())
    assert _resolver(tmp_path, undeclared).declared_identity(
        build_image_id=image_id, runtime_user=user) == identity
    assert _resolver(tmp_path, settings)._preinstalled(build_image_id=image_id, runtime_user=user) is None


def test_go_profile_and_customized_images_derive_distinct_identities(tmp_path):
    resolver = _resolver(tmp_path, _codeql_settings("derive"))
    identities = {resolver.declared_identity(build_image_id=image_id, runtime_user=user)
                  for _tag, image_id, user in _go_images().values()}
    assert len(identities) == 2


@pytest.mark.parametrize("kind", ["profile", "customized"])
def test_fail_rejects_the_undeclared_go_image_naming_image_and_user(tmp_path, kind):
    _tag, image_id, user = _go_images()[kind]
    resolver = _resolver(tmp_path, _codeql_settings("fail"))
    message = (f"build_image_id={image_id}, effective_user={application_runtime_user(user)}")
    with pytest.raises(ValueError, match=re.escape(message)):
        resolver.declared_identity(build_image_id=image_id, runtime_user=user)


class _Events:
    def __init__(self):
        self.records = []

    def write(self, event, **fields):
        self.records.append((event, fields))


class _Stop(Exception):
    pass


class _DerivingDocker:
    """Fakes only the Docker boundary of the plain derived-image build."""

    def __init__(self, images):
        self.images = dict(images)
        self.calls = []

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
            self.images[argv[argv.index("--tag") + 1]] = DERIVED_RUNTIME_ID
            return 0, b"built", b"", False
        pytest.fail(f"unexpected Docker operation: {argv}")


def _unit(tmp_path, settings):
    job = SimpleNamespace(
        events=_Events(), repository_root=ROOT, metadata_root=tmp_path / "metadata",
        run_root=tmp_path / "run", config=SimpleNamespace(typed_settings=settings),
        review_policy=_shipped().review_policy)
    return SimpleNamespace(unit_id="codeql-database-go", job=job)


@pytest.mark.parametrize("kind", ["profile", "customized"])
def test_go_scope_receipt_derives_runtime_through_the_database_job(tmp_path, monkeypatch, kind):
    tag, image_id, user = _go_images()[kind]
    settings = _codeql_settings("derive")
    docker = _DerivingDocker({settings.source_image_tag: settings.source_image_id, tag: image_id})
    monkeypatch.setattr(runtime, "_run", docker)
    monkeypatch.delenv("APPSEC_NATIVE_REQUESTED", raising=False)

    def stop(_root):
        raise _Stop
    monkeypatch.setattr(codeql, "load_asset_lock", stop)
    unit = _unit(tmp_path, settings)
    receipts = {"build-unit-go": {"image": {"image_tag": tag, "image_id": image_id, "user": user}}}
    with pytest.raises(_Stop):
        codeql._database_one(unit, _go_scope(), receipts)

    identity = _resolver(tmp_path, settings).declared_identity(build_image_id=image_id, runtime_user=user)
    base_tag = f"appsec-review-codeql-base:{image_id[7:31]}"
    source_tag = f"appsec-review-codeql-source:{settings.source_image_id[7:31]}"
    assert ("docker", "image", "tag", image_id, base_tag) in docker.calls
    assert ("docker", "image", "tag", settings.source_image_id, source_tag) in docker.calls
    build = next(call for call in docker.calls if call[:3] == ("docker", "buildx", "build"))
    assert build[build.index("--network") + 1] == "none"
    assert build[build.index("--tag") + 1] == f"appsec-review-codeql:{identity[:24]}"
    arguments = {build[index + 1] for index, value in enumerate(build) if value == "--build-arg"}
    assert arguments == {f"BUILD_IMAGE={base_tag}", f"CODEQL_SOURCE_IMAGE={source_tag}",
                         f"RUNTIME_USER={user}"}
    context = Path(build[build.index("--file") + 1]).parent
    assert (context / "Dockerfile").read_bytes() == (CODEQL_TOOL / "Dockerfile").read_bytes()

    resolved = [fields for event, fields in unit.job.events.records if event == "CODEQL_RUNTIME_RESOLVED"]
    assert len(resolved) == 1
    assert resolved[0]["preparation_kind"] == "derived"
    assert resolved[0]["build_image_id"] == image_id
    assert resolved[0]["image_identity"] == identity
    assert resolved[0]["image_id"] == DERIVED_RUNTIME_ID
    assert resolved[0]["requested_runtime_user"] == resolved[0]["runtime_user"] == user
    image = json.loads((tmp_path / "run/data/codeql/scopes" / _go_scope().scope_id / "image.json").read_text())
    assert image["schema"] == runtime.IMAGE_SCHEMA and image["preinstalled"] is False


@pytest.mark.parametrize("kind", ["profile", "customized"])
def test_go_scope_receipt_fails_closed_before_docker_under_fail(tmp_path, monkeypatch, kind):
    tag, image_id, user = _go_images()[kind]
    docker = _DerivingDocker({})
    monkeypatch.setattr(runtime, "_run", docker)
    unit = _unit(tmp_path, _codeql_settings("fail"))
    receipts = {"build-unit-go": {"image": {"image_tag": tag, "image_id": image_id, "user": user}}}
    message = f"build_image_id={image_id}, effective_user={application_runtime_user(user)}"
    with pytest.raises(ValueError, match=re.escape(message)):
        codeql._database_one(unit, _go_scope(), receipts)
    assert not docker.calls
    assert not any(event == "CODEQL_RUNTIME_RESOLVED" for event, _ in unit.job.events.records)


# Static compatibility of containers/tools/codeql/Dockerfile layered on the Go images.

def test_go_profile_image_chain_is_glibc_ubuntu_with_a_non_root_numeric_user():
    go, native, base = (_instructions(path) for path in (
        GO_BUILDENV, NATIVE_TOOLCHAIN / "Dockerfile", BASE_UBUNTU))
    froms = [line for chain in (go, native, base) for line in chain if line.startswith("FROM ")]
    assert froms == ["FROM appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1",
                     "FROM appsec-review/base-ubuntu:24.04",
                     "FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3"]
    text = "\n".join(GO_BUILDENV.read_text().splitlines() + (NATIVE_TOOLCHAIN / "Dockerfile").read_text()
                     .splitlines() + BASE_UBUNTU.read_text().splitlines()).lower()
    assert "alpine" not in text and "musl" not in text
    # The CodeQL bundle is linux64/glibc and the runner entrypoint is python3.
    lock = (NATIVE_TOOLCHAIN / "packages.lock").read_text().splitlines()
    assert any(line.startswith("libc6-dev=2.39-") for line in lock)
    assert any(line.startswith("python3=") for line in lock)
    assert any(line.startswith("bash=") for line in lock)
    users = [line for line in go if line.startswith("USER ")]
    assert users[-1] == "USER 10001:10001"
    # The derived image's WORKDIR /scratch already exists and belongs to the image user.
    assert "mkdir -p /workspace /scratch" in " ".join(base)
    assert "chown 10001:10001 /scratch" in " ".join(base)


def test_go_profile_keeps_a_local_pinned_toolchain_and_no_image_root_go_caches():
    instructions = _instructions(GO_BUILDENV)
    environment = _env(instructions)
    assert environment["GOTOOLCHAIN"] == "local"
    path = environment["PATH"].split(":")
    assert path[0] == "/usr/lib/go-1.23/bin" and {"/usr/bin", "/bin"} <= set(path)
    assert any("golang-1.23-go=1.23.1-1~24.04.1" in line for line in instructions)
    assert any("grep -F 'go1.23.1 linux/amd64'" in line for line in instructions)
    # Module and build caches default beneath HOME, which the CodeQL executor and runner point at
    # writable /tmp; none may resolve into the read-only image root.
    for chain in (environment, _env(_instructions(NATIVE_TOOLCHAIN / "Dockerfile")),
                  _env(_instructions(BASE_UBUNTU))):
        assert not {"GOPATH", "GOCACHE", "GOMODCACHE", "GOFLAGS", "GOPROXY", "GOROOT"} & set(chain)
        assert chain.get("HOME", "/tmp") == "/tmp"


def test_codeql_layer_runs_as_root_only_to_install_and_keeps_the_go_path():
    instructions = _instructions(CODEQL_TOOL / "Dockerfile")
    assert instructions[:3] == ["ARG CODEQL_SOURCE_IMAGE", "ARG BUILD_IMAGE",
                                "FROM ${CODEQL_SOURCE_IMAGE} AS codeql_source"]
    final = instructions[instructions.index("FROM ${BUILD_IMAGE}"):]
    assert final[1] == "ARG RUNTIME_USER=10001:10001" and final[2] == "USER 0:0"
    root_steps = final[2:final.index("USER ${RUNTIME_USER}")]
    assert any(line.startswith("COPY --from=codeql_source /opt/codeql") for line in root_steps)
    assert any(line.startswith("RUN chmod -R a+rX /opt/codeql") for line in root_steps)
    # PATH is prepended, never replaced, so /usr/lib/go-1.23/bin stays visible to the tracer.
    assert "ENV PATH=/opt/codeql:${PATH}" in final
    assert set(_env(final)) == {"PATH"}
    assert final[-2:] == ["USER ${RUNTIME_USER}", "WORKDIR /scratch"]
    assert not any(line.startswith(("ENTRYPOINT", "CMD")) for line in final)


def test_codeql_pins_ship_a_go_extractor_for_the_configured_version():
    lock = json.loads((CODEQL_TOOL / "assets.lock.json").read_text(encoding="utf-8"))
    settings = _codeql_settings("derive")
    assert lock["codeql"]["version"] == "2.27.0"
    assert lock["source_image"]["image_id"] == settings.source_image_id
    assert lock["source_image"]["tag"] == settings.source_image_tag
    assert re.fullmatch(r"[0-9a-f]{64}", lock["extractors"]["go"]["tree_sha256"])
    assert lock["extractors"]["go"]["file_count"] > 0
    bundle = (CODEQL_TOOL / "Dockerfile.bundle").read_text(encoding="utf-8")
    assert "codeql-bundle-linux64" in bundle


def test_catalog_probe_matches_the_shipped_go_profile():
    catalog = tomllib.loads((ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8"))
    image = next(item for item in catalog["images"] if item["id"] == "audit-buildenv-go")
    profile = _go_profile()
    assert image["tag"] == profile.tag
    assert "go1.23.1 linux/amd64" in image["probe_expect"]
    assert profile.user.split(":", 1)[0] in image["probe_expect"]


def test_customized_go_image_stays_on_the_profile_with_bounded_go_environment(tmp_path):
    profile = _go_profile()
    recipe = {"build_system": "go", "source_dir": ".", "dependency_files": ["go.mod", "go.sum"],
              "network_required": True, "system_packages": ["libpcap-dev"],
              "image_repairs": {"environment": {"GOFLAGS": "-mod=mod -buildvcs=false",
                                                "CGO_ENABLED": "1"}}}
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=tmp_path)
    _identity, dockerfile = resolver._definition(recipe, profile, {"go.mod": "a" * 64, "go.sum": "b" * 64})
    lines = dockerfile.decode().splitlines()
    assert lines[0] == f"FROM {profile.tag}"
    assert [line for line in lines if line.startswith("USER ")] == ["USER 0:0", f"USER {profile.user}"]
    assert "ENV GOMODCACHE=/opt/project-deps/go" in lines
    assert 'ENV GOFLAGS="-mod=mod -buildvcs=false"' in lines
    assert 'RUN ["go","mod","download"]' in lines
    assert not any(line.startswith(("ENV PATH", "ENV GOTOOLCHAIN", "ENV GOROOT")) for line in lines)
    assert project_dependency_environment(recipe) == {"GOMODCACHE": "/opt/project-deps/go"}
    assert set(REPAIR_ENVIRONMENT["go"]) == {"GOFLAGS", "CGO_ENABLED"}
    assert REPAIR_ENVIRONMENT["go"]["GOFLAGS"].fullmatch("-mod=vendor")
    assert not REPAIR_ENVIRONMENT["go"]["GOFLAGS"].fullmatch("-toolexec=/bin/sh")
