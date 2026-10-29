"""Native, Rust and customized project images under the shipped CodeQL runtime declarations.

These checks load the real ``appsec-review.toml`` and only override ``preinstalled_undeclared``.
They never start Docker: identity derivation is pure, and resolution uses a fake inspector that
stops at the bounded image builder boundary.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tomllib
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime
from appsec_review.config import load_config
from appsec_review.container_runtime.build_executor import BuildProfile
from appsec_review.container_runtime.project_images import ProjectImageResolver
from appsec_review.jobs.job_codeql_analysis import job as codeql
from appsec_review.jobs.job_codeql_analysis import planning
from appsec_review.jobs.job_codeql_analysis.planning import CodeQLScope, SCOPE_SCHEMA
from appsec_review.storage import canonical_json


ROOT = Path(__file__).resolve().parents[1]
EFFECTIVE_USER = "1000:1000"
RECEIPT_USER = "10001:10001"
# Review run 2026-10-29-0002, cpp manual scope at projects/python-package/case-085.
CUSTOMIZED_TAG = "appsec-review-project-python:d94589bbb022fa31a80e772e"
CUSTOMIZED_ID = "sha256:2dd6083f53a09838e1cb1c5ea32a219384c30fe7dc5d4750daddc7ac64c3a235"
SYNTHETIC_NATIVE_CUSTOMIZED_ID = "sha256:" + "c" * 64
GLIBC_UBUNTU = re.compile(r"ubuntu:24\.04@sha256:[0-9a-f]{64}")


class BuilderReached(Exception):
    pass


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("native derive fixture attempted an external process")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(runtime, "_run", lambda *args, **kwargs: pytest.fail("unexpected Docker call"))
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _fallback: EFFECTIVE_USER)
    monkeypatch.delenv("APPSEC_REVIEW_PROFILE", raising=False)
    monkeypatch.delenv("APPSEC_REVIEW_CONFIG_OVERLAY", raising=False)
    for name in [name for name in os.environ if name.startswith("APPSEC_NATIVE_")]:
        monkeypatch.delenv(name)


@pytest.fixture(scope="module")
def shipped():
    return load_config(ROOT / "appsec-review.toml", profile="dev", overlay="")


def _settings(shipped, policy):
    return replace(shipped.job("job_codeql_analysis").typed_settings, preinstalled_undeclared=policy)


def _profiles(shipped):
    return shipped.job("job_project_build").settings["profiles"]


def _resolver(shipped, tmp_path, policy, *, runner=None, settings=None):
    return runtime.CodeQLImageResolver(
        repository_root=ROOT, metadata_root=tmp_path / "metadata",
        settings=settings or _settings(shipped, policy), releases=shipped.review_policy.releases,
        runner=runner or (lambda *args: pytest.fail("declared identity must not call Docker")))


def _derived_identity(shipped, build_image_id, runtime_user):
    settings = shipped.job("job_codeql_analysis").typed_settings
    releases = shipped.review_policy.releases.values
    return hashlib.sha256(canonical_json({
        "schema": runtime.IMAGE_SCHEMA, "source_image_id": settings.source_image_id,
        "build_image_id": build_image_id, "runtime_user": runtime_user,
        "component_release_id": releases.get("codeql"),
        "runner_release_id": releases.get("codeql_runner"),
    })).hexdigest()


def _declaration(shipped, build_image_id):
    settings = shipped.job("job_codeql_analysis").typed_settings
    matches = [item for item in settings.preinstalled_runtimes if item.build_image_id == build_image_id]
    assert len(matches) == 1
    return matches[0]


def test_shipped_native_declaration_matches_the_native_profile(shipped):
    native = _profiles(shipped)["native"]
    declaration = _declaration(shipped, native["image_id"])
    assert declaration.runner_source == "application"
    assert declaration.runtime_user == EFFECTIVE_USER
    assert shipped.job("job_codeql_analysis").typed_settings.preinstalled_undeclared == "fail"


@pytest.mark.parametrize("policy", ["fail", "derive"])
def test_native_profile_stays_preinstalled_under_either_policy(shipped, tmp_path, policy):
    native = _profiles(shipped)["native"]
    declaration = _declaration(shipped, native["image_id"])
    releases = shipped.review_policy.releases.values
    expected = hashlib.sha256(canonical_json({
        "schema": runtime.PREINSTALLED_IMAGE_SCHEMA,
        "source_image_id": declaration.source_image_id, "build_image_id": native["image_id"],
        "runtime_user": declaration.runtime_user,
        "component_release_id": releases.get("codeql"), "runner_release_id": releases.get("codeql_runner"),
        "preinstalled": asdict(declaration),
    })).hexdigest()
    identity = _resolver(shipped, tmp_path, policy).declared_identity(
        build_image_id=native["image_id"], runtime_user=native["user"])
    assert identity == expected
    assert identity != _derived_identity(shipped, native["image_id"], native["user"])


def _undeclared_images(shipped):
    profiles = _profiles(shipped)
    return {
        "rust": (profiles["rust"]["image_id"], profiles["rust"]["user"]),
        "wasm": (profiles["wasm"]["image_id"], profiles["wasm"]["user"]),
        "python": (profiles["python"]["image_id"], profiles["python"]["user"]),
        "customized-python-case-085": (CUSTOMIZED_ID, RECEIPT_USER),
        "customized-native": (SYNTHETIC_NATIVE_CUSTOMIZED_ID, RECEIPT_USER),
    }


@pytest.mark.parametrize("name", ["rust", "wasm", "python", "customized-python-case-085",
                                  "customized-native"])
def test_undeclared_native_family_images_derive_with_image_schema(shipped, tmp_path, name):
    image_id, user = _undeclared_images(shipped)[name]
    declared = {item.build_image_id
                for item in shipped.job("job_codeql_analysis").typed_settings.preinstalled_runtimes}
    assert image_id not in declared
    identity = _resolver(shipped, tmp_path, "derive").declared_identity(
        build_image_id=image_id, runtime_user=user)
    assert identity == _derived_identity(shipped, image_id, user)


@pytest.mark.parametrize("name", ["rust", "wasm", "customized-python-case-085", "customized-native"])
def test_undeclared_native_family_images_fail_closed_naming_image_and_user(shipped, tmp_path, name):
    image_id, user = _undeclared_images(shipped)[name]
    with pytest.raises(ValueError) as caught:
        _resolver(shipped, tmp_path, "fail").declared_identity(build_image_id=image_id, runtime_user=user)
    assert f"build_image_id={image_id}" in str(caught.value)
    assert f"effective_user={EFFECTIVE_USER}" in str(caught.value)


def test_declared_native_image_with_other_effective_user_never_derives(shipped, tmp_path, monkeypatch):
    native = _profiles(shipped)["native"]
    monkeypatch.setattr(runtime, "application_runtime_user", lambda _fallback: "1001:1001")
    with pytest.raises(ValueError, match="effective_user=1001:1001"):
        _resolver(shipped, tmp_path, "derive").declared_identity(
            build_image_id=native["image_id"], runtime_user=native["user"])


def test_native_application_runner_still_rejects_native_execution_under_derive(shipped, tmp_path,
                                                                               monkeypatch):
    native = _profiles(shipped)["native"]
    monkeypatch.setenv("APPSEC_NATIVE_EXECUTION", "1")
    with pytest.raises(ValueError, match="native execution"):
        _resolver(shipped, tmp_path, "derive").declared_identity(
            build_image_id=native["image_id"], runtime_user=native["user"])


class InspectOnlyDocker:
    def __init__(self, shipped):
        settings = shipped.job("job_codeql_analysis").typed_settings
        native = _profiles(shipped)["native"]
        declaration = _declaration(shipped, native["image_id"])
        self.images = {
            settings.source_image_tag: settings.source_image_id,
            native["tag"]: native["image_id"],
            declaration.runtime_image_id: declaration.runtime_image_id,
            CUSTOMIZED_TAG: CUSTOMIZED_ID,
        }
        self.calls = []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        assert argv[:3] == ("docker", "image", "inspect"), argv
        image = self.images.get(argv[3])
        return (0, (image + "\n").encode(), b"", False) if image else (1, b"", b"missing", False)


class Events:
    def __init__(self):
        self.records = []

    def write(self, event_type, **fields):
        self.records.append((event_type, fields))


def _unit(shipped, tmp_path, policy):
    job = SimpleNamespace(
        config=SimpleNamespace(typed_settings=_settings(shipped, policy)), events=Events(),
        repository_root=ROOT, metadata_root=tmp_path / "metadata", run_root=tmp_path / "run",
        review_policy=shipped.review_policy)
    return SimpleNamespace(unit_id="codeql-native-fixture", job=job)


def _case_085_scope():
    return CodeQLScope(
        SCOPE_SCHEMA, "codeql-unit-" + "0" * 24, "cpp", ("C", "C++"), "manual",
        "projects/python-package/case-085", ({"path": "projects/python-package/case-085/ext.c"},),
        "build-unit-case-085", "f" * 64, "e" * 64, True)


def _case_085_receipts():
    return {"build-unit-case-085": {"image": {
        "image_tag": CUSTOMIZED_TAG, "image_id": CUSTOMIZED_ID, "user": RECEIPT_USER}}}


def test_cpp_manual_scope_on_customized_python_image_takes_the_derived_path(shipped, tmp_path,
                                                                            monkeypatch):
    docker = InspectOnlyDocker(shipped)
    monkeypatch.setattr(runtime, "_run", docker)

    def builder_boundary():
        raise BuilderReached

    monkeypatch.setattr("appsec_review.runtime.resources.require_bounded_image_builder", builder_boundary)
    unit = _unit(shipped, tmp_path, "derive")
    with pytest.raises(BuilderReached):
        codeql._database_one(unit, _case_085_scope(), _case_085_receipts())
    settings = shipped.job("job_codeql_analysis").typed_settings
    inspected = [call[3] for call in docker.calls]
    assert all(call[:3] == ("docker", "image", "inspect") for call in docker.calls)
    assert inspected[:2] == [settings.source_image_tag, CUSTOMIZED_TAG]
    assert _declaration(shipped, _profiles(shipped)["native"]["image_id"]).runtime_image_id not in inspected
    identity = _derived_identity(shipped, CUSTOMIZED_ID, RECEIPT_USER)
    assert (tmp_path / "metadata" / "codeql-images").is_dir()
    assert not (tmp_path / "metadata" / "codeql-preinstalled-images").exists()
    assert any(path.name == identity for path in (tmp_path / "metadata" / "codeql-images").rglob(identity))
    assert not any(event == "CODEQL_RUNTIME_RESOLVED" for event, _ in unit.job.events.records)


def test_cpp_manual_scope_on_customized_image_fails_closed_without_derive(shipped, tmp_path, monkeypatch):
    docker = InspectOnlyDocker(shipped)
    monkeypatch.setattr(runtime, "_run", docker)
    unit = _unit(shipped, tmp_path, "fail")
    with pytest.raises(ValueError) as caught:
        codeql._database_one(unit, _case_085_scope(), _case_085_receipts())
    assert f"build_image_id={CUSTOMIZED_ID}" in str(caught.value)
    assert f"effective_user={EFFECTIVE_USER}" in str(caught.value)
    assert docker.calls == []


def test_native_profile_resolution_stays_preinstalled_application_runner_under_derive(shipped, tmp_path,
                                                                                      monkeypatch):
    docker = InspectOnlyDocker(shipped)
    monkeypatch.setattr(runtime, "_run", docker)
    monkeypatch.setattr("appsec_review.runtime.resources.require_bounded_image_builder",
                        lambda: pytest.fail("declared native runtime must not build"))
    native = _profiles(shipped)["native"]
    declaration = _declaration(shipped, native["image_id"])
    unit = _unit(shipped, tmp_path, "derive")
    image, stdout, stderr = codeql._resolve_image(
        unit, build_image_tag=native["tag"], build_image_id=native["image_id"],
        runtime_user=native["user"], scope_id="codeql-unit-" + "1" * 24)
    assert stdout == stderr == b""
    assert image.preinstalled and not image.image_build_performed
    assert image.schema == runtime.PREINSTALLED_IMAGE_SCHEMA
    assert image.runner_source == "application"
    assert image.image_id == declaration.runtime_image_id
    assert image.runtime_user == EFFECTIVE_USER
    resolved = [fields for event, fields in unit.job.events.records if event == "CODEQL_RUNTIME_RESOLVED"]
    assert len(resolved) == 1
    assert resolved[0]["preparation_kind"] == "preinstalled"
    assert resolved[0]["runner_source"] == "application"
    assert resolved[0]["requested_runtime_user"] == RECEIPT_USER
    assert not (tmp_path / "metadata" / "codeql-images").exists()


# Static compatibility of containers/tools/codeql/Dockerfile layered on native-family images.

def _catalog():
    return tomllib.loads((ROOT / "containers" / "catalog.toml").read_text(encoding="utf-8"))["images"]


def _instructions(path):
    lines, pending = [], ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not pending and (not raw.strip() or raw.lstrip().startswith("#")):
            continue
        pending += raw.rstrip("\\").strip() + " "
        if not raw.endswith("\\"):
            lines.append(pending.strip())
            pending = ""
    return lines


def _arg_defaults(instructions):
    return dict(line.split(" ", 1)[1].split("=", 1) for line in instructions
                if line.startswith("ARG ") and "=" in line)


def _from_chain(tag):
    contexts = {entry["tag"]: ROOT / entry["context"] / entry.get("dockerfile", "Dockerfile")
                for entry in _catalog() if entry.get("state") == "enabled" and "tag" in entry}
    chain = []
    while tag in contexts:
        instructions = _instructions(contexts[tag])
        chain.append((tag, instructions))
        froms = [line.split()[1] for line in instructions if line.startswith("FROM ")]
        assert len(froms) == 1, (tag, froms)
        tag = froms[0]
    return chain, tag


@pytest.mark.parametrize("profile", ["native", "rust", "wasm", "python", "node"])
def test_native_family_profiles_root_in_glibc_ubuntu_with_numeric_nonroot_user(shipped, profile):
    value = _profiles(shipped)[profile]
    chain, upstream = _from_chain(value["tag"])
    tags = [tag for tag, _ in chain]
    assert "appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1" in tags
    assert tags[-1] == "appsec-review/base-ubuntu:24.04"
    # The CodeQL linux64 bundle and the derived RUN (/bin/sh, chmod) need a glibc Ubuntu userland.
    assert GLIBC_UBUNTU.fullmatch(upstream)
    users = [line.split()[1] for line in chain[0][1] if line.startswith("USER ")]
    assert users[-1] == value["user"] == RECEIPT_USER
    assert re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", users[-1])


def test_native_toolchain_supplies_codeql_runner_and_derive_prerequisites():
    pins = {line.split("=", 1)[0] for line in
            (ROOT / "containers/buildenv/native-toolchain/packages.lock").read_text().splitlines()
            if line and not line.startswith("#")}
    # python3 runs the runner entrypoint, coreutils supplies chmod, compilers serve cpp manual replay.
    assert {"python3", "coreutils", "bash", "gcc", "g++", "clang", "make", "libc6-dev"} <= pins
    cpp = _instructions(ROOT / "containers/buildenv/cpp/Dockerfile")
    assert any("cmake" in line and line.startswith("RUN ") for line in cpp)


def test_rust_wasm_image_carries_rust_src_and_explicit_path():
    instructions = _instructions(ROOT / "containers/buildenv/rust-wasm/Dockerfile")
    assert any("rust-src" in line for line in instructions if line.startswith("RUN "))
    paths = [line for line in instructions if line.startswith("ENV PATH=")]
    assert paths and paths[-1].startswith("ENV PATH=/opt/rust/bin:") and ":/bin" in paths[-1]


def test_codeql_source_bundle_is_built_on_the_same_glibc_toolchain():
    bundle = _instructions(ROOT / "containers/tools/codeql/Dockerfile.bundle")
    assert _arg_defaults(bundle)["BASE_IMAGE"] == "appsec-review/buildenv-native-toolchain:noble-gcc13.3-clang18.1"
    assert any("linux64" in line for line in bundle)


def test_derived_codeql_layer_is_offline_root_copy_then_nonroot_scratch():
    instructions = _instructions(ROOT / "containers/tools/codeql/Dockerfile")
    assert instructions[:3] == ["ARG CODEQL_SOURCE_IMAGE", "ARG BUILD_IMAGE",
                                "FROM ${CODEQL_SOURCE_IMAGE} AS codeql_source"]
    final = instructions[instructions.index("FROM ${BUILD_IMAGE}"):]
    assert final[1:3] == ["ARG RUNTIME_USER=10001:10001", "USER 0:0"]
    assert "COPY --from=codeql_source /opt/codeql /opt/codeql" in final
    assert any(line.startswith("RUN chmod -R a+rX /opt/codeql") for line in final)
    assert final[-3:] == ["ENV PATH=/opt/codeql:${PATH}", "USER ${RUNTIME_USER}", "WORKDIR /scratch"]
    assert not any(token in line for line in final for token in ("apt-get", "curl", "wget", "pip "))


def test_customized_python_image_derives_from_the_profile_and_keeps_its_user(tmp_path, shipped):
    value = _profiles(shipped)["python"]
    profile = BuildProfile("python", value["tag"], value["image_id"], value["user"])
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=tmp_path,
                                    runner=lambda *args: pytest.fail("definition must not call Docker"))
    _identity, dockerfile = resolver._definition(
        {"system": "python", "source_dir": "projects/python-package/case-085",
         "system_packages": ["libffi-dev"], "dependency_files": []}, profile, {})
    lines = dockerfile.decode().splitlines()
    assert lines[0] == "FROM audit-buildenv-python:local"
    assert [line for line in lines if line.startswith("USER ")][-1] == f"USER {RECEIPT_USER}"
    assert lines[-1] == "WORKDIR /opt/project/projects/python-package/case-085"


def test_rust_scopes_need_cargo_prerequisites_and_wasm_has_no_codeql_family(shipped):
    settings = shipped.job("job_codeql_analysis").typed_settings
    assert {"Cargo.toml", "Cargo.lock", "bundled-rust-indexer"} <= set(settings.languages["rust"].prerequisites)
    assert planning._SOURCE_FAMILIES["rust"] == "rust"
    assert planning._COMPILED_FAMILIES["native"] == "cpp"
    assert {"node", "python"} <= set(planning._NATIVE_COMPONENT_FAMILIES)
    assert "wasm" not in planning._SOURCE_FAMILIES and "wasm" not in planning._COMPILED_FAMILIES
