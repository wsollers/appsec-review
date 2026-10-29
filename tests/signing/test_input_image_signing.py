"""Pinned input images are signature-verified before a derived image is built from them or reused."""
from __future__ import annotations

from contextlib import nullcontext
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from appsec_review.codeql import runtime as codeql_runtime
from appsec_review.config import native_dagster
from appsec_review.config.assurance import ComponentReleases
from appsec_review.config.codeql import parse_codeql_settings
from appsec_review.container_runtime import BuildProfile, ProjectImageResolver
from appsec_review.container_runtime import native_client
from appsec_review.jobs.job_third_party_data_sync.steps.cve_bin_tool_db_build import database as cve_database
from appsec_review.runtime import resources
from appsec_review.signing import (
    EnvelopeImageVerifier, OpenSSL, SignatureVerificationError, image_envelope_path, key_id, sign_image,
)
from tests.test_codeql_preinstalled import (
    BASE, INSTALLED_BUILD, INSTALLED_SOURCE, RELEASES, SOURCE, USER, settings_value,
)


OPENSSL_BINARY = "/usr/bin/openssl"
PINNED = "sha256:" + "a" * 64
DERIVED = "sha256:" + "b" * 64
OTHER = "sha256:" + "e" * 64
PROJECT_BASE = "sha256:" + "c" * 64


class RecordingVerifier:
    def __init__(self, rejected: frozenset[str] = frozenset()) -> None:
        self.rejected = rejected
        self.calls: list[tuple[str, str | None]] = []

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        self.calls.append((image_id, reference))
        if image_id in self.rejected:
            raise SignatureVerificationError(f"container image {image_id} has no signature envelope")


def _rejecting(*image_ids: str) -> RecordingVerifier:
    return RecordingVerifier(frozenset(image_ids))


def _is_build(call: tuple[str, ...]) -> bool:
    return call[:3] == ("docker", "buildx", "build") or call[:2] == ("docker", "build")


@pytest.fixture
def envelope_verifier(tmp_path: Path):
    if not os.path.isfile(OPENSSL_BINARY):
        pytest.skip("system OpenSSL is required")
    openssl = OpenSSL(OPENSSL_BINARY)
    keys = tmp_path / "keys"
    trusted, untrusted = (openssl.generate_private_key(keys / "private" / f"{name}.pem")
                          for name in ("trusted", "untrusted"))
    public = openssl.public_key_pem(trusted)
    trusted_dir = keys / "trusted"
    trusted_dir.mkdir()
    (trusted_dir / f"{key_id(openssl.public_key_der(public)).removeprefix('sha256:')}.pem").write_bytes(public)
    signatures = tmp_path / "signatures"
    verifier = EnvelopeImageVerifier(signatures_dir=signatures, trusted_keys_dir=trusted_dir, openssl=openssl)
    return verifier, openssl, trusted, untrusted, signatures


# -- ProjectImageResolver --------------------------------------------------------------------------

class ProjectDocker:
    def __init__(self) -> None:
        self.derived: str | None = None
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            if argv[3] == "node-base:local":
                return 0, PINNED.encode(), b"", False
            return (0, self.derived.encode(), b"", False) if self.derived else (1, b"", b"missing", False)
        if argv[:3] == ("docker", "buildx", "build"):
            self.derived = DERIVED
            return 0, b"built", b"", False
        raise AssertionError(argv)

    @property
    def builds(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if _is_build(call)]


RECIPE = {
    "schema": "appsec-review/build-recipe/1", "build_unit_id": "build-unit-" + "1" * 20,
    "image_profile": "node", "source_dir": "web", "build_dir": "web/dist",
    "system_packages": [], "environment": {},
    "dependency_files": ["web/package.json", "web/package-lock.json"],
    "configure_commands": [], "build_commands": [["npm", "run", "build"]],
    "expected_outputs": ["web/dist"], "network_required": True,
    "reason": "fixture", "build_system": "node",
}


def _project_resolver(tmp_path: Path, docker: ProjectDocker, verifier=None) -> ProjectImageResolver:
    project = tmp_path / "target" / "web"
    project.mkdir(parents=True, exist_ok=True)
    (project / "package.json").write_text('{"scripts":{"build":"tsc"}}', encoding="utf-8")
    (project / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
    return ProjectImageResolver(
        metadata_root=tmp_path / "metadata", target_root=tmp_path / "target", runner=docker,
        releases=ComponentReleases({"platform": "fixture/1", "build_toolchain": "fixture/1"}),
        image_verifier=verifier)


PROFILE = BuildProfile("node", "node-base:local", PINNED, "10001:10001")


def test_unsigned_project_base_blocks_the_derived_build(tmp_path: Path) -> None:
    docker, verifier = ProjectDocker(), _rejecting(PINNED)
    with pytest.raises(SignatureVerificationError,
                       match=r"refusing to derive a project image from build profile node base node-base:local"):
        _project_resolver(tmp_path, docker, verifier).resolve(RECIPE, PROFILE)
    assert docker.builds == []
    assert verifier.calls == [(PINNED, "node-base:local")]


def test_signed_project_base_allows_the_build_and_reuse_reverifies_it(tmp_path: Path) -> None:
    docker, verifier = ProjectDocker(), RecordingVerifier()
    resolver = _project_resolver(tmp_path, docker, verifier)
    first, _, _ = resolver.resolve(RECIPE, PROFILE)
    assert first.image_id == DERIVED and not first.reused and len(docker.builds) == 1

    second, _, _ = resolver.resolve(RECIPE, PROFILE)
    assert second.reused and len(docker.builds) == 1
    assert verifier.calls == [(PINNED, "node-base:local")] * 2


def test_reuse_of_a_derived_image_is_refused_once_its_base_is_unsigned(tmp_path: Path) -> None:
    docker = ProjectDocker()
    _project_resolver(tmp_path, docker, RecordingVerifier()).resolve(RECIPE, PROFILE)
    with pytest.raises(SignatureVerificationError, match="has no signature envelope"):
        _project_resolver(tmp_path, docker, _rejecting(PINNED)).resolve(RECIPE, PROFILE)
    assert len(docker.builds) == 1


def test_project_base_is_checked_through_the_default_verifier(tmp_path: Path,
                                                              _unit_test_accepting_image_verifier) -> None:
    docker = ProjectDocker()
    _project_resolver(tmp_path, docker).resolve(RECIPE, PROFILE)
    assert _unit_test_accepting_image_verifier.calls == [(PINNED, "node-base:local")]


def test_uncustomized_recipe_builds_nothing_and_leaves_launch_verification_to_the_executor(
        tmp_path: Path) -> None:
    docker, verifier = ProjectDocker(), _rejecting(PINNED)
    image, _, _ = _project_resolver(tmp_path, docker, verifier).resolve(
        {**RECIPE, "network_required": False}, PROFILE)
    assert not image.customized and image.image_id == PINNED
    assert docker.builds == [] and verifier.calls == []


def test_project_base_with_real_signatures(tmp_path: Path, envelope_verifier) -> None:
    verifier, openssl, trusted, untrusted, signatures = envelope_verifier

    sign_image(openssl, untrusted, PINNED, signatures)
    docker = ProjectDocker()
    with pytest.raises(SignatureVerificationError, match="signature is not valid"):
        _project_resolver(tmp_path / "untrusted", docker, verifier).resolve(RECIPE, PROFILE)
    assert docker.builds == []

    # A valid envelope for another image, copied into the base's place, signs the wrong subject.
    image_envelope_path(signatures, PINNED).unlink()
    sign_image(openssl, trusted, OTHER, signatures)
    shutil.copyfile(image_envelope_path(signatures, OTHER), image_envelope_path(signatures, PINNED))
    with pytest.raises(SignatureVerificationError, match="signs a different subject"):
        _project_resolver(tmp_path / "tampered", docker, verifier).resolve(RECIPE, PROFILE)
    assert docker.builds == []

    image_envelope_path(signatures, PINNED).unlink()
    sign_image(openssl, trusted, PINNED, signatures)
    image, _, _ = _project_resolver(tmp_path / "signed", docker, verifier).resolve(RECIPE, PROFILE)
    assert image.image_id == DERIVED and len(docker.builds) == 1


# -- CodeQLImageResolver ---------------------------------------------------------------------------

class CodeQLDocker:
    def __init__(self, *, build_tag_image: str = BASE) -> None:
        self.images = {"source:fixture": SOURCE, "build:fixture": build_tag_image, SOURCE: SOURCE,
                       BASE: BASE, build_tag_image: build_tag_image,
                       INSTALLED_SOURCE: INSTALLED_SOURCE, INSTALLED_BUILD: INSTALLED_BUILD}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, timeout):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            image = self.images.get(argv[3])
            return (0, (image + "\n").encode(), b"", False) if image else (1, b"", b"missing", False)
        if argv[:3] == ("docker", "image", "tag"):
            return 0, b"", b"", False
        if argv[:3] == ("docker", "buildx", "build"):
            self.images[argv[argv.index("--tag") + 1]] = DERIVED
            return 0, b"built", b"", False
        raise AssertionError(argv)

    @property
    def mutations(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:3] in {("docker", "image", "tag"), ("docker", "buildx", "build")}]


def _codeql_resolver(tmp_path: Path, docker: CodeQLDocker, verifier, *, preinstalled: bool):
    tool_root = tmp_path / "containers" / "tools" / "codeql"
    tool_root.mkdir(parents=True, exist_ok=True)
    for name in ("Dockerfile", "Dockerfile.source", "codeql_runner.py"):
        (tool_root / name).write_text("fixture\n", encoding="utf-8")
    value = settings_value()
    if not preinstalled:
        value["preinstalled_runtimes"] = []
    return codeql_runtime.CodeQLImageResolver(
        repository_root=tmp_path, metadata_root=tmp_path / "metadata",
        settings=parse_codeql_settings(value), runner=docker, releases=ComponentReleases(RELEASES),
        image_verifier=verifier)


@pytest.mark.parametrize("rejected", [SOURCE, BASE])
def test_unsigned_codeql_input_blocks_the_derived_runtime_build(tmp_path: Path, rejected: str) -> None:
    docker, verifier = CodeQLDocker(), _rejecting(rejected)
    with pytest.raises(SignatureVerificationError, match="refusing to use"):
        _codeql_resolver(tmp_path, docker, verifier, preinstalled=False).resolve(
            build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert docker.mutations == []


def test_signed_codeql_inputs_allow_the_build_and_reuse_reverifies_them(tmp_path: Path) -> None:
    docker, verifier = CodeQLDocker(), RecordingVerifier()
    resolver = _codeql_resolver(tmp_path, docker, verifier, preinstalled=False)
    first, _, _ = resolver.resolve(build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert first.image_id == DERIVED and first.image_build_performed
    second, _, _ = resolver.resolve(build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert second.reused
    assert sum(_is_build(call) for call in docker.calls) == 1
    assert verifier.calls == [(SOURCE, "source:fixture"), (BASE, "build:fixture")] * 2

    docker.calls.clear()
    with pytest.raises(SignatureVerificationError):
        _codeql_resolver(tmp_path, docker, _rejecting(BASE), preinstalled=False).resolve(
            build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert docker.mutations == []


def test_codeql_source_only_runtime_verifies_the_source_once(tmp_path: Path) -> None:
    docker, verifier = CodeQLDocker(), RecordingVerifier()
    _codeql_resolver(tmp_path, docker, verifier, preinstalled=False).resolve(
        build_image_tag="source:fixture", build_image_id=SOURCE, runtime_user=USER)
    assert verifier.calls == [(SOURCE, "source:fixture")]


def test_derived_codeql_environment_is_trusted_through_its_pinned_base(tmp_path: Path) -> None:
    docker, verifier = CodeQLDocker(build_tag_image=DERIVED), _rejecting(DERIVED)
    image, _, _ = _codeql_resolver(tmp_path, docker, verifier, preinstalled=False).resolve(
        build_image_tag="build:fixture", build_image_id=DERIVED, runtime_user=USER,
        build_image_derived_from=PROJECT_BASE)
    assert image.build_image_id == DERIVED
    assert verifier.calls == [(SOURCE, "source:fixture"), (PROJECT_BASE, "base of build:fixture")]

    docker = CodeQLDocker(build_tag_image=DERIVED)
    with pytest.raises(SignatureVerificationError, match="CodeQL environment image base"):
        _codeql_resolver(tmp_path / "unsigned", docker, _rejecting(PROJECT_BASE), preinstalled=False).resolve(
            build_image_tag="build:fixture", build_image_id=DERIVED, runtime_user=USER,
            build_image_derived_from=PROJECT_BASE)
    assert docker.mutations == []


@pytest.mark.parametrize("derived_from", ["sha256:short", DERIVED])
def test_codeql_rejects_an_invalid_derived_base(tmp_path: Path, derived_from: str) -> None:
    docker = CodeQLDocker(build_tag_image=DERIVED)
    with pytest.raises(ValueError, match="derived base id is invalid"):
        _codeql_resolver(tmp_path, docker, RecordingVerifier(), preinstalled=False).resolve(
            build_image_tag="build:fixture", build_image_id=DERIVED, runtime_user=USER,
            build_image_derived_from=derived_from)
    assert docker.calls == []


@pytest.mark.parametrize("rejected", [SOURCE, BASE, INSTALLED_BUILD])
def test_preinstalled_codeql_runtime_and_its_pins_are_verified(tmp_path: Path, rejected: str) -> None:
    verifier = RecordingVerifier()
    resolved, _, _ = _codeql_resolver(tmp_path / "ok", CodeQLDocker(), verifier, preinstalled=True).resolve(
        build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert resolved.preinstalled and resolved.image_id == INSTALLED_BUILD
    assert verifier.calls == [(SOURCE, "source:fixture"), (BASE, "build:fixture"),
                              (INSTALLED_BUILD, "preinstalled runtime for build:fixture")]

    blocked = tmp_path / "blocked"
    with pytest.raises(SignatureVerificationError, match="refusing to use"):
        _codeql_resolver(blocked, CodeQLDocker(), _rejecting(rejected), preinstalled=True).resolve(
            build_image_tag="build:fixture", build_image_id=BASE, runtime_user=USER)
    assert not (blocked / "metadata" / "codeql-preinstalled-images").exists()


def test_codeql_job_forwards_the_recorded_derived_base(monkeypatch) -> None:
    from appsec_review.container_runtime.project_images import SCHEMA
    from appsec_review.jobs.job_codeql_analysis import job as codeql_job

    forwarded = {}

    class Resolver:
        def __init__(self, **kwargs) -> None:
            pass

        def resolve(self, **kwargs):
            forwarded.update(kwargs)
            raise SignatureVerificationError("fixture stop")

    settings = parse_codeql_settings(settings_value())
    monkeypatch.setattr(codeql_job, "CodeQLImageResolver", Resolver)
    monkeypatch.setattr(codeql_job, "_settings", lambda unit: settings)
    monkeypatch.setattr(codeql_job, "_policy", lambda unit: SimpleNamespace(releases=ComponentReleases(RELEASES)))
    unit = SimpleNamespace(unit_id="unit", job=SimpleNamespace(
        repository_root=Path("."), metadata_root=Path("."),
        events=SimpleNamespace(write=lambda *args, **kwargs: None)))
    record = {"schema": SCHEMA, "customized": True, "base_image_id": PROJECT_BASE, "image_id": DERIVED,
              "image_tag": "build:fixture", "user": USER}
    with pytest.raises(SignatureVerificationError, match="fixture stop"):
        codeql_job._resolve_image(unit, build_image_tag="build:fixture", build_image_id=DERIVED,
                                  runtime_user=USER,
                                  build_image_derived_from=codeql_job.derived_base_image_id(record))
    assert forwarded["build_image_derived_from"] == PROJECT_BASE


# -- cve-bin-tool database builder -----------------------------------------------------------------

class CveDocker:
    def __init__(self, *, present: bool) -> None:
        self.present = present
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:3] == ["docker", "image", "inspect"]:
            if not self.present:
                return subprocess.CompletedProcess(argv, 1, "", "missing")
            return subprocess.CompletedProcess(argv, 0, PINNED + "\n", "")
        if argv[:2] == ["docker", "build"]:
            self.present = True
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    @property
    def runs(self) -> list[list[str]]:
        return [call for call in self.calls if call[:2] == ["docker", "run"]]


def _cve_settings(tmp_path: Path) -> cve_database.CveBinToolSettings:
    return cve_database.CveBinToolSettings(
        feed_root=tmp_path / "feed", image="appsec-review/cve-bin-tool:3.4", tool_version="3.4",
        build_context=tmp_path / "context", build_timeout_seconds=60, run_timeout_seconds=60)


@pytest.fixture
def cve_docker(tmp_path: Path, monkeypatch):
    def install(*, present: bool) -> CveDocker:
        docker = CveDocker(present=present)
        monkeypatch.setattr(native_dagster, "native_execution_requested", lambda: False)
        monkeypatch.setattr(cve_database.subprocess, "run", docker)
        monkeypatch.setattr(cve_database, "_docker_bind_source", lambda path: path)
        for name in ("input", "output"):
            (tmp_path / name).mkdir(exist_ok=True)
        return docker
    return install


def test_unsigned_pinned_cve_bin_tool_image_is_not_launched(tmp_path: Path, cve_docker) -> None:
    docker, verifier = cve_docker(present=True), _rejecting(PINNED)
    with pytest.raises(SignatureVerificationError,
                       match=r"refusing to launch cve-bin-tool image appsec-review/cve-bin-tool:3\.4"):
        cve_database._docker_builder(_cve_settings(tmp_path), tmp_path / "input", tmp_path / "output",
                                     image_verifier=verifier)
    assert docker.runs == []
    assert verifier.calls == [(PINNED, "appsec-review/cve-bin-tool:3.4")]


def test_signed_pinned_cve_bin_tool_image_launches_by_its_verified_id(tmp_path: Path, cve_docker) -> None:
    docker, verifier = cve_docker(present=True), RecordingVerifier()
    tool = cve_database._docker_builder(_cve_settings(tmp_path), tmp_path / "input", tmp_path / "output",
                                        image_verifier=verifier)
    assert tool["image_id"] == PINNED and verifier.calls == [(PINNED, "appsec-review/cve-bin-tool:3.4")]
    assert len(docker.runs) == 1
    run = docker.runs[0]
    assert run[run.index("--entrypoint") + 2] == PINNED


def test_cve_bin_tool_default_verifier_is_used(tmp_path: Path, cve_docker,
                                               _unit_test_accepting_image_verifier) -> None:
    cve_docker(present=True)
    cve_database._docker_builder(_cve_settings(tmp_path), tmp_path / "input", tmp_path / "output")
    assert _unit_test_accepting_image_verifier.calls == [(PINNED, "appsec-review/cve-bin-tool:3.4")]


def test_cve_bin_tool_image_built_from_its_context_is_derived_and_unverified(
        tmp_path: Path, cve_docker) -> None:
    docker, verifier = cve_docker(present=False), _rejecting(PINNED)
    cve_database._docker_builder(_cve_settings(tmp_path), tmp_path / "input", tmp_path / "output",
                                 image_verifier=verifier)
    assert any(call[:2] == ["docker", "build"] for call in docker.calls)
    assert verifier.calls == [] and len(docker.runs) == 1


def test_native_cve_bin_tool_image_is_verified_before_launch(tmp_path: Path, monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []

    def native_run(argv, timeout):
        calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, PINNED.encode(), b"", False
        return 0, b"", b"", False

    monkeypatch.setattr(native_dagster, "native_execution_requested", lambda: True)
    monkeypatch.setattr(native_client, "native_run", native_run)
    monkeypatch.setattr(resources, "reserve_execution", lambda **kwargs: nullcontext())
    monkeypatch.setattr(resources, "tracked_container", lambda *args, **kwargs: nullcontext())
    (tmp_path / "input").mkdir()
    (tmp_path / "output").mkdir()
    with pytest.raises(SignatureVerificationError, match="refusing to launch cve-bin-tool image"):
        cve_database._docker_builder(_cve_settings(tmp_path), tmp_path / "input", tmp_path / "output",
                                     image_verifier=_rejecting(PINNED))
    assert [call for call in calls if call[:2] == ("docker", "run")] == []
