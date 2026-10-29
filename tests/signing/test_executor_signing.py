"""Signature enforcement at the scanner and build container launch points."""
from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
from types import MappingProxyType

import pytest

from appsec_review.config import BuildCaptureConfig
from appsec_review.container_runtime import (
    BuildContainerExecutor, BuildProfile, CaptureScope, ProjectImage, derived_base_image_id,
)
from appsec_review.container_runtime.catalog import ContainerCatalog, ToolImage, load_catalog
from appsec_review.container_runtime.executor import CommandOutcome, ContainerExecutor, ExecutionRequest
from appsec_review.container_runtime.project_images import SCHEMA as PROJECT_IMAGE_SCHEMA
from appsec_review.signing import EnvelopeImageVerifier, OpenSSL, SignatureVerificationError, key_id, sign_image
from appsec_review.signing.policy import set_default_image_verifier


OPENSSL_BINARY = "/usr/bin/openssl"
PINNED = "sha256:" + "a" * 64
DERIVED = "sha256:" + "d" * 64
OTHER = "sha256:" + "e" * 64


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


def _catalog(tmp_path: Path, *, expected: str | None = PINNED) -> ContainerCatalog:
    policy = MappingProxyType({"tmpfs": ["/tmp:rw,nosuid,nodev,noexec,size=128m"]})
    tool = ToolImage("tool-fixture", "fixture", "1", "fixture:1", "/bin/fixture",
                     "10001:10001", "none", "1g", "2", 256, 10, 8, expected,
                     tmp_path / "tool.toml", MappingProxyType({}))
    return ContainerCatalog(tmp_path / "catalog.toml", tmp_path / "policy.toml", policy,
                            MappingProxyType({"tool-fixture": tool}))


class ScannerDocker:
    def __init__(self, image_id: str = PINNED) -> None:
        self.image_id = image_id
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, timeout):
        self.calls.append(tuple(argv))
        if tuple(argv[:3]) == ("docker", "image", "inspect"):
            return CommandOutcome(0, (self.image_id + "\n").encode(), b"")
        return CommandOutcome(0, b"ok", b"")

    @property
    def runs(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:2] == ("docker", "run")]


def _scan(tmp_path: Path, executor: ContainerExecutor):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    return executor.execute(ExecutionRequest("tool-fixture", ("/bin/fixture",), target,
                                             tmp_path / "run" / "scratch"))


class BuildDocker:
    def __init__(self, image_id: str, *, gitleaks_image_id: str | None = None) -> None:
        self.image_id = image_id
        self.gitleaks_image_id = gitleaks_image_id
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv, timeout):
        self.calls.append(tuple(argv))
        if argv[:3] == ("docker", "image", "inspect"):
            resolved = self.gitleaks_image_id if "gitleaks" in argv[3] else self.image_id
            return 0, str(resolved).encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, json.dumps([{"Destination": "/", "Source": "/"}]).encode(), b"", False
        return 0, b"built", b"", False

    @property
    def runs(self) -> list[tuple[str, ...]]:
        return [call for call in self.calls if call[:2] == ("docker", "run")]


def _build(tmp_path: Path, executor: BuildContainerExecutor):
    (tmp_path / "project").mkdir(exist_ok=True)
    return executor.execute(("make",), workspace=tmp_path, working_directory="project", environment={})


def _build_executor(profile: BuildProfile, docker: BuildDocker, verifier=None) -> BuildContainerExecutor:
    return BuildContainerExecutor(profile, timeout_seconds=90, output_bytes=1024, runner=docker,
                                  image_verifier=verifier)


def _capture_config() -> BuildCaptureConfig:
    return BuildCaptureConfig("ptrace", 100, 32, 4096, True, 128, 16384, (), 1024, 100, 100)


def _scope() -> CaptureScope:
    return CaptureScope("2026-10-09-0001", "job_project_build", "attempt_0001", "build-unit", "native")


# -- pinned images: an unsigned or tampered image never reaches ``docker run`` ---------------------

def test_scanner_launch_is_refused_for_an_unsigned_pinned_image(tmp_path: Path) -> None:
    docker, verifier = ScannerDocker(), _rejecting(PINNED)
    executor = ContainerExecutor(_catalog(tmp_path), tmp_path / "run", runner=docker, image_verifier=verifier)
    with pytest.raises(SignatureVerificationError, match=r"refusing to launch tool-fixture image fixture:1"):
        _scan(tmp_path, executor)
    assert verifier.calls == [(PINNED, "fixture:1")]
    assert docker.runs == []


def test_resolve_image_is_the_verified_identity_point(tmp_path: Path) -> None:
    docker, verifier = ScannerDocker(), _rejecting(PINNED)
    executor = ContainerExecutor(_catalog(tmp_path), tmp_path / "run", runner=docker, image_verifier=verifier)
    with pytest.raises(SignatureVerificationError, match=PINNED):
        executor.resolve_image(executor.catalog.tool("tool-fixture"))
    assert docker.runs == []


def test_build_launch_is_refused_for_an_unsigned_pinned_profile_image(tmp_path: Path) -> None:
    docker, verifier = BuildDocker(PINNED), _rejecting(PINNED)
    executor = _build_executor(BuildProfile("native", "build-native:local", PINNED, "10001:10001"),
                               docker, verifier)
    with pytest.raises(SignatureVerificationError, match=r"build profile native image build-native:local"):
        executor.resolve()
    with pytest.raises(SignatureVerificationError):
        _build(tmp_path, executor)
    with pytest.raises(SignatureVerificationError):
        executor.prepare_node_dependencies(workspace=tmp_path, source_dir="project")
    workspace = tmp_path / "workspace"
    (workspace / "native").mkdir(parents=True)
    with pytest.raises(SignatureVerificationError):
        executor.execute_captured(("make",), workspace=workspace, working_directory="native",
                                  environment={}, capture_directory=workspace / ".capture",
                                  capture_config=_capture_config(), scope=_scope())
    assert docker.runs == []
    assert set(verifier.calls) == {(PINNED, "build-native:local")}


def test_unsigned_gitleaks_image_is_not_launched_and_the_capture_is_redacted(tmp_path: Path) -> None:
    gitleaks = load_catalog(Path(__file__).parents[2]).tool("tool-gitleaks")
    gitleaks_id = gitleaks.expected_image_id or OTHER
    capture = tmp_path / "capture"
    capture.mkdir()
    (capture / "stdout").write_text("SECRET-VALUE", encoding="utf-8")
    (capture / "stderr").write_bytes(b"")
    (capture / "events.jsonl").write_text("", encoding="utf-8")
    docker, verifier = BuildDocker(PINNED, gitleaks_image_id=gitleaks_id), _rejecting(gitleaks_id)
    executor = _build_executor(BuildProfile("native", "build-native:local", PINNED, "10001:10001"),
                               docker, verifier)
    result = executor._scan_capture_secrets(capture, trace_paths=(), finding_limit=10,
                                            argv=("make",), environment={})
    assert docker.runs == []
    assert verifier.calls == [(gitleaks_id, gitleaks.tag)]
    assert "refusing to launch tool-gitleaks image" in result["coverage_gap"]
    assert result["redact_invocation"] is True
    assert "SECRET-VALUE" not in (capture / "stdout").read_text(encoding="utf-8")


# -- valid signatures through the real envelope verifier -------------------------------------------

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


def test_signed_pinned_images_launch_in_both_executors(tmp_path: Path, envelope_verifier) -> None:
    verifier, openssl, trusted, _untrusted, signatures = envelope_verifier
    sign_image(openssl, trusted, PINNED, signatures)

    scanner = ScannerDocker()
    result = _scan(tmp_path, ContainerExecutor(_catalog(tmp_path), tmp_path / "run", runner=scanner,
                                               image_verifier=verifier))
    assert result.image_id == PINNED and len(scanner.runs) == 1 and PINNED in scanner.runs[0]

    build = BuildDocker(PINNED)
    executor = _build_executor(BuildProfile("native", "build-native:local", PINNED, "10001:10001"),
                               build, verifier)
    executor.resolve()
    (tmp_path / "build").mkdir()
    assert _build(tmp_path / "build", executor).exit_code == 0
    assert len(build.runs) == 1 and PINNED in build.runs[0]


def test_retagged_and_untrusted_images_are_refused(tmp_path: Path, envelope_verifier) -> None:
    verifier, openssl, trusted, untrusted, signatures = envelope_verifier
    sign_image(openssl, trusted, PINNED, signatures)
    sign_image(openssl, untrusted, OTHER, signatures)

    # An unpinned tool whose tag was moved to a different, unsigned image.
    scanner = ScannerDocker(DERIVED)
    with pytest.raises(SignatureVerificationError, match="no signature envelope"):
        _scan(tmp_path, ContainerExecutor(_catalog(tmp_path, expected=None), tmp_path / "run",
                                          runner=scanner, image_verifier=verifier))
    assert scanner.runs == []

    build = BuildDocker(OTHER)
    executor = _build_executor(BuildProfile("native", "build-native:local", OTHER, "10001:10001"),
                               build, verifier)
    with pytest.raises(SignatureVerificationError, match="signature is not valid"):
        _build(tmp_path, executor)
    assert build.runs == []


# -- runtime-derived project images ----------------------------------------------------------------

def _project_image(*, customized: bool, image_id: str, base: str = PINNED) -> dict:
    return asdict(ProjectImage(PROJECT_IMAGE_SCHEMA, "f" * 64, "native", base, "appsec-review-project-native:x",
                               image_id, None, customized, False, {}))


def test_only_a_recorded_customized_project_image_is_marked_derived() -> None:
    assert derived_base_image_id(_project_image(customized=True, image_id=DERIVED)) == PINNED
    assert derived_base_image_id(_project_image(customized=False, image_id=PINNED)) is None
    assert derived_base_image_id(_project_image(customized=True, image_id=PINNED)) is None
    assert derived_base_image_id({**_project_image(customized=True, image_id=DERIVED),
                                  "schema": "appsec-review/project-build-image/1"}) is None
    assert derived_base_image_id({**_project_image(customized=True, image_id=DERIVED),
                                  "customized": "true"}) is None
    assert derived_base_image_id({**_project_image(customized=True, image_id=DERIVED),
                                  "base_image_id": "build-native:local"}) is None
    # A tag that merely looks like a project image is not a derivation record.
    assert derived_base_image_id({"image_tag": "appsec-review-project-native:x", "image_id": DERIVED}) is None
    assert derived_base_image_id(None) is None


def test_build_profile_rejects_an_invalid_derived_base() -> None:
    with pytest.raises(ValueError, match="derived base"):
        BuildProfile("native", "t:1", DERIVED, "10001:10001", derived_from_image_id=DERIVED)
    with pytest.raises(ValueError, match="derived base"):
        BuildProfile("native", "t:1", DERIVED, "10001:10001", derived_from_image_id="build-native:local")


def test_derived_project_image_launches_on_its_verified_pinned_base(tmp_path: Path) -> None:
    profile = BuildProfile("native", "appsec-review-project-native:x", DERIVED, "10001:10001",
                           derived_from_image_id=derived_base_image_id(
                               _project_image(customized=True, image_id=DERIVED)))
    docker, verifier = BuildDocker(DERIVED), _rejecting(DERIVED)
    executor = _build_executor(profile, docker, verifier)
    executor.resolve()
    _build(tmp_path, executor)
    assert len(docker.runs) == 1 and DERIVED in docker.runs[0]
    assert {image_id for image_id, _reference in verifier.calls} == {PINNED}


def test_derived_project_image_is_refused_when_its_base_is_unsigned(tmp_path: Path) -> None:
    profile = BuildProfile("native", "appsec-review-project-native:x", DERIVED, "10001:10001",
                           derived_from_image_id=PINNED)
    docker = BuildDocker(DERIVED)
    with pytest.raises(SignatureVerificationError, match=r"build profile native base"):
        _build(tmp_path, _build_executor(profile, docker, _rejecting(PINNED)))
    assert docker.runs == []


def test_unmarked_project_image_requires_its_own_signature(tmp_path: Path) -> None:
    docker = BuildDocker(DERIVED)
    profile = BuildProfile("native", "appsec-review-project-native:x", DERIVED, "10001:10001")
    with pytest.raises(SignatureVerificationError):
        _build(tmp_path, _build_executor(profile, docker, _rejecting(DERIVED)))
    assert docker.runs == []


# -- default verifier ------------------------------------------------------------------------------

def test_default_verifier_is_resolved_at_first_use_not_construction(tmp_path: Path) -> None:
    scanner, build = ScannerDocker(), BuildDocker(PINNED)
    scanner_executor = ContainerExecutor(_catalog(tmp_path), tmp_path / "run", runner=scanner)
    build_executor = _build_executor(BuildProfile("native", "build-native:local", PINNED, "10001:10001"), build)
    installed = _rejecting(PINNED)
    set_default_image_verifier(installed)
    with pytest.raises(SignatureVerificationError):
        _scan(tmp_path, scanner_executor)
    with pytest.raises(SignatureVerificationError):
        _build(tmp_path, build_executor)
    assert installed.calls == [(PINNED, "fixture:1"), (PINNED, "build-native:local")]
    assert scanner.runs == [] and build.runs == []


def test_unresolvable_default_policy_fails_closed_at_launch(tmp_path: Path, monkeypatch) -> None:
    set_default_image_verifier(None)
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(tmp_path / "missing.toml"))
    scanner, build = ScannerDocker(), BuildDocker(PINNED)
    scanner_executor = ContainerExecutor(_catalog(tmp_path), tmp_path / "run", runner=scanner)
    build_executor = _build_executor(BuildProfile("native", "build-native:local", PINNED, "10001:10001"), build)
    with pytest.raises(SignatureVerificationError, match="policy is unavailable"):
        _scan(tmp_path, scanner_executor)
    with pytest.raises(SignatureVerificationError, match="policy is unavailable"):
        _build(tmp_path, build_executor)
    assert scanner.runs == [] and build.runs == []


def test_unit_tests_default_to_the_accepting_recording_verifier(tmp_path: Path,
                                                                _unit_test_accepting_image_verifier) -> None:
    scanner = ScannerDocker()
    _scan(tmp_path, ContainerExecutor(_catalog(tmp_path), tmp_path / "run", runner=scanner))
    assert _unit_test_accepting_image_verifier.calls == [(PINNED, "fixture:1")]
    assert len(scanner.runs) == 1
