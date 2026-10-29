"""Shared gate and fixtures for the signing integration tests.

Every test here is skipped unless ``APPSEC_REVIEW_SIGNING_INTEGRATION=1``; each fixture also skips,
naming what is missing, when the system OpenSSL, the Docker daemon or the local base image is
unavailable. Keys are ephemeral Ed25519 keys under the pytest base directory. Docker images are
built with ``--network none`` from the local ``appsec-review/base-python`` image only (never
pulled), tagged ``appsec-review-signing-test:<name>-<unique>``, and removed after each test by the
image IDs that test created.

    APPSEC_REVIEW_SIGNING_INTEGRATION=1 python -m pytest -p no:cacheprovider -rs \
        tests/integration/signing --basetemp=test/tmp/signing-integration
"""
from __future__ import annotations

import argparse
from collections.abc import Iterator
import contextlib
from dataclasses import dataclass, field
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

import pytest

from appsec_review.signing import OpenSSL, SignatureVerificationError, key_id
from appsec_review.signing import cli as signing_cli


GATE = "APPSEC_REVIEW_SIGNING_INTEGRATION"
OPENSSL_BINARY = "/usr/bin/openssl"
BASE_IMAGE = "appsec-review/base-python:3.12-bookworm"
TEST_REPOSITORY = "appsec-review-signing-test"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_SOURCE = REPOSITORY_ROOT / "src" / "appsec_review"
BUILDX_PLUGIN = Path("/usr/libexec/docker/cli-plugins/docker-buildx")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def pytest_runtest_setup(item: pytest.Item) -> None:
    if os.environ.get(GATE) != "1":
        pytest.skip(f"signing integration tests run only with {GATE}=1")


@dataclass(frozen=True)
class SigningKey:
    openssl: OpenSSL
    private_key: Path
    trusted_keys_dir: Path
    key_id: str


def make_signing_key(openssl: OpenSSL, root: Path) -> SigningKey:
    """An ephemeral Ed25519 key with its public key installed as the only ``<hex>.pem`` anchor."""
    private_key = openssl.generate_private_key(root / "private" / "operator.pem")
    public_key_pem = openssl.public_key_pem(private_key)
    identity = key_id(openssl.public_key_der(public_key_pem))
    trusted = root / "trusted-keys"
    trusted.mkdir()
    os.chmod(trusted, 0o755)
    anchor = trusted / f"{identity.removeprefix('sha256:')}.pem"
    anchor.write_bytes(public_key_pem)
    os.chmod(anchor, 0o644)
    return SigningKey(openssl, private_key, trusted, identity)


def copy_package(destination: Path) -> Path:
    """Copy the repository's ``src/appsec_review`` tree, without bytecode, to ``destination``."""
    shutil.copytree(PACKAGE_SOURCE, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return destination


def export_bootstrap(directory: Path) -> Path:
    """Export the standalone verifier exactly as ``appsec-review signing export-bootstrap`` does."""
    def no_configuration():
        raise AssertionError("export-bootstrap must not load configuration")

    arguments = argparse.Namespace(signing_command="export-bootstrap", directory=directory)
    with contextlib.redirect_stdout(io.StringIO()) as report:
        assert signing_cli.run(arguments, no_configuration) == 0, report.getvalue()
    assert sorted(path.name for path in directory.iterdir()) == sorted(signing_cli.BOOTSTRAP_FILES)
    return directory


@pytest.fixture(scope="session")
def openssl_scratch(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("openssl-scratch")


@pytest.fixture(scope="session")
def openssl(openssl_scratch) -> OpenSSL:
    if not os.access(OPENSSL_BINARY, os.X_OK):
        pytest.skip(f"system OpenSSL is unavailable: {OPENSSL_BINARY}")
    try:
        verifier = OpenSSL(OPENSSL_BINARY, temp_dir=str(openssl_scratch))
        verifier.self_test()
    except SignatureVerificationError as error:
        pytest.skip(f"system OpenSSL cannot verify Ed25519: {error}")
    return verifier


@pytest.fixture(scope="session")
def signing_key(openssl, tmp_path_factory) -> SigningKey:
    return make_signing_key(openssl, tmp_path_factory.mktemp("signing-key"))


@dataclass
class Docker:
    """Builds, tags and runs only ``appsec-review-signing-test`` images; removes what it built."""

    environment: dict[str, str]
    suffix: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created: list[str] = field(default_factory=list)

    def __call__(self, *args: str, timeout: float = 300) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["docker", *args], env=self.environment, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, check=False, timeout=timeout)

    def tag(self, name: str) -> str:
        return f"{TEST_REPOSITORY}:{name}-{self.suffix}"

    def image_id(self, reference: str) -> str:
        completed = self("image", "inspect", "--format", "{{.Id}}", "--", reference)
        assert completed.returncode == 0, completed.stderr
        image_id = completed.stdout.strip()
        assert _IMAGE_ID.fullmatch(image_id), image_id
        return image_id

    def build(self, context: Path, name: str) -> tuple[str, str]:
        tag = self.tag(name)
        completed = self("build", "--network", "none", "--quiet", "--tag", tag, str(context))
        assert completed.returncode == 0, completed.stderr
        image_id = self.image_id(tag)
        if image_id not in self.created:
            self.created.append(image_id)
        return tag, image_id

    def retag(self, image_id: str, tag: str) -> None:
        assert image_id in self.created and tag.startswith(f"{TEST_REPOSITORY}:")
        completed = self("tag", image_id, tag)
        assert completed.returncode == 0, completed.stderr

    def run(self, image_id: str, *argv: str, options: tuple[str, ...] = (),
            timeout: float = 300) -> subprocess.CompletedProcess[str]:
        assert image_id in self.created
        name = f"{TEST_REPOSITORY}-{self.suffix}-{uuid.uuid4().hex[:8]}"
        return self("run", "--rm", "--name", name, "--network", "none", *options, image_id, *argv,
                    timeout=timeout)

    def remove_created(self) -> None:
        for image_id in reversed(self.created):
            self("image", "rm", "--force", image_id)
        self.created.clear()


@pytest.fixture(scope="session")
def docker_environment(tmp_path_factory) -> dict[str, str]:
    """The caller's environment, with a private DOCKER_CONFIG when the default lacks buildx."""
    if shutil.which("docker") is None:
        pytest.skip("the docker CLI is unavailable")
    info = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, check=False, timeout=60)
    if info.returncode != 0:
        pytest.skip(f"the Docker daemon is unreachable: {info.stderr.strip()[:200]}")
    environment = dict(os.environ)
    probe = subprocess.run(["docker", "buildx", "version"], env=environment, stdin=subprocess.DEVNULL,
                           capture_output=True, check=False, timeout=60)
    if probe.returncode != 0:
        if not BUILDX_PLUGIN.is_file():
            pytest.skip(f"docker buildx is unavailable and {BUILDX_PLUGIN} does not exist")
        config = tmp_path_factory.mktemp("docker-config")
        (config / "cli-plugins").mkdir()
        (config / "cli-plugins" / "docker-buildx").symlink_to(BUILDX_PLUGIN)
        environment["DOCKER_CONFIG"] = str(config)
    base = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", "--", BASE_IMAGE],
                          env=environment, stdin=subprocess.DEVNULL, capture_output=True, check=False,
                          timeout=60)
    if base.returncode != 0:
        pytest.skip(f"local base image {BASE_IMAGE} is absent; build it from containers/bases/python "
                    "(these tests never pull)")
    return environment


@pytest.fixture
def docker(docker_environment) -> Iterator[Docker]:
    client = Docker(docker_environment)
    try:
        yield client
    finally:
        client.remove_created()
