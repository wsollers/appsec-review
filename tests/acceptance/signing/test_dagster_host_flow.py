"""Dagster host flow without Compose: the host scripts sign and verify a real image before any launch.

``image_signing`` signs the module tree of a scratch checkout and a tiny ``--network none`` image
through the real signing CLI and Docker daemon; the ID it verifies is the ID Docker reports.
``lifecycle.run_action("start")`` then hands exactly that ID to a recording stand-in for Compose.
Once another image is retagged in its place, ``start`` exits 3 and never invokes Compose. The real
Dagster Dockerfile, its build tag and ``deploy/dagster/.env`` are never used: ``lifecycle`` reads
and records ``.env`` in the test directory, and the image comes from ``APPSEC_REVIEW_DAGSTER_IMAGE``.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from tests.integration.signing.test_image_signing_docker import _image_context

from .conftest import OPENSSL_BINARY, REPOSITORY_ROOT, copy_package


sys.path.insert(0, str(REPOSITORY_ROOT / "deploy" / "dagster" / "bin"))
import host  # noqa: E402
import image_signing  # noqa: E402
import lifecycle  # noqa: E402


class ComposeRecorder:
    """Runs every command but ``docker compose`` for real; records Compose and optionally forbids it."""

    def __init__(self, *, allow_compose: bool) -> None:
        self.allow_compose = allow_compose
        self.compose: list[tuple[list[str], dict]] = []
        self.signing: list[list[str]] = []

    def __call__(self, command, **kwargs):
        command = list(command)
        if command[:2] == ["docker", "compose"]:
            self.compose.append((command, kwargs))
            if not self.allow_compose:
                pytest.fail(f"Compose was invoked for an image that did not verify: {command}")
            return subprocess.CompletedProcess(command, 0, "", "")
        self.signing.append(command)
        return subprocess.run(command, **kwargs)


def test_host_flow_verifies_the_exact_image_and_refuses_a_retagged_one(tmp_path, monkeypatch, capsys, docker,
                                                                       docker_operator, operator_key):
    operator = docker_operator
    monkeypatch.setenv("TMPDIR", operator.environment["TMPDIR"])
    for name in ("APPSEC_REVIEW_PROFILE", "APPSEC_REVIEW_CONFIG_OVERLAY", "APPSEC_REVIEW_MODULE_SIGNATURE",
                 "APPSEC_REVIEW_REQUIRE_SIGNED_MODULES"):
        monkeypatch.delenv(name, raising=False)
    # As in the installed layout, the configuration anchors the non-package assets (here: this
    # repository's) while the package tree comes from the scratch checkout.
    monkeypatch.setenv("APPSEC_REVIEW_CONFIG", str(REPOSITORY_ROOT / "appsec-review.toml"))
    environment_file = tmp_path / "deployment" / ".env"
    environment_file.parent.mkdir()
    monkeypatch.setattr(lifecycle, "environment_file", environment_file)

    markers = {name: f"{name}-{uuid.uuid4().hex}" for name in ("dagster", "substitute")}
    tag, image_id = docker.build(_image_context(tmp_path / "context-dagster", markers["dagster"]), "dagster")
    _, substitute_id = docker.build(_image_context(tmp_path / "context-substitute", markers["substitute"]),
                                    "dagster-substitute")
    environ = {**operator.environment,
               "APPSEC_SIGNING_PYTHON": sys.executable,
               "APPSEC_SIGNING_PRIVATE_KEY": str(operator.private_key),
               "APPSEC_SIGNING_TRUSTED_KEYS_DIR": str(operator.trusted_keys_dir),
               "APPSEC_SIGNING_IMAGE_SIGNATURES_DIR": str(operator.image_signatures_dir),
               "APPSEC_SIGNING_OPENSSL": OPENSSL_BINARY,
               host.IMAGE_VARIABLE: tag}
    settings = lifecycle.signing_settings(environ)

    # The build-time steps, against a scratch checkout so the module envelope stays in the test directory.
    checkout = tmp_path / "checkout"
    copy_package(checkout / image_signing.PACKAGE_ROOT)
    envelope = image_signing.sign_modules(settings, checkout)
    assert envelope == checkout / image_signing.MODULE_ENVELOPE and envelope.is_file()
    signed = image_signing.sign_image(settings, REPOSITORY_ROOT, tag)
    assert signed == image_id
    assert image_signing.verify_image(settings, REPOSITORY_ROOT, tag) == image_id == docker.image_id(tag)
    assert image_signing.verify_image(settings, REPOSITORY_ROOT, image_id) == image_id

    platform = host.actual_platform()
    allowed = ComposeRecorder(allow_compose=True)
    assert lifecycle.run_action("start", platform, "dev", environ, runner=allowed) == lifecycle.OK
    [(command, kwargs)] = allowed.compose
    assert command[-3:] == ["up", "-d", "--wait"]
    assert kwargs["env"][host.IMAGE_VARIABLE] == image_id
    assert f"{host.IMAGE_VARIABLE}={image_id}" in environment_file.read_text(encoding="utf-8").splitlines()
    recorded = environment_file.read_bytes()

    # Another image now answers to the tag the deployment launches.
    docker.retag(substitute_id, tag)
    assert docker.image_id(tag) == substitute_id
    with pytest.raises(image_signing.SigningError, match="has no signature envelope"):
        image_signing.verify_image(settings, REPOSITORY_ROOT, tag)

    capsys.readouterr()
    forbidden = ComposeRecorder(allow_compose=False)
    assert lifecycle.run_action("start", platform, "dev", environ, runner=forbidden) == lifecycle.REFUSED
    assert forbidden.compose == []
    assert any("verify-image" in command for command in forbidden.signing)
    assert "refusing to start" in capsys.readouterr().err
    assert environment_file.read_bytes() == recorded
