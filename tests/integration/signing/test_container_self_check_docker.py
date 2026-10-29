"""The Dagster code location's in-container image gate, judged against real containers.

What this covers: ``container_self_check.self_check`` and ``main`` run on the test host with the
real Docker daemon, real OpenSSL and a real ``EnvelopeImageVerifier``, fed the ``/proc/self/mountinfo``
and kernel host name read from inside real running containers of the tiny test images
(``docker exec``). So container identification from Docker's per-container bind mounts, ``docker
container inspect`` of that full ID, the host-name binding, the ``.Image`` comparison with
``APPSEC_REVIEW_DAGSTER_IMAGE`` (under either image store) and the signature check are all exercised
for real.

What it does not cover: the gate process itself running inside the container (the tiny images
carry neither the package, the Docker CLI nor OpenSSL, and get no daemon socket), the signed-module
bootstrap that precedes it in the Dagster image, and the final ``execvp`` (recorded, not executed).
Those run only in the deployed Dagster image.
"""
from __future__ import annotations

import functools
import json
import subprocess
import uuid

import pytest

from appsec_review.signing import EnvelopeImageVerifier, sign_image
from appsec_review.signing.container_self_check import (
    EXIT_REFUSED, IMAGE_VARIABLE, SelfCheckRefused, main, own_container_id, self_check,
)

from .test_image_signing_docker import _image_context


COMMAND = ["dagster", "code-server", "start", "--module-name", "appsec_review.orchestration.dagster.definitions"]


def _inside(docker, container_id: str) -> tuple[str, str]:
    """The container's own mount table and kernel host name, as a process inside it sees them."""
    mountinfo = docker("exec", container_id, "cat", "/proc/self/mountinfo")
    assert mountinfo.returncode == 0, mountinfo.stderr
    hostname = docker("exec", container_id, "cat", "/proc/sys/kernel/hostname")
    assert hostname.returncode == 0, hostname.stderr
    return mountinfo.stdout, hostname.stdout.strip()


class RecordingExec:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str]]] = []

    def __call__(self, file: str, argv: list[str]) -> None:
        self.calls.append((file, list(argv)))


def test_self_check_verifies_the_image_of_a_real_container(tmp_path, capsys, docker, signing_key):
    _, signed = docker.build(_image_context(tmp_path / "context-signed", f"signed-{uuid.uuid4().hex}"),
                             "self-check-signed")
    _, unsigned = docker.build(_image_context(tmp_path / "context-unsigned", f"unsigned-{uuid.uuid4().hex}"),
                               "self-check-unsigned")
    assert signed != unsigned
    signatures = tmp_path / "image-signatures"
    sign_image(signing_key.openssl, signing_key.private_key, signed, signatures)
    verifier = EnvelopeImageVerifier(signatures_dir=signatures, trusted_keys_dir=signing_key.trusted_keys_dir,
                                     openssl=signing_key.openssl)
    runner = functools.partial(subprocess.run, env=docker.environment)

    container = docker.start(signed, "sleep", "600")
    mountinfo, hostname = _inside(docker, container)
    assert own_container_id(mountinfo) == container
    assert hostname and container.startswith(hostname)

    report = self_check({IMAGE_VARIABLE: signed}, verifier, mountinfo=mountinfo, hostname=hostname, runner=runner)
    assert report == {"status": "verified", "image_id": signed, "container_id": container}

    # Compose said another image was launched: the container's real .Image does not match it.
    with pytest.raises(SelfCheckRefused, match=f"runs image {signed}, not {IMAGE_VARIABLE}={unsigned}"):
        self_check({IMAGE_VARIABLE: unsigned}, verifier, mountinfo=mountinfo, hostname=hostname, runner=runner)

    other = docker.start(unsigned, "sleep", "600")
    other_mountinfo, other_hostname = _inside(docker, other)
    assert own_container_id(other_mountinfo) == other and other_hostname != hostname

    # A container of an image without a trusted signature is refused even when the variable matches.
    with pytest.raises(SelfCheckRefused, match="has no signature envelope"):
        self_check({IMAGE_VARIABLE: unsigned}, verifier, mountinfo=other_mountinfo, hostname=other_hostname,
                   runner=runner)

    # Mounts of one container with the host name of another: the daemon is not running this process.
    with pytest.raises(SelfCheckRefused, match="the mounted daemon is not running this container"):
        self_check({IMAGE_VARIABLE: signed}, verifier, mountinfo=mountinfo, hostname=other_hostname,
                   runner=runner)

    # main(): verified -> report on stdout and exec of the real command; refused -> exit code, no exec.
    mountinfo_path = tmp_path / "mountinfo"
    mountinfo_path.write_text(mountinfo, encoding="utf-8")
    execvp = RecordingExec()
    code = main(["--", *COMMAND], environ={IMAGE_VARIABLE: signed}, resolve_verifier=lambda: verifier,
                mountinfo_path=mountinfo_path, hostname=lambda: hostname, runner=runner, execvp=execvp)
    out = capsys.readouterr().out
    assert code == 0 and execvp.calls == [(COMMAND[0], COMMAND)]
    assert json.loads(out) == {"check": "container-image-self-check", "status": "verified", "image_id": signed,
                               "container_id": container}

    other_path = tmp_path / "other-mountinfo"
    other_path.write_text(other_mountinfo, encoding="utf-8")
    execvp = RecordingExec()
    code = main(["--", *COMMAND], environ={IMAGE_VARIABLE: unsigned}, resolve_verifier=lambda: verifier,
                mountinfo_path=other_path, hostname=lambda: other_hostname, runner=runner, execvp=execvp)
    err = capsys.readouterr().err
    assert code == EXIT_REFUSED and execvp.calls == []
    assert "refusing to start dagster" in err and "has no signature envelope" in err
