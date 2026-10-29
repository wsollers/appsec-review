"""The in-container gate verifies the image its own container runs before the code server starts."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

from appsec_review.signing import DisabledImageVerifier, EnvelopeImageVerifier, OpenSSL, SignatureVerificationError
from appsec_review.signing import container_self_check as gate
from appsec_review.signing.images import sign_image
from tests.signing._host import OPENSSL_BINARY
from tests.signing.test_images import Signer


CONTAINER = "c0" * 32
HOSTNAME = CONTAINER[:12]
IMAGE = "sha256:" + "1a" * 32
OTHER_IMAGE = "sha256:" + "2b" * 32
COMMAND = ["dagster", "code-server", "start", "--port", "4000"]


def mountinfo(container: str = CONTAINER, root: str = "/var/lib/docker") -> str:
    lines = ["1 0 0:1 / / rw - overlay overlay rw",
             "2 1 0:2 / /proc rw - proc proc rw"]
    for index, (target, leaf) in enumerate((("/etc/resolv.conf", "resolv.conf"), ("/etc/hostname", "hostname"),
                                            ("/etc/hosts", "hosts")), start=3):
        lines.append(f"{index} 1 8:1 {root}/containers/{container}/{leaf} {target} rw,relatime - ext4 /dev/sda1 rw")
    return "\n".join(lines) + "\n"


class FakeDocker:
    """Stands in for ``docker container inspect``; records each command."""

    def __init__(self, *, image: str = IMAGE, container: str = CONTAINER, hostname: str = HOSTNAME,
                 returncode: int = 0, stdout: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.document = [{"Id": container, "Image": image, "Config": {"Hostname": hostname}}]
        self.returncode, self.stdout = returncode, stdout

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        assert kwargs["stdin"] is subprocess.DEVNULL and kwargs["check"] is False
        stdout = json.dumps(self.document) if self.stdout is None else self.stdout
        return subprocess.CompletedProcess(command, self.returncode, stdout, "no such container" if
                                           self.returncode else "")


class AcceptingVerifier:
    enforced = True

    def __init__(self) -> None:
        self.verified: list[str] = []

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        self.verified.append(image_id)


@pytest.fixture
def mounts(tmp_path: Path) -> Path:
    path = tmp_path / "mountinfo"
    path.write_text(mountinfo(), encoding="utf-8")
    return path


def run(mounts: Path, verifier, *, docker: FakeDocker | None = None, environ: dict | None = None,
        hostname: str = HOSTNAME, argv: list[str] | None = None):
    executed: list[tuple[str, list[str]]] = []
    docker = docker or FakeDocker()
    code = gate.main(["--", *COMMAND] if argv is None else argv,
                     environ={gate.IMAGE_VARIABLE: IMAGE} if environ is None else environ,
                     resolve_verifier=lambda: verifier, mountinfo_path=mounts, hostname=lambda: hostname,
                     runner=docker, execvp=lambda file, args: executed.append((file, list(args))))
    return code, executed, docker


def test_own_image_equal_to_the_launched_id_and_signed_execs_the_real_command(mounts, capsys) -> None:
    verifier = AcceptingVerifier()
    code, executed, docker = run(mounts, verifier)
    assert code == 0
    assert executed == [("dagster", COMMAND)]
    assert docker.calls == [["docker", "container", "inspect", "--", CONTAINER]]
    assert verifier.verified == [IMAGE]
    report = json.loads(capsys.readouterr().out)
    assert report == {"check": "container-image-self-check", "status": "verified", "image_id": IMAGE,
                      "container_id": CONTAINER}


@pytest.mark.parametrize(("docker", "environ", "hostname", "message"), [
    (FakeDocker(image=OTHER_IMAGE), None, HOSTNAME, "runs image"),
    (FakeDocker(), {}, HOSTNAME, "must be the host-verified"),
    (FakeDocker(), {gate.IMAGE_VARIABLE: "appsec-review-dagster:wsl"}, HOSTNAME, "must be the host-verified"),
    (FakeDocker(container="d1" * 32), None, HOSTNAME, "the daemon reported container"),
    (FakeDocker(), None, "other-host", "is not running this container"),
    (FakeDocker(returncode=1), None, HOSTNAME, "inspect failed"),
    (FakeDocker(stdout="[]"), None, HOSTNAME, "exactly one container"),
    (FakeDocker(image="sha256:short"), None, HOSTNAME, "invalid image ID"),
], ids=["image-differs", "missing-env", "tag-in-env", "other-container", "other-host", "inspect-fails",
        "no-container", "bad-image-id"])
def test_identity_mismatch_or_missing_env_refuses_before_the_server_starts(
        mounts, capsys, docker, environ, hostname, message) -> None:
    verifier = AcceptingVerifier()
    code, executed, _ = run(mounts, verifier, docker=docker, environ=environ, hostname=hostname)
    assert code == gate.EXIT_REFUSED and executed == [] and verifier.verified == []
    err = capsys.readouterr().err
    assert message in err and '"status": "refused"' in err


@pytest.mark.parametrize("text", [
    "",
    "1 0 0:1 / / rw - overlay overlay rw\n",
    mountinfo().replace(f"containers/{CONTAINER}/hosts", f"containers/{'e4' * 32}/hosts"),
    "\n".join(line for line in mountinfo().splitlines() if "/etc/hostname" not in line),
    mountinfo().replace(f"containers/{CONTAINER}/hostname", f"containers/{CONTAINER}/hosts"),
    mountinfo().replace(CONTAINER, CONTAINER[:12]),
], ids=["empty", "no-container-mounts", "two-ids", "no-hostname-mount", "wrong-leaf", "short-id"])
def test_an_undeterminable_own_container_refuses(tmp_path, capsys, text) -> None:
    path = tmp_path / "mountinfo"
    path.write_text(text, encoding="utf-8")
    code, executed, docker = run(path, AcceptingVerifier())
    assert code == gate.EXIT_REFUSED and executed == [] and docker.calls == []
    assert "cannot identify this container" in capsys.readouterr().err


def test_unreadable_mountinfo_refuses(tmp_path) -> None:
    code, executed, _ = run(tmp_path / "missing", AcceptingVerifier())
    assert code == gate.EXIT_REFUSED and executed == []


def test_docker_desktop_relative_mount_root_identifies_the_container() -> None:
    assert gate.own_container_id(mountinfo(root="/docker")) == CONTAINER


def test_disabled_enforcement_skips_with_an_explicit_status(mounts, capsys) -> None:
    code, executed, docker = run(mounts, DisabledImageVerifier(), environ={})
    assert code == 0 and executed == [("dagster", COMMAND)] and docker.calls == []
    assert json.loads(capsys.readouterr().out)["status"] == "disabled"


def test_an_unloadable_policy_refuses(mounts, capsys) -> None:
    def broken():
        raise SignatureVerificationError("image signature policy is unavailable")
    executed: list = []
    code = gate.main(["--", *COMMAND], environ={gate.IMAGE_VARIABLE: IMAGE}, resolve_verifier=broken,
                     mountinfo_path=mounts, hostname=lambda: HOSTNAME, runner=FakeDocker(),
                     execvp=lambda *args: executed.append(args))
    assert code == gate.EXIT_REFUSED and executed == []
    assert "policy is unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [[], ["--"], COMMAND])
def test_usage_without_a_command_after_the_separator(mounts, argv) -> None:
    code, executed, docker = run(mounts, AcceptingVerifier(), argv=argv)
    assert code == gate.EXIT_USAGE and executed == [] and docker.calls == []


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    if not os.path.isfile(OPENSSL_BINARY):
        pytest.skip("system OpenSSL is required")
    openssl = OpenSSL(OPENSSL_BINARY)
    root = tmp_path_factory.mktemp("self-check-keys")
    return openssl, Signer(openssl, root, "trusted"), Signer(openssl, root, "revoked")


def _envelope_verifier(keys, tmp_path: Path, signer_index: int) -> EnvelopeImageVerifier:
    openssl, trusted, revoked = keys
    anchors, signatures = tmp_path / "trusted-keys", tmp_path / "images"
    trusted.install(anchors)
    sign_image(openssl, (trusted, revoked)[signer_index].private_key, IMAGE, signatures)
    return EnvelopeImageVerifier(signatures_dir=signatures, trusted_keys_dir=anchors, openssl=OpenSSL(OPENSSL_BINARY))


def test_image_signed_by_a_trusted_anchor_verifies_with_real_openssl(keys, tmp_path, mounts) -> None:
    code, executed, _ = run(mounts, _envelope_verifier(keys, tmp_path, 0))
    assert code == 0 and executed == [("dagster", COMMAND)]


def test_image_signed_by_a_key_outside_the_anchors_refuses(keys, tmp_path, mounts, capsys) -> None:
    code, executed, _ = run(mounts, _envelope_verifier(keys, tmp_path, 1))
    assert code == gate.EXIT_REFUSED and executed == []
    assert "signature is not valid" in capsys.readouterr().err


def test_unsigned_image_refuses(keys, tmp_path, mounts, capsys) -> None:
    verifier = _envelope_verifier(keys, tmp_path, 0)
    code, executed, _ = run(mounts, verifier, docker=FakeDocker(image=OTHER_IMAGE),
                            environ={gate.IMAGE_VARIABLE: OTHER_IMAGE})
    assert code == gate.EXIT_REFUSED and executed == []
    assert "has no signature envelope" in capsys.readouterr().err
