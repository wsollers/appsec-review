"""In-container gate: verify the image this container runs from, then exec the real command.

Compose runs the Dagster code location as
``python -m appsec_review.signing.container_self_check -- dagster code-server start ...``. Like every
Python process in the final image stages, this one first passes the signed-module bootstrap
(``sitecustomize``), so the gate itself runs only from verified modules. Before the code server
starts it:

1. resolves the image policy with ``default_image_verifier`` (``[signing]``); only an explicit
   ``image_enforcement = "disabled"`` skips the gate, with a logged ``disabled`` status;
2. reads ``APPSEC_REVIEW_DAGSTER_IMAGE``, the ``sha256:`` ID that Compose launched;
3. identifies its own container from ``/proc/self/mountinfo``: Docker bind-mounts ``/etc/hostname``
   (and ``/etc/hosts``, ``/etc/resolv.conf``) from ``<docker root>/containers/<64-hex ID>/``, which
   names the full ID independently of the cgroup version, while ``HOSTNAME`` holds only a
   12-character prefix that an operator can override. Exactly one full ID must be found;
4. asks the mounted Docker daemon (``docker container inspect`` by that full ID) for the container
   and requires its ``.Id`` to be that ID, its ``.Config.Hostname`` to be this kernel host name, and
   its ``.Image`` to equal ``APPSEC_REVIEW_DAGSTER_IMAGE`` exactly;
5. verifies that image ID against the mounted trust anchors and envelopes.

Any failure prints a refusal and exits with ``EXIT_REFUSED`` before the server starts, so the
container never becomes healthy. On success the process is replaced by the real command.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Any

from .core import SignatureVerificationError
from .images import ImageSignatureVerifier


IMAGE_VARIABLE = "APPSEC_REVIEW_DAGSTER_IMAGE"
MOUNTINFO = Path("/proc/self/mountinfo")
DOCKER = "docker"
INSPECT_TIMEOUT_SECONDS = 60.0
EXIT_REFUSED = 3
EXIT_USAGE = 2

_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_CONTAINER_FILES = {"/etc/hostname": "hostname", "/etc/hosts": "hosts", "/etc/resolv.conf": "resolv.conf"}
_CONTAINER_ROOT = re.compile(r"(?:^|/)containers/([0-9a-f]{64})/([^/]+)")


class SelfCheckRefused(RuntimeError):
    """The container cannot prove that it runs the verified image; the server must not start."""


def own_container_id(mountinfo: str) -> str:
    """The full 64-hex container ID from Docker's per-container bind mounts in ``mountinfo``."""
    found: dict[str, set[str]] = {}
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[4] not in _CONTAINER_FILES:
            continue
        match = _CONTAINER_ROOT.search(fields[3])
        if match is None or match.end() != len(fields[3]) or match.group(2) != _CONTAINER_FILES[fields[4]]:
            continue
        found.setdefault(match.group(1), set()).add(fields[4])
    if len(found) != 1:
        detail = "none" if not found else ", ".join(sorted(found))
        raise SelfCheckRefused(f"cannot identify this container unambiguously from its mounts: {detail}")
    (container_id, targets), = found.items()
    if "/etc/hostname" not in targets:
        raise SelfCheckRefused("cannot identify this container: /etc/hostname is not a Docker container mount")
    return container_id


def inspect_container(container_id: str, *, docker: str = DOCKER,
                      runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                      timeout: float = INSPECT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """The daemon's ``docker container inspect`` object for exactly ``container_id``."""
    command = [docker, "container", "inspect", "--", container_id]
    try:
        completed = runner(command, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise SelfCheckRefused(f"docker container inspect timed out for {container_id}") from error
    except OSError as error:
        raise SelfCheckRefused(f"docker container inspect could not run: {error}") from error
    stdout, stderr = completed.stdout, completed.stderr
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    if completed.returncode != 0:
        raise SelfCheckRefused(f"docker container inspect failed for {container_id} with exit code "
                               f"{completed.returncode}: {(stderr or '').strip()[:500]}")
    try:
        document = json.loads(stdout)
    except (TypeError, ValueError) as error:
        raise SelfCheckRefused(f"docker container inspect returned no JSON for {container_id}") from error
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise SelfCheckRefused(f"docker container inspect did not return exactly one container for {container_id}")
    return document[0]


def running_image(container_id: str, hostname: str, *, docker: str = DOCKER,
                  runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> str:
    """The image ID the daemon reports for this container, after checking it is this container."""
    container = inspect_container(container_id, docker=docker, runner=runner)
    if container.get("Id") != container_id:
        raise SelfCheckRefused(f"the daemon reported container {container.get('Id')!r}, not {container_id}")
    config = container.get("Config")
    reported = config.get("Hostname") if isinstance(config, dict) else None
    if not hostname or reported != hostname:
        raise SelfCheckRefused(f"container {container_id} has host name {reported!r}, but this process runs "
                               f"on {hostname!r}; the mounted daemon is not running this container")
    image_id = container.get("Image")
    if not isinstance(image_id, str) or _IMAGE_ID.fullmatch(image_id) is None:
        raise SelfCheckRefused(f"container {container_id} reports an invalid image ID: {image_id!r}")
    return image_id


def self_check(environ: Mapping[str, str], verifier: ImageSignatureVerifier, *, mountinfo: str, hostname: str,
               docker: str = DOCKER,
               runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> dict[str, str]:
    """Verify the image this container runs from; return the report or raise SelfCheckRefused."""
    if getattr(verifier, "enforced", True) is False:
        return {"status": "disabled", "reason": "[signing] image_enforcement is \"disabled\""}
    expected = environ.get(IMAGE_VARIABLE, "")
    if _IMAGE_ID.fullmatch(expected) is None:
        raise SelfCheckRefused(f"{IMAGE_VARIABLE} must be the host-verified sha256 image ID, not {expected!r}")
    container_id = own_container_id(mountinfo)
    image_id = running_image(container_id, hostname, docker=docker, runner=runner)
    if image_id != expected:
        raise SelfCheckRefused(f"container {container_id} runs image {image_id}, not {IMAGE_VARIABLE}={expected}")
    try:
        verifier.verify(image_id, reference=f"container {container_id[:12]}")
    except SignatureVerificationError as error:
        raise SelfCheckRefused(str(error)) from error
    return {"status": "verified", "image_id": image_id, "container_id": container_id}


def _report(stream, report: dict[str, str]) -> None:
    stream.write(json.dumps({"check": "container-image-self-check", **report}, sort_keys=True) + "\n")
    stream.flush()


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] | None = None,
         resolve_verifier: Callable[[], ImageSignatureVerifier] | None = None,
         mountinfo_path: Path = MOUNTINFO, hostname: Callable[[], str] = socket.gethostname,
         runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
         execvp: Callable[[str, list[str]], Any] = os.execvp) -> int:
    """``container_self_check -- COMMAND ...``: verify, then replace this process with COMMAND."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) < 2 or arguments[0] != "--":
        sys.stderr.write("usage: python -m appsec_review.signing.container_self_check -- COMMAND [ARG ...]\n")
        return EXIT_USAGE
    command = arguments[1:]
    try:
        if resolve_verifier is None:
            from .policy import default_image_verifier
            resolve_verifier = default_image_verifier
        verifier = resolve_verifier()
        mountinfo = ""
        if getattr(verifier, "enforced", True) is not False:
            try:
                mountinfo = mountinfo_path.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                raise SelfCheckRefused(f"cannot read {mountinfo_path}: {error}") from error
        report = self_check(dict(os.environ if environ is None else environ), verifier,
                            mountinfo=mountinfo, hostname=hostname(), runner=runner)
    except (SelfCheckRefused, SignatureVerificationError) as error:
        _report(sys.stderr, {"status": "refused", "error": str(error)})
        sys.stderr.write(f"appsec-review: refusing to start {command[0]}: the container image did not "
                         f"verify: {error}\n")
        sys.stderr.flush()
        return EXIT_REFUSED
    _report(sys.stdout, report)
    execvp(command[0], command)
    return 0


if __name__ == "__main__":
    sys.exit(main())
