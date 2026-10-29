"""Container image signatures: statements, envelope storage, and launch-time verification.

The signed subject is the Docker image ID (``docker image inspect --format {{.Id}}``) that the
same daemon reports and that launch then uses verbatim. This module imports only the standard
library and ``.core``; it never loads configuration or talks to Docker except through
``inspect_image_id``.
"""
from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import re
import subprocess
import threading
from typing import Any, Protocol, runtime_checkable

from .core import (
    OpenSSL,
    SignatureVerificationError,
    TrustedKeys,
    make_statement,
    read_envelope,
    sign_statement,
    verify_envelope,
    write_envelope,
)


IMAGE_KIND = "container-image"
IMAGE_ID_KIND = "docker-image-id"
DEFAULT_INSPECT_TIMEOUT_SECONDS = 60.0

_IMAGE_ID = re.compile(r"sha256:([0-9a-f]{64})")
_REFERENCE_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f]")


def _image_hex(image_id: Any) -> str:
    match = _IMAGE_ID.fullmatch(image_id) if isinstance(image_id, str) else None
    if match is None:
        raise SignatureVerificationError(
            f"container image ID must be sha256:<64 lowercase hex>: {image_id!r}")
    return match.group(1)


def image_statement(image_id: str) -> dict:
    _image_hex(image_id)
    return make_statement(IMAGE_KIND, {"image_id": image_id, "id_kind": IMAGE_ID_KIND})


def image_envelope_path(signatures_dir: str | os.PathLike[str], image_id: str) -> Path:
    return Path(signatures_dir) / f"{_image_hex(image_id)}.json"


def _describe(image_id: str, reference: str | None) -> str:
    return f"container image {image_id}" + (f" ({reference})" if reference else "")


@runtime_checkable
class ImageSignatureVerifier(Protocol):
    """Checks an image ID before it is launched or reused; raises SignatureVerificationError."""

    def verify(self, image_id: str, *, reference: str | None = None) -> None: ...


class EnvelopeImageVerifier:
    """Requires a trusted-key signed ``container-image`` envelope whose subject is this image ID."""

    enforced = True

    def __init__(self, *, signatures_dir: Path, trusted_keys_dir: Path, openssl: OpenSSL) -> None:
        self.signatures_dir = Path(signatures_dir)
        self.trusted_keys_dir = Path(trusted_keys_dir)
        self.openssl = openssl
        self._lock = threading.Lock()
        self._trusted: TrustedKeys | None = None
        self._verified: dict[str, tuple[int, ...]] = {}

    def _trusted_keys(self) -> TrustedKeys:
        if self._trusted is None:
            self.openssl.self_test()
            self._trusted = TrustedKeys.load(self.trusted_keys_dir, self.openssl)
        return self._trusted

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        try:
            _image_hex(image_id)
        except SignatureVerificationError as error:
            raise SignatureVerificationError(
                f"{error}" + (f" (reference {reference})" if reference else "")) from error
        described = _describe(image_id, reference)
        path = image_envelope_path(self.signatures_dir, image_id)
        with self._lock:
            # The identity is captured before reading so a later replacement always misses the cache.
            try:
                info = os.lstat(path)
            except FileNotFoundError as error:
                self._verified.pop(image_id, None)
                raise SignatureVerificationError(
                    f"{described} has no signature envelope; expected {path}") from error
            except OSError as error:
                self._verified.pop(image_id, None)
                raise SignatureVerificationError(
                    f"{described} signature envelope cannot be inspected: {path}: {error}") from error
            identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if self._verified.get(image_id) == identity:
                return
            self._verified.pop(image_id, None)
            try:
                trusted = self._trusted_keys()
                statement = verify_envelope(read_envelope(path), trusted, self.openssl, kind=IMAGE_KIND)
            except SignatureVerificationError as error:
                raise SignatureVerificationError(
                    f"{described} signature is not valid: {path}: {error}") from error
            if statement["subject"] != image_statement(image_id)["subject"]:
                raise SignatureVerificationError(
                    f"{described} signature envelope {path} signs a different subject: "
                    f"{statement['subject']!r}")
            self._verified[image_id] = identity


class DisabledImageVerifier:
    """Performs NO image signature verification.

    Construct this only when configuration explicitly sets image enforcement to ``"disabled"``;
    it must never be a fallback for a missing, unreadable, or failing verifier.
    """

    enforced = False

    def verify(self, image_id: str, *, reference: str | None = None) -> None:
        return None


def sign_image(openssl: OpenSSL, private_key_path: str | os.PathLike[str], image_id: str,
               signatures_dir: str | os.PathLike[str]) -> Path:
    """Sign ``image_id`` and atomically write its envelope to ``<signatures_dir>/<hex>.json``."""
    envelope = sign_statement(openssl, private_key_path, image_statement(image_id))
    directory = Path(os.path.abspath(signatures_dir))
    if not directory.exists():
        directory.mkdir(mode=0o755, parents=True)
        os.chmod(directory, 0o755)
    path = image_envelope_path(directory, image_id)
    write_envelope(path, envelope)
    return path


def inspect_image_id(reference: str, *, docker: str = "docker",
                     runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                     timeout: float = DEFAULT_INSPECT_TIMEOUT_SECONDS) -> str:
    """Return the ``sha256:`` image ID the Docker daemon reports for ``reference``."""
    if (not isinstance(reference, str) or not reference or reference.startswith("-")
            or _REFERENCE_FORBIDDEN.search(reference)):
        raise SignatureVerificationError(f"invalid container image reference: {reference!r}")
    command = [docker, "image", "inspect", "--format", "{{.Id}}", "--", reference]
    try:
        completed = runner(command, stdin=subprocess.DEVNULL, capture_output=True, check=False,
                           timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise SignatureVerificationError(f"docker image inspect timed out for {reference}") from error
    except OSError as error:
        raise SignatureVerificationError(f"docker image inspect could not run: {error}") from error
    stdout, stderr = completed.stdout, completed.stderr
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    if completed.returncode != 0:
        detail = (stderr or "").strip()[:500]
        raise SignatureVerificationError(
            f"docker image inspect failed for {reference} with exit code {completed.returncode}: {detail}")
    if isinstance(stdout, bytes):
        try:
            stdout = stdout.decode("ascii")
        except UnicodeDecodeError as error:
            raise SignatureVerificationError(
                f"docker image inspect returned non-ASCII output for {reference}") from error
    if not isinstance(stdout, str):
        raise SignatureVerificationError(f"docker image inspect returned no output for {reference}")
    image_id = stdout[:-1] if stdout.endswith("\n") else stdout
    if _IMAGE_ID.fullmatch(image_id) is None:
        raise SignatureVerificationError(
            f"docker image inspect returned an invalid image ID for {reference}: {stdout[:200]!r}")
    return image_id
