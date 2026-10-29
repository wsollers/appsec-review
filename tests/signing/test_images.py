"""Unit tests for container image signatures over the system OpenSSL CLI."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from appsec_review.signing import (
    IMAGE_KIND, DisabledImageVerifier, EnvelopeImageVerifier, ImageSignatureVerifier, OpenSSL,
    SignatureVerificationError, image_statement, inspect_image_id, key_id, make_statement,
    sign_image, sign_statement, write_envelope,
)
from tests.signing._host import OPENSSL_BINARY

IMAGE_A = "sha256:" + "a1" * 32
IMAGE_B = "sha256:" + "b2" * 32

requires_openssl = pytest.mark.skipif(
    not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


class CountingOpenSSL(OpenSSL):
    def __init__(self, binary: str) -> None:
        super().__init__(binary)
        self.verify_calls = 0
        self.self_test_calls = 0

    def verify(self, public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        self.verify_calls += 1
        return super().verify(public_key_pem, message, signature)

    def self_test(self) -> bool:
        self.self_test_calls += 1
        return super().self_test()


class Signer:
    def __init__(self, openssl: OpenSSL, root: Path, name: str) -> None:
        self.private_key = openssl.generate_private_key(root / "private" / f"{name}.pem")
        self.public_key_pem = openssl.public_key_pem(self.private_key)
        self.key_id = key_id(openssl.public_key_der(self.public_key_pem))

    def install(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{self.key_id.removeprefix('sha256:')}.pem").write_bytes(self.public_key_pem)


@pytest.fixture(scope="module")
def signers(tmp_path_factory) -> tuple[Signer, Signer]:
    if not os.path.isfile(OPENSSL_BINARY):
        pytest.skip("system OpenSSL is required")
    openssl = OpenSSL(OPENSSL_BINARY)
    root = tmp_path_factory.mktemp("image-signing-keys")
    return Signer(openssl, root, "trusted"), Signer(openssl, root, "other")


@pytest.fixture
def setup(signers, tmp_path):
    trusted_dir = tmp_path / "trusted-keys"
    signers[0].install(trusted_dir)
    openssl = CountingOpenSSL(OPENSSL_BINARY)
    signatures = tmp_path / "signatures"
    verifier = EnvelopeImageVerifier(
        signatures_dir=signatures, trusted_keys_dir=trusted_dir, openssl=openssl)
    return verifier, openssl, signatures


def _envelope_path(signatures: Path, image_id: str) -> Path:
    return signatures / f"{image_id.removeprefix('sha256:')}.json"


def test_image_statement_subject_is_image_id_and_kind():
    assert image_statement(IMAGE_A) == make_statement(
        IMAGE_KIND, {"image_id": IMAGE_A, "id_kind": "docker-image-id"})


@pytest.mark.parametrize("image_id", [
    "", "a1" * 32, "sha256:" + "A1" * 32, "sha256:" + "a1" * 31, "sha256:" + "a1" * 32 + "\n",
    "sha512:" + "a1" * 32, " sha256:" + "a1" * 32, None, 42,
])
def test_malformed_image_ids_are_rejected(image_id):
    with pytest.raises(SignatureVerificationError):
        image_statement(image_id)
    with pytest.raises(SignatureVerificationError):
        EnvelopeImageVerifier(signatures_dir=Path("/nonexistent"), trusted_keys_dir=Path("/nonexistent"),
                              openssl=None).verify(image_id)


@requires_openssl
def test_signed_image_verifies_and_is_cached(signers, setup):
    verifier, openssl, signatures = setup
    path = sign_image(openssl, signers[0].private_key, IMAGE_A, signatures)
    assert path == _envelope_path(signatures, IMAGE_A)
    assert isinstance(verifier, ImageSignatureVerifier)
    openssl.verify_calls = 0

    verifier.verify(IMAGE_A, reference="example:latest")
    assert openssl.self_test_calls == 1
    after_first = openssl.verify_calls
    assert after_first > 0

    verifier.verify(IMAGE_A)
    assert openssl.verify_calls == after_first
    assert openssl.self_test_calls == 1


@requires_openssl
def test_replaced_envelope_is_reverified(signers, setup):
    verifier, openssl, signatures = setup
    sign_image(openssl, signers[0].private_key, IMAGE_A, signatures)
    verifier.verify(IMAGE_A)

    sign_image(openssl, signers[0].private_key, IMAGE_A, signatures)
    calls = openssl.verify_calls
    verifier.verify(IMAGE_A)
    assert openssl.verify_calls > calls

    write_envelope(_envelope_path(signatures, IMAGE_A),
                   sign_statement(openssl, signers[1].private_key, image_statement(IMAGE_A)))
    with pytest.raises(SignatureVerificationError, match="no signature from a trusted key"):
        verifier.verify(IMAGE_A)
    assert openssl.self_test_calls == 1


@requires_openssl
def test_missing_envelope_names_image_and_expected_path(setup):
    verifier, _, signatures = setup
    expected = _envelope_path(signatures, IMAGE_A)
    with pytest.raises(SignatureVerificationError) as raised:
        verifier.verify(IMAGE_A, reference="example:latest")
    assert IMAGE_A in str(raised.value)
    assert str(expected) in str(raised.value)
    assert "example:latest" in str(raised.value)


@requires_openssl
def test_envelope_for_other_image_under_this_name_is_rejected(signers, setup):
    verifier, openssl, signatures = setup
    other = sign_image(openssl, signers[0].private_key, IMAGE_B, signatures)
    shutil.copyfile(other, _envelope_path(signatures, IMAGE_A))
    verifier.verify(IMAGE_B)
    with pytest.raises(SignatureVerificationError, match="different subject"):
        verifier.verify(IMAGE_A)


@requires_openssl
def test_untrusted_signer_is_rejected(signers, setup):
    verifier, openssl, signatures = setup
    sign_image(openssl, signers[1].private_key, IMAGE_A, signatures)
    with pytest.raises(SignatureVerificationError, match="no signature from a trusted key"):
        verifier.verify(IMAGE_A)


@requires_openssl
def test_wrong_statement_kind_is_rejected(signers, setup):
    verifier, openssl, signatures = setup
    signatures.mkdir()
    statement = make_statement("python-modules", image_statement(IMAGE_A)["subject"])
    write_envelope(_envelope_path(signatures, IMAGE_A),
                   sign_statement(openssl, signers[0].private_key, statement))
    with pytest.raises(SignatureVerificationError, match="does not match expected"):
        verifier.verify(IMAGE_A)


@requires_openssl
def test_extra_subject_fields_are_rejected(signers, setup):
    verifier, openssl, signatures = setup
    signatures.mkdir()
    subject = dict(image_statement(IMAGE_A)["subject"], reference="example:latest")
    write_envelope(_envelope_path(signatures, IMAGE_A),
                   sign_statement(openssl, signers[0].private_key, make_statement(IMAGE_KIND, subject)))
    with pytest.raises(SignatureVerificationError, match="different subject"):
        verifier.verify(IMAGE_A)


def test_disabled_verifier_is_explicit_no_op():
    verifier = DisabledImageVerifier()
    assert verifier.enforced is False
    assert isinstance(verifier, ImageSignatureVerifier)
    assert verifier.verify(IMAGE_A, reference="example:latest") is None


class FakeRunner:
    def __init__(self, stdout=b"", returncode=0, stderr=b"") -> None:
        self.result = (stdout, returncode, stderr)
        self.calls: list[list[str]] = []

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        assert kwargs["check"] is False and kwargs["capture_output"] is True
        stdout, returncode, stderr = self.result
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_inspect_image_id_returns_reported_id():
    runner = FakeRunner(stdout=(IMAGE_A + "\n").encode())
    assert inspect_image_id("example:latest", docker="/usr/bin/docker", runner=runner) == IMAGE_A
    assert runner.calls == [
        ["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", "--", "example:latest"]]


@pytest.mark.parametrize("stdout", [
    b"", b"\n", b"a1" * 32 + b"\n", (IMAGE_A + "\n" + IMAGE_B + "\n").encode(),
    ("sha256:" + "A1" * 32 + "\n").encode(), (IMAGE_A + "\n\n").encode(), b"\xff\n",
])
def test_inspect_image_id_rejects_bad_output(stdout):
    with pytest.raises(SignatureVerificationError, match="docker image inspect"):
        inspect_image_id("example:latest", runner=FakeRunner(stdout=stdout))


def test_inspect_image_id_reports_docker_failure():
    runner = FakeRunner(returncode=1, stderr=b"Error: No such image: example:latest\n")
    with pytest.raises(SignatureVerificationError, match="No such image"):
        inspect_image_id("example:latest", runner=runner)


@pytest.mark.parametrize("reference", ["", "-x", "--format", "a b", "a\nb", None])
def test_inspect_image_id_rejects_unsafe_references(reference):
    runner = FakeRunner(stdout=(IMAGE_A + "\n").encode())
    with pytest.raises(SignatureVerificationError, match="invalid container image reference"):
        inspect_image_id(reference, runner=runner)
    assert runner.calls == []
