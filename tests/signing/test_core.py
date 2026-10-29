"""Unit tests for the stdlib-only Ed25519 signing core over the system OpenSSL CLI."""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from appsec_review.signing import core
from appsec_review.signing.core import (
    STATEMENT_SCHEMA, OpenSSL, SignatureVerificationError, TrustedKeys, canonical_json, key_id,
    make_statement, read_envelope, sign_statement, verify_envelope, write_envelope,
)


OPENSSL_BINARY = "/usr/bin/openssl"
KIND = "container-image"
SUBJECT = {"image_id": "sha256:" + "ab" * 32, "id_kind": "docker-image-id"}

pytestmark = pytest.mark.skipif(not os.path.isfile(OPENSSL_BINARY), reason="system OpenSSL is required")


class Signer:
    def __init__(self, openssl: OpenSSL, root: Path, name: str) -> None:
        self.private_key = openssl.generate_private_key(root / "private" / f"{name}.pem")
        self.public_key_pem = openssl.public_key_pem(self.private_key)
        self.key_id = key_id(openssl.public_key_der(self.public_key_pem))

    def install(self, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.key_id.removeprefix('sha256:')}.pem"
        path.write_bytes(self.public_key_pem)
        return path


@pytest.fixture(scope="module")
def openssl() -> OpenSSL:
    return OpenSSL(OPENSSL_BINARY)


@pytest.fixture(scope="module")
def signers(openssl, tmp_path_factory) -> tuple[Signer, Signer]:
    root = tmp_path_factory.mktemp("signing-keys")
    return Signer(openssl, root, "trusted"), Signer(openssl, root, "other")


@pytest.fixture(scope="module")
def envelope(openssl, signers) -> dict:
    return sign_statement(openssl, signers[0].private_key, make_statement(KIND, SUBJECT))


@pytest.fixture
def trusted(openssl, signers, tmp_path) -> TrustedKeys:
    signers[0].install(tmp_path / "trusted-keys")
    return TrustedKeys.load(tmp_path / "trusted-keys", openssl)


def _with_signature(envelope: dict, **changes) -> dict:
    tampered = copy.deepcopy(envelope)
    tampered["signatures"][0].update(changes)
    return tampered


def test_self_test_verifies_known_answer(openssl):
    assert openssl.self_test() is True


def test_self_test_fails_closed_when_known_answer_is_corrupted(openssl, monkeypatch):
    monkeypatch.setattr(core, "_KAT_MESSAGE", b"\x73")
    with pytest.raises(SignatureVerificationError, match="self-test"):
        openssl.self_test()


def test_openssl_binary_must_be_absolute_and_executable(tmp_path):
    with pytest.raises(SignatureVerificationError, match="absolute"):
        OpenSSL("openssl")
    with pytest.raises(SignatureVerificationError, match="executable"):
        OpenSSL(str(tmp_path / "missing-openssl"))


def test_private_key_is_created_exclusively_with_private_modes(openssl, tmp_path):
    path = tmp_path / "new-parent" / "operator.pem"
    assert openssl.generate_private_key(path) == path
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        openssl.generate_private_key(path)
    assert path.read_bytes() == original


def test_raw_sign_and_verify(openssl, signers):
    signer = signers[0]
    signature = openssl.sign(signer.private_key, b"message")
    assert len(signature) == 64
    assert openssl.verify(signer.public_key_pem, b"message", signature)
    assert not openssl.verify(signer.public_key_pem, b"messagf", signature)
    assert not openssl.verify(signers[1].public_key_pem, b"message", signature)
    assert len(openssl.public_key_der(signer.public_key_pem)) == 44
    assert signer.key_id.startswith("sha256:") and len(signer.key_id) == 71


def test_openssl_ignores_inherited_configuration(openssl, signers, tmp_path, monkeypatch):
    bogus = tmp_path / "bogus.cnf"
    bogus.write_text("openssl_conf = x\n[x]\nproviders = p\n[p]\nbogus = q\n[q]\nactivate = 1\n")
    inherited = {**os.environ, "OPENSSL_CONF": str(bogus)}
    broken = subprocess.run([OPENSSL_BINARY, "genpkey", "-algorithm", "ed25519"], env=inherited,
                            capture_output=True, check=False)
    assert broken.returncode != 0 or not broken.stdout.startswith(b"-----BEGIN")
    monkeypatch.setenv("OPENSSL_CONF", str(bogus))
    monkeypatch.setenv("OPENSSL_MODULES", str(tmp_path / "no-modules"))
    monkeypatch.setenv("OPENSSL_ENGINES", str(tmp_path / "no-engines"))
    signature = openssl.sign(signers[0].private_key, b"message")
    assert openssl.verify(signers[0].public_key_pem, b"message", signature)
    assert openssl.self_test()


def test_envelope_round_trip_through_file(openssl, envelope, trusted, signers, tmp_path):
    path = tmp_path / "envelope.json"
    write_envelope(path, envelope)
    data = path.read_bytes()
    assert data == canonical_json(envelope) + b"\n"
    loaded = read_envelope(path)
    statement = verify_envelope(loaded, trusted, openssl, kind=KIND)
    assert statement == {"schema": STATEMENT_SCHEMA, "kind": KIND, "subject": SUBJECT}
    assert verify_envelope(data, trusted, openssl, kind=KIND) == statement
    assert loaded["signatures"][0]["key_id"] == signers[0].key_id


def test_tampered_statement_is_rejected(openssl, envelope, trusted):
    tampered = copy.deepcopy(envelope)
    tampered["statement"]["subject"]["image_id"] = "sha256:" + "cd" * 32
    with pytest.raises(SignatureVerificationError, match="does not verify"):
        verify_envelope(tampered, trusted, openssl, kind=KIND)


def test_tampered_signature_is_rejected(openssl, envelope, trusted):
    raw = bytearray(base64.b64decode(envelope["signatures"][0]["signature"]))
    raw[10] ^= 0x01
    tampered = _with_signature(envelope, signature=base64.b64encode(bytes(raw)).decode())
    with pytest.raises(SignatureVerificationError, match="does not verify"):
        verify_envelope(tampered, trusted, openssl, kind=KIND)


def test_untrusted_key_is_rejected(openssl, envelope, signers, tmp_path):
    signers[1].install(tmp_path / "other-keys")
    other = TrustedKeys.load(tmp_path / "other-keys", openssl)
    with pytest.raises(SignatureVerificationError, match="no signature from a trusted key"):
        verify_envelope(envelope, other, openssl, kind=KIND)


@pytest.mark.parametrize("make_directory", [False, True])
def test_missing_or_empty_trust_directory_verifies_nothing(openssl, envelope, tmp_path, make_directory):
    directory = tmp_path / "keys"
    if make_directory:
        directory.mkdir()
    keys = TrustedKeys.load(directory, openssl)
    assert len(keys) == 0
    with pytest.raises(SignatureVerificationError, match="no trusted signing keys"):
        verify_envelope(envelope, keys, openssl, kind=KIND)


def test_unknown_signature_is_ignored_beside_trusted_signature(openssl, envelope, trusted, signers):
    statement = make_statement(KIND, SUBJECT)
    foreign = sign_statement(openssl, signers[1].private_key, statement)["signatures"][0]
    both = copy.deepcopy(envelope)
    both["signatures"].insert(0, foreign)
    assert verify_envelope(both, trusted, openssl, kind=KIND)["subject"] == SUBJECT


def test_failing_trusted_signature_rejects_even_with_another_valid_one(openssl, envelope, signers, tmp_path):
    signers[0].install(tmp_path / "keys")
    signers[1].install(tmp_path / "keys")
    keys = TrustedKeys.load(tmp_path / "keys", openssl)
    bad = {"key_id": signers[1].key_id, "algorithm": "ed25519",
           "signature": base64.b64encode(b"\x00" * 64).decode()}
    mixed = copy.deepcopy(envelope)
    mixed["signatures"].append(bad)
    with pytest.raises(SignatureVerificationError, match="does not verify"):
        verify_envelope(mixed, keys, openssl, kind=KIND)


def test_key_file_name_must_match_key_id(openssl, signers, tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir()
    (directory / f"{signers[1].key_id.removeprefix('sha256:')}.pem").write_bytes(signers[0].public_key_pem)
    with pytest.raises(SignatureVerificationError, match="does not match its key ID"):
        TrustedKeys.load(directory, openssl)
    for path in directory.iterdir():
        path.unlink()
    (directory / "operator.pem").write_bytes(signers[0].public_key_pem)
    with pytest.raises(SignatureVerificationError, match="file name"):
        TrustedKeys.load(directory, openssl)


def test_symlinked_trusted_key_is_rejected(openssl, signers, tmp_path):
    real = signers[0].install(tmp_path / "real")
    directory = tmp_path / "keys"
    directory.mkdir()
    (directory / real.name).symlink_to(real)
    with pytest.raises(SignatureVerificationError, match="symbolic link"):
        TrustedKeys.load(directory, openssl)


def test_trusted_key_must_be_ed25519(openssl, tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir()
    private = tmp_path / "ec.pem"
    subprocess.run([OPENSSL_BINARY, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(private)], check=True, capture_output=True)
    public = subprocess.run([OPENSSL_BINARY, "pkey", "-in", str(private), "-pubout"], check=True,
                            capture_output=True).stdout
    (directory / f"{'0' * 64}.pem").write_bytes(public)
    with pytest.raises(SignatureVerificationError, match="not an Ed25519"):
        TrustedKeys.load(directory, openssl)


def test_kind_mismatch_is_rejected(openssl, envelope, trusted):
    with pytest.raises(SignatureVerificationError, match="does not match expected"):
        verify_envelope(envelope, trusted, openssl, kind="python-modules")


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(extra=1),
    lambda value: value.pop("signatures"),
    lambda value: value["statement"].update(extra=1),
    lambda value: value["statement"].update(schema="appsec-review.signed-statement/v2"),
    lambda value: value["statement"].update(subject=["not", "an", "object"]),
    lambda value: value["statement"]["subject"].update(ratio=0.5),
    lambda value: value.update(signatures=[]),
    lambda value: value.update(signatures={}),
    lambda value: value["signatures"][0].update(extra=1),
    lambda value: value["signatures"][0].update(algorithm="rsa"),
    lambda value: value["signatures"][0].update(key_id="sha256:" + "A" * 64),
    lambda value: value["signatures"][0].update(signature="not base64!"),
    lambda value: value["signatures"][0].update(
        signature=value["signatures"][0]["signature"].rstrip("=")),
    lambda value: value["signatures"][0].update(signature=base64.b64encode(b"\x00" * 63).decode()),
    lambda value: value["signatures"][0].update(signature=base64.b64encode(b"\x00" * 65).decode()),
    lambda value: value["signatures"].append(copy.deepcopy(value["signatures"][0])),
], ids=[
    "extra-top-level", "missing-signatures", "extra-statement-key", "wrong-schema", "subject-not-object",
    "float-in-subject", "empty-signatures", "signatures-not-list", "extra-signature-key", "wrong-algorithm",
    "bad-key-id", "bad-base64", "unpadded-base64", "short-signature", "long-signature", "duplicate-key",
])
def test_malformed_envelopes_are_rejected(openssl, envelope, trusted, mutate):
    malformed = copy.deepcopy(envelope)
    mutate(malformed)
    with pytest.raises(SignatureVerificationError):
        verify_envelope(malformed, trusted, openssl, kind=KIND)


@pytest.mark.parametrize("data", [
    b"{",
    b"\xff",
    b'{"statement":{},"statement":{},"signatures":[]}',
    b'{"statement":{"schema":"x","kind":"y","subject":{"n":NaN}},"signatures":[]}',
    b'{"statement":{"schema":"x","kind":"y","subject":{"n":1.0}},"signatures":[]}',
    b"[]",
])
def test_malformed_envelope_bytes_are_rejected(openssl, trusted, data):
    with pytest.raises(SignatureVerificationError):
        verify_envelope(data, trusted, openssl, kind=KIND)


def test_read_envelope_rejects_symlinks_missing_and_oversized_files(envelope, tmp_path, monkeypatch):
    path = tmp_path / "envelope.json"
    write_envelope(path, envelope)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(SignatureVerificationError, match="symbolic link"):
        read_envelope(link)
    with pytest.raises(SignatureVerificationError, match="missing"):
        read_envelope(tmp_path / "absent.json")
    monkeypatch.setattr(core, "MAX_ENVELOPE_BYTES", 16)
    with pytest.raises(SignatureVerificationError, match="exceeds"):
        read_envelope(path)


def test_write_envelope_replaces_atomically_and_refuses_malformed(envelope, tmp_path):
    path = tmp_path / "envelope.json"
    path.write_text("old")
    write_envelope(path, envelope)
    assert json.loads(path.read_bytes()) == envelope
    with pytest.raises(SignatureVerificationError):
        write_envelope(path, {**envelope, "extra": 1})
    assert sorted(item.name for item in tmp_path.iterdir()) == ["envelope.json"]


def test_canonical_json_is_deterministic():
    first = {"b": [1, True, None], "a": {"z": "é", "y": "x"}}
    second = {"a": {"y": "x", "z": "é"}, "b": [1, True, None]}
    assert canonical_json(first) == canonical_json(second)
    assert canonical_json(first) == '{"a":{"y":"x","z":"é"},"b":[1,true,null]}'.encode()


@pytest.mark.parametrize("value", [1.0, float("nan"), float("inf"), {"a": [0.1]}, {1: "x"}, {"a": {1, 2}},
                                   {"a": b"bytes"}, "\ud800"])
def test_canonical_json_rejects_non_canonical_values(value):
    with pytest.raises(ValueError):
        canonical_json(value)


def test_make_statement_validates_inputs():
    statement = make_statement(KIND, SUBJECT)
    assert statement == {"schema": STATEMENT_SCHEMA, "kind": KIND, "subject": SUBJECT}
    assert statement["subject"] is not SUBJECT
    with pytest.raises(ValueError):
        make_statement("", SUBJECT)
    with pytest.raises(ValueError):
        make_statement(KIND, ["not", "a", "dict"])


def test_core_loads_standalone_by_file_path_in_isolated_mode():
    source = Path(core.__file__)
    imports = [line.split() for line in source.read_text(encoding="utf-8").splitlines()
               if line.startswith(("import ", "from "))]
    assert imports and all(not words[1].startswith((".", "appsec_review")) for words in imports)
    script = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('signing_core_standalone', {str(source)!r})\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        f"assert module.OpenSSL({OPENSSL_BINARY!r}).self_test()\n"
        "assert not any(name.startswith('appsec_review') for name in sys.modules)\n"
    )
    subprocess.run([sys.executable, "-I", "-S", "-c", script], check=True, capture_output=True, timeout=30)
    assert importlib.util.find_spec("appsec_review.signing.core") is not None
