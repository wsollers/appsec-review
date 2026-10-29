"""Stdlib-only Ed25519 signing primitives over the system OpenSSL command line.

This module must stay loadable by file path under ``python -I -S``: it imports only the standard
library and nothing from ``appsec_review``. Every failure to establish a valid signature raises
``SignatureVerificationError``; nothing here reports an unverifiable object as trusted.
"""
from __future__ import annotations

import base64
import binascii
from collections.abc import Iterator, Mapping
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any


STATEMENT_SCHEMA = "appsec-review.signed-statement/v1"
ALGORITHM = "ed25519"
DEFAULT_OPENSSL = "/usr/bin/openssl"
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_ENVELOPE_BYTES = 64 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
MAX_SIGNATURES = 16
SIGNATURE_BYTES = 64

ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_ED25519_SPKI_BYTES = len(ED25519_SPKI_PREFIX) + 32
_SANITIZED_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "OPENSSL_CONF": "/dev/null"}
_KEY_ID = re.compile(r"sha256:[0-9a-f]{64}")
_KEY_FILE = re.compile(r"([0-9a-f]{64})\.pem")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

# RFC 8032 section 7.1, TEST 2. OpenSSL 3.0 cannot sign or verify an empty -rawin message (TEST 1).
_KAT_PUBLIC_KEY = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
_KAT_MESSAGE = bytes.fromhex("72")
_KAT_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")


class SignatureVerificationError(Exception):
    """A signature, trust anchor, or envelope could not be verified; callers must fail closed."""


def key_id(public_key_der: bytes) -> str:
    if not isinstance(public_key_der, (bytes, bytearray)) or not public_key_der:
        raise SignatureVerificationError("public key DER must be non-empty bytes")
    return "sha256:" + hashlib.sha256(bytes(public_key_der)).hexdigest()


def ed25519_public_key_pem(raw_public_key: bytes) -> bytes:
    """Wrap a raw 32-byte Ed25519 public key as an SPKI PEM document."""
    if len(raw_public_key) != 32:
        raise SignatureVerificationError("raw Ed25519 public key must be 32 bytes")
    return _der_to_pem(ED25519_SPKI_PREFIX + bytes(raw_public_key))


def _der_to_pem(der: bytes) -> bytes:
    body = base64.b64encode(der)
    lines = [body[index:index + 64] for index in range(0, len(body), 64)]
    return b"-----BEGIN PUBLIC KEY-----\n" + b"\n".join(lines) + b"\n-----END PUBLIC KEY-----\n"


def _check_canonical_value(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise ValueError("canonical JSON rejects floating-point values")
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_canonical_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON object keys must be strings")
            _check_canonical_value(item)
        return
    raise ValueError(f"canonical JSON rejects values of type {type(value).__name__}")


def canonical_json(obj: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no whitespace, no floats, string keys only."""
    try:
        _check_canonical_value(obj)
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except RecursionError as error:
        raise ValueError("canonical JSON value is nested too deeply") from error
    except UnicodeEncodeError as error:
        raise ValueError("canonical JSON strings must be valid Unicode") from error


def make_statement(kind: str, subject: dict) -> dict:
    if not isinstance(kind, str) or not kind:
        raise ValueError("statement kind must be a non-empty string")
    if not isinstance(subject, dict):
        raise ValueError("statement subject must be an object")
    return {"schema": STATEMENT_SCHEMA, "kind": kind, "subject": json.loads(canonical_json(subject))}


@contextlib.contextmanager
def _private_directory(parent: str | None) -> Iterator[Path]:
    directory = tempfile.mkdtemp(prefix="appsec-review-openssl-", dir=parent)
    try:
        os.chmod(directory, 0o700)
        yield Path(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _write_new_file(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        if descriptor != -1:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise


def _read_regular_file(path: Path, limit: int, what: str) -> bytes:
    try:
        info = os.lstat(path)
    except FileNotFoundError as error:
        raise SignatureVerificationError(f"{what} is missing: {path}") from error
    except OSError as error:
        raise SignatureVerificationError(f"{what} cannot be inspected: {path}: {error}") from error
    if stat.S_ISLNK(info.st_mode):
        raise SignatureVerificationError(f"{what} must not be a symbolic link: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise SignatureVerificationError(f"{what} must be a regular file: {path}")
    try:
        descriptor = os.open(path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except OSError as error:
        raise SignatureVerificationError(f"{what} cannot be opened: {path}: {error}") from error
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise SignatureVerificationError(f"{what} changed while it was opened: {path}")
        if opened.st_size > limit:
            raise SignatureVerificationError(f"{what} exceeds {limit} bytes: {path}")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise SignatureVerificationError(f"{what} exceeds {limit} bytes: {path}")
    return data


class OpenSSL:
    """Absolute-path OpenSSL 3 CLI run without a shell and with a fixed, minimal environment."""

    def __init__(self, binary: str = DEFAULT_OPENSSL, *, timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 temp_dir: str | None = None) -> None:
        binary = os.fspath(binary)
        if not isinstance(binary, str) or not os.path.isabs(binary):
            raise SignatureVerificationError(f"OpenSSL binary must be an absolute path: {binary!r}")
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise SignatureVerificationError(f"OpenSSL binary is not an executable file: {binary}")
        self.binary = binary
        self.timeout = float(timeout)
        self.temp_dir = temp_dir

    def _run(self, arguments: list[str], *, stdin: bytes | None = None,
             check: bool = True) -> subprocess.CompletedProcess[bytes]:
        try:
            completed = subprocess.run(
                [self.binary, *arguments], input=stdin,
                stdin=subprocess.DEVNULL if stdin is None else None,
                capture_output=True, env=dict(_SANITIZED_ENV), cwd="/", shell=False,
                close_fds=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise SignatureVerificationError(f"openssl {arguments[0]} timed out") from error
        except OSError as error:
            raise SignatureVerificationError(f"openssl {arguments[0]} could not run: {error}") from error
        if check and completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", "replace").strip()[:500]
            raise SignatureVerificationError(
                f"openssl {arguments[0]} failed with exit code {completed.returncode}: {detail}")
        return completed

    def generate_private_key(self, path: str | os.PathLike[str]) -> Path:
        target = Path(os.path.abspath(path))
        if not target.parent.exists():
            target.parent.mkdir(mode=0o700, parents=True)
            os.chmod(target.parent, 0o700)
        if os.path.lexists(target):
            raise FileExistsError(f"private key already exists: {target}")
        pem = self._run(["genpkey", "-algorithm", "ed25519"]).stdout
        if not pem.startswith(b"-----BEGIN PRIVATE KEY-----"):
            raise SignatureVerificationError("openssl genpkey did not produce a PEM private key")
        _write_new_file(target, pem, 0o600)
        return target

    def public_key_pem(self, private_key_path: str | os.PathLike[str]) -> bytes:
        pem = self._run(["pkey", "-in", os.path.abspath(private_key_path), "-pubout"]).stdout
        return _der_to_pem(self.public_key_der(pem))

    def public_key_der(self, public_key_pem: bytes) -> bytes:
        if not isinstance(public_key_pem, (bytes, bytearray)) or not public_key_pem:
            raise SignatureVerificationError("public key PEM must be non-empty bytes")
        der = self._run(["pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
                        stdin=bytes(public_key_pem)).stdout
        if len(der) != _ED25519_SPKI_BYTES or not der.startswith(ED25519_SPKI_PREFIX):
            raise SignatureVerificationError("public key is not an Ed25519 SubjectPublicKeyInfo")
        return der

    def sign(self, private_key_path: str | os.PathLike[str], message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)) or not message:
            raise SignatureVerificationError("message to sign must be non-empty bytes")
        with _private_directory(self.temp_dir) as directory:
            message_path = directory / "message"
            _write_new_file(message_path, bytes(message), 0o600)
            signature = self._run(["pkeyutl", "-sign", "-inkey", os.path.abspath(private_key_path),
                                   "-rawin", "-in", str(message_path)]).stdout
        if len(signature) != SIGNATURE_BYTES:
            raise SignatureVerificationError("openssl did not produce a 64-byte Ed25519 signature")
        return signature

    def verify(self, public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        if not isinstance(message, (bytes, bytearray)) or not message:
            return False
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_BYTES:
            return False
        if not isinstance(public_key_pem, (bytes, bytearray)) or not public_key_pem:
            raise SignatureVerificationError("public key PEM must be non-empty bytes")
        with _private_directory(self.temp_dir) as directory:
            key_path, message_path, signature_path = (
                directory / "key.pem", directory / "message", directory / "signature")
            _write_new_file(key_path, bytes(public_key_pem), 0o600)
            _write_new_file(message_path, bytes(message), 0o600)
            _write_new_file(signature_path, bytes(signature), 0o600)
            completed = self._run(["pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-rawin",
                                   "-in", str(message_path), "-sigfile", str(signature_path)],
                                  check=False)
        if completed.returncode == 0 and b"Signature Verified Successfully" in completed.stdout:
            return True
        if completed.returncode == 1 and b"Signature Verification Failure" in completed.stdout:
            return False
        detail = completed.stderr.decode("utf-8", "replace").strip()[:500]
        raise SignatureVerificationError(
            f"openssl pkeyutl -verify failed with exit code {completed.returncode}: {detail}")

    def self_test(self) -> bool:
        """Verify the RFC 8032 known answer and reject a one-bit corruption of it."""
        public_key_pem = ed25519_public_key_pem(_KAT_PUBLIC_KEY)
        if self.public_key_der(public_key_pem) != ED25519_SPKI_PREFIX + _KAT_PUBLIC_KEY:
            raise SignatureVerificationError("OpenSSL self-test failed: Ed25519 key round trip")
        if not self.verify(public_key_pem, _KAT_MESSAGE, _KAT_SIGNATURE):
            raise SignatureVerificationError("OpenSSL self-test failed: known-answer signature rejected")
        corrupted = bytes([_KAT_SIGNATURE[0] ^ 0x01]) + _KAT_SIGNATURE[1:]
        if self.verify(public_key_pem, _KAT_MESSAGE, corrupted):
            raise SignatureVerificationError("OpenSSL self-test failed: corrupted signature accepted")
        return True


class TrustedKeys(Mapping[str, bytes]):
    """Trust anchors keyed by recomputed key ID; values are normalized Ed25519 public-key PEM."""

    def __init__(self, keys: Mapping[str, bytes] | None = None) -> None:
        self._keys = dict(keys or {})

    def __getitem__(self, key: str) -> bytes:
        return self._keys[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def load(cls, directory: str | os.PathLike[str], openssl: OpenSSL) -> TrustedKeys:
        """Load ``<hex>.pem`` anchors; a missing or empty directory loads no keys and verifies nothing."""
        root = Path(directory)
        if not root.exists():
            return cls()
        if not root.is_dir():
            raise SignatureVerificationError(f"trusted keys path is not a directory: {root}")
        keys: dict[str, bytes] = {}
        with os.scandir(root) as entries:
            names = sorted(entry.name for entry in entries if entry.name.endswith(".pem"))
        for name in names:
            path = root / name
            match = _KEY_FILE.fullmatch(name)
            if match is None:
                raise SignatureVerificationError(f"trusted key file name is not <sha256-hex>.pem: {path}")
            der = openssl.public_key_der(_read_regular_file(path, MAX_PUBLIC_KEY_BYTES, "trusted key"))
            identity = key_id(der)
            if identity != "sha256:" + match.group(1):
                raise SignatureVerificationError(
                    f"trusted key file name does not match its key ID {identity}: {path}")
            keys[identity] = _der_to_pem(der)
        return cls(keys)


def _check_statement(statement: Any, kind: str | None = None) -> None:
    if not isinstance(statement, dict) or set(statement) != {"schema", "kind", "subject"}:
        raise SignatureVerificationError("statement must have exactly schema, kind, and subject")
    if statement["schema"] != STATEMENT_SCHEMA:
        raise SignatureVerificationError(f"unsupported statement schema: {statement['schema']!r}")
    if not isinstance(statement["kind"], str) or not statement["kind"]:
        raise SignatureVerificationError("statement kind must be a non-empty string")
    if kind is not None and statement["kind"] != kind:
        raise SignatureVerificationError(
            f"statement kind {statement['kind']!r} does not match expected {kind!r}")
    if not isinstance(statement["subject"], dict):
        raise SignatureVerificationError("statement subject must be an object")


def _canonical_statement(statement: Any, kind: str | None = None) -> bytes:
    _check_statement(statement, kind)
    try:
        return canonical_json(statement)
    except ValueError as error:
        raise SignatureVerificationError(f"statement is not canonical JSON: {error}") from error


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise SignatureVerificationError("signature must be a base64 string")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise SignatureVerificationError("signature is not strict base64") from error
    if base64.b64encode(raw).decode("ascii") != value:
        raise SignatureVerificationError("signature is not canonical base64")
    if len(raw) != SIGNATURE_BYTES:
        raise SignatureVerificationError(f"signature must decode to {SIGNATURE_BYTES} bytes")
    return raw


def _parsed_signatures(signatures: Any) -> list[tuple[str, bytes]]:
    if not isinstance(signatures, list) or not signatures:
        raise SignatureVerificationError("envelope signatures must be a non-empty list")
    if len(signatures) > MAX_SIGNATURES:
        raise SignatureVerificationError(f"envelope carries more than {MAX_SIGNATURES} signatures")
    parsed: list[tuple[str, bytes]] = []
    for entry in signatures:
        if not isinstance(entry, dict) or set(entry) != {"key_id", "algorithm", "signature"}:
            raise SignatureVerificationError(
                "signature entry must have exactly key_id, algorithm, and signature")
        if entry["algorithm"] != ALGORITHM:
            raise SignatureVerificationError(f"unsupported signature algorithm: {entry['algorithm']!r}")
        if not isinstance(entry["key_id"], str) or not _KEY_ID.fullmatch(entry["key_id"]):
            raise SignatureVerificationError("signature key_id must be sha256:<64 lowercase hex>")
        if any(entry["key_id"] == seen for seen, _ in parsed):
            raise SignatureVerificationError(f"duplicate signature for key {entry['key_id']}")
        parsed.append((entry["key_id"], _decode_signature(entry["signature"])))
    return parsed


def _check_envelope(envelope: Any) -> None:
    if not isinstance(envelope, dict) or set(envelope) != {"statement", "signatures"}:
        raise SignatureVerificationError("envelope must have exactly statement and signatures")


def sign_statement(openssl: OpenSSL, private_key_path: str | os.PathLike[str], statement: dict) -> dict:
    message = _canonical_statement(statement)
    signature = openssl.sign(private_key_path, message)
    public_key_pem = openssl.public_key_pem(private_key_path)
    if not openssl.verify(public_key_pem, message, signature):
        raise SignatureVerificationError("freshly produced signature does not verify")
    return {
        "statement": json.loads(message),
        "signatures": [{
            "key_id": key_id(openssl.public_key_der(public_key_pem)),
            "algorithm": ALGORITHM,
            "signature": base64.b64encode(signature).decode("ascii"),
        }],
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"JSON constant {name} is not allowed")


def _reject_float(text: str) -> Any:
    raise ValueError("JSON floating-point numbers are not allowed")


def parse_envelope(data: bytes) -> dict:
    """Strictly parse envelope bytes without verifying any signature."""
    if not isinstance(data, (bytes, bytearray)):
        raise SignatureVerificationError("envelope bytes are required")
    if len(data) > MAX_ENVELOPE_BYTES:
        raise SignatureVerificationError(f"envelope exceeds {MAX_ENVELOPE_BYTES} bytes")
    try:
        value = json.loads(bytes(data).decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                           parse_constant=_reject_constant, parse_float=_reject_float)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise SignatureVerificationError(f"envelope is not strict JSON: {error}") from error
    _check_envelope(value)
    return value


def verify_envelope(envelope: dict | bytes, trusted: TrustedKeys, openssl: OpenSSL, *, kind: str) -> dict:
    """Return the statement only if at least one trusted key signed it and no trusted signature fails.

    Signatures by keys outside ``trusted`` are ignored, so they never suffice on their own.
    """
    if isinstance(envelope, (bytes, bytearray)):
        envelope = parse_envelope(envelope)
    _check_envelope(envelope)
    message = _canonical_statement(envelope["statement"], kind)
    signatures = _parsed_signatures(envelope["signatures"])
    if not trusted:
        raise SignatureVerificationError("no trusted signing keys are configured")
    verified = 0
    for identity, signature in signatures:
        public_key_pem = trusted.get(identity)
        if public_key_pem is None:
            continue
        if not openssl.verify(public_key_pem, message, signature):
            raise SignatureVerificationError(f"signature by trusted key {identity} does not verify")
        verified += 1
    if not verified:
        raise SignatureVerificationError("envelope has no signature from a trusted key")
    return json.loads(message)


def write_envelope(path: str | os.PathLike[str], envelope: dict) -> None:
    """Atomically write a structurally valid envelope as canonical JSON plus a newline."""
    _check_envelope(envelope)
    _canonical_statement(envelope["statement"])
    _parsed_signatures(envelope["signatures"])
    try:
        data = canonical_json(envelope) + b"\n"
    except ValueError as error:
        raise SignatureVerificationError(f"envelope is not canonical JSON: {error}") from error
    target = Path(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o644)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    if hasattr(os, "O_DIRECTORY"):
        with contextlib.suppress(OSError):
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


def read_envelope(path: str | os.PathLike[str]) -> dict:
    """Read and strictly parse an envelope file (no symlinks, size-capped); signatures are unchecked."""
    return parse_envelope(_read_regular_file(Path(path), MAX_ENVELOPE_BYTES, "signature envelope"))
