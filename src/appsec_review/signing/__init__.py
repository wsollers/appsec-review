"""Ed25519 signing and verification for container images and Python modules."""
from .core import (
    ALGORITHM,
    STATEMENT_SCHEMA,
    OpenSSL,
    SignatureVerificationError,
    TrustedKeys,
    canonical_json,
    ed25519_public_key_pem,
    key_id,
    make_statement,
    parse_envelope,
    read_envelope,
    sign_statement,
    verify_envelope,
    write_envelope,
)

__all__ = [
    "ALGORITHM",
    "STATEMENT_SCHEMA",
    "OpenSSL",
    "SignatureVerificationError",
    "TrustedKeys",
    "canonical_json",
    "ed25519_public_key_pem",
    "key_id",
    "make_statement",
    "parse_envelope",
    "read_envelope",
    "sign_statement",
    "verify_envelope",
    "write_envelope",
]
