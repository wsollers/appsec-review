"""Canonical identities for review records.

Every identity is a lowercase prefix plus SHA-256 over versioned canonical JSON. Records keep the
full hash; ``short_id`` is for display only and callers must check collisions.
"""
from __future__ import annotations

import hashlib
from typing import Any, Mapping

from appsec_review.storage.atomic import canonical_json

PREFIXES = {
    "claim": "claim", "evidence_relation": "evrel", "evidence_request": "evreq", "review": "review",
    "adjudication": "adjudication", "score": "score", "cell": "cell", "actor": "actor", "gap": "gap",
    "event": "event", "package": "package", "finding_package": "finding", "team": "team",
}


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def make_id(kind: str, version: int, body: Mapping[str, Any]) -> str:
    """Return ``<prefix>-<sha256>`` over ``{"kind", "version", "body"}``."""
    try:
        prefix = PREFIXES[kind]
    except KeyError as exc:
        raise ValueError(f"unknown identity kind: {kind}") from exc
    if version < 1:
        raise ValueError("identity version must be positive")
    return f"{prefix}-{sha256_hex({'kind': kind, 'version': version, 'body': dict(body)})}"


def short_id(identity: str, length: int = 24) -> str:
    prefix, _, digest = identity.partition("-")
    if not digest:
        raise ValueError("identity has no digest")
    return f"{prefix}-{digest[:length]}"
