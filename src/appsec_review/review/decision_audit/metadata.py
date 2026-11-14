"""Accepted publication metadata for the protected audit sidecar.

The runner retains ``metadata_path`` and pins the explicit artifact references in the
unit payload. This descriptor binds the audit without extending generic control keys
or changing the original inner review handoff.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib

from appsec_review.config.inference_review import DecisionAuditSettings
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json

from .contracts import ManifestRef, Origin

PUBLICATION_SCHEMA = "appsec-review/review-audit-publication/1"
POLICY_VERSION = "decision-audit-projection/1"
UNAVAILABLE_REASONS = frozenset({"disabled", "capacity_exceeded", "input_unavailable"})
_FIELDS = frozenset({"schema", "origin", "status", "manifest", "unavailable_reason", "policy"})


@dataclass(frozen=True, slots=True)
class PublicationMetadata:
    origin: Origin
    settings: DecisionAuditSettings
    manifest: ManifestRef | None
    unavailable_reason: str | None


def policy_document(settings: DecisionAuditSettings) -> dict[str, object]:
    checked = DecisionAuditSettings.from_mapping(asdict(settings), "decision_audit")
    body = {"version": POLICY_VERSION, "settings": asdict(checked)}
    return {**body, "sha256": hashlib.sha256(canonical_json(body)).hexdigest()}


def _policy_matches(value: object, expected: Mapping[str, object]) -> bool:
    if (not isinstance(value, Mapping) or set(value) != {"version", "settings", "sha256"}
            or not isinstance(value["settings"], Mapping)):
        return False
    try:
        checked = DecisionAuditSettings.from_mapping(value["settings"], "decision_audit")
    except ValueError:
        return False
    return (value["version"] == POLICY_VERSION
            and value["sha256"] == expected["sha256"]
            and asdict(checked) == expected["settings"])


def read_publication(document: object, *, expected_origin: Origin,
                     settings: DecisionAuditSettings) -> PublicationMetadata:
    """Validate metadata against independently verified run/configuration inputs."""
    if not isinstance(document, Mapping) or set(document) != _FIELDS:
        raise IntegrityError("audit publication metadata has invalid fields")
    if document["schema"] != PUBLICATION_SCHEMA:
        raise IntegrityError("audit publication schema is unsupported")
    policy = policy_document(settings)
    if (expected_origin.projection_policy_version != POLICY_VERSION
            or expected_origin.projection_policy_sha256 != policy["sha256"]):
        raise IntegrityError("expected audit origin disagrees with frozen projection policy")
    if document["origin"] != expected_origin.to_dict():
        raise IntegrityError("audit publication origin disagrees with accepted review")
    if not _policy_matches(document["policy"], policy):
        raise IntegrityError("audit publication policy disagrees with frozen configuration")
    reason = document["unavailable_reason"]
    if document["status"] == "available":
        if not settings.enabled or reason is not None or document["manifest"] is None:
            raise IntegrityError("available audit disagrees with its policy or manifest")
        manifest = ManifestRef.from_document(document["manifest"], expected_origin=expected_origin)
    elif document["status"] == "unavailable":
        if (document["manifest"] is not None or not isinstance(reason, str)
                or reason not in UNAVAILABLE_REASONS
                or (reason == "disabled") != (not settings.enabled)):
            raise IntegrityError("unavailable audit lacks a valid policy-bound reason")
        manifest = None
    else:
        raise IntegrityError("audit publication status is unsupported")
    return PublicationMetadata(expected_origin, settings, manifest, reason)


def build_publication(origin: Origin, *, settings: DecisionAuditSettings,
                      manifest: ManifestRef | None = None,
                      unavailable_reason: str | None = None) -> dict[str, object]:
    document: dict[str, object] = {
        "schema": PUBLICATION_SCHEMA,
        "origin": origin.to_dict(),
        "status": "available" if manifest is not None else "unavailable",
        "manifest": manifest.to_dict() if manifest is not None else None,
        "unavailable_reason": unavailable_reason,
        "policy": policy_document(settings),
    }
    read_publication(document, expected_origin=origin, settings=settings)
    return document
