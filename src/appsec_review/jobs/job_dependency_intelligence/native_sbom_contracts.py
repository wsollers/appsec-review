"""Shared data contracts for bounded native discovery and SPDX publication."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
import hashlib
from typing import Any, Literal, TypedDict

from appsec_review.storage import canonical_json


DISCOVERY_SCHEMA = "appsec-review/native-discovery/1"
PROVENANCE_SCHEMA = "appsec-review/native-sbom-provenance/1"
METRICS_SCHEMA = "appsec-review/native-sbom-metrics/1"
DISCOVERY_IDENTITY = "native-discovery/1"
MERGE_IDENTITY = "native-spdx-enrichment/1"
SPDX_VERSION = "SPDX-2.3"
ClaimStatus = Literal["unknown", "inferred", "corroborated", "conflicted"]
PublicationStatus = Literal["SUCCEEDED", "COMPLETED_WITH_GAPS", "FAILED"]
GAP_KINDS = frozenset({
    "input_missing", "upstream_partial", "unmapped_path", "unsupported_response_file",
    "unsupported_metadata", "decode_failed", "read_failed", "bounds", "ambiguous_root",
    "identity_conflict", "version_conflict", "repository_conflict",
    "sbom_conversion_failed", "sbom_validation_failed", "artifact_inventory_not_merged",
})
DISCOVERY_COUNTERS = (
    "eligible_files", "selected_files", "read_files", "unsupported_files", "omitted_files",
    "bytes_read", "roots_inspected", "commands_available", "commands_processed",
    "commands_truncated", "artifacts_inspected", "candidates_total",
    "identities_unknown", "identities_inferred", "identities_corroborated", "identities_conflicted",
    "releases_unknown", "releases_inferred", "releases_corroborated", "releases_conflicted",
)
SBOM_COUNTERS = (
    "baseline_packages", "native_additions", "exact_merges", "unresolved_matches", "conflicts",
    "output_packages", "output_relationships", "output_bytes",
)
METRIC_COUNTERS = (*DISCOVERY_COUNTERS, *SBOM_COUNTERS)


class NativeInputIntegrityError(ValueError):
    """Accepted native evidence no longer matches its bound identity."""


class SpdxValidationError(ValueError):
    """An SPDX document violates the standard or reference integrity."""


def _positive_bounds(value: object) -> None:
    for field in fields(value):
        bound = getattr(value, field.name)
        if type(bound) is not int or bound < 1:
            raise ValueError(f"{field.name} must be a positive integer")


@dataclass(frozen=True)
class NativeBounds:
    candidate_limit: int
    command_token_limit: int
    file_limit: int
    bytes_per_file: int
    source_bytes_limit: int
    root_limit: int
    evidence_limit: int
    evidence_per_candidate: int
    field_bytes: int
    path_chars: int

    def __post_init__(self) -> None:
        _positive_bounds(self)


@dataclass(frozen=True)
class SbomBounds:
    input_bytes: int
    element_limit: int
    output_bytes: int
    field_bytes: int

    def __post_init__(self) -> None:
        _positive_bounds(self)


class ArtifactRef(TypedDict):
    path: str
    sha256: str
    size_bytes: int


class NativeFile(TypedDict):
    domain: Literal["target", "workspace"]
    root_id: str
    path: str
    sha256: str
    size_bytes: int
    upstream: ArtifactRef
    backing: ArtifactRef | None


class NativeEvidence(TypedDict):
    evidence_id: str
    kind: str
    value: str
    source_fingerprint: str
    domain: str
    root_id: str
    path: str
    sha256: str
    upstream: ArtifactRef
    backing: ArtifactRef | None
    selector: dict[str, Any]


class Claim(TypedDict):
    value: str | None
    status: ClaimStatus
    evidence_ids: list[str]
    alternatives: list[str]


class NativeCandidate(TypedDict):
    candidate_id: str
    native_name: str
    observations: list[dict[str, Any]]
    metadata: dict[str, Any]
    repository: dict[str, Any] | None
    package_root: str
    root_id: str
    identity: Claim
    release: Claim
    upstream: Claim
    evidence_ids: list[str]


class CoverageGap(TypedDict):
    kind: str
    scope: str
    detail: str
    evidence_ids: list[str]


class DiscoveryResult(TypedDict):
    schema: str
    candidates: list[NativeCandidate]
    evidence: list[NativeEvidence]
    gaps: list[CoverageGap]
    coverage: dict[str, Any]
    metrics: dict[str, int]


class SpdxBaseline(TypedDict):
    document: Mapping[str, Any]
    artifact: ArtifactRef
    source_artifact: ArtifactRef
    tool_identity: Mapping[str, str]


class SbomResult(TypedDict):
    document: Mapping[str, Any]
    provenance: Mapping[str, Any]
    gaps: list[CoverageGap]
    metrics: dict[str, int]


class NativeSbomMetrics(TypedDict):
    schema: str
    source_fingerprint: str
    run_id: str
    job_id: str
    attempt_id: str
    unit_id: str
    status: PublicationStatus
    discovery_status: str
    conversion_status: str
    validation_status: str
    input_fingerprint: str
    sbom_sha256: str | None
    counters: dict[str, int]
    gaps_by_kind: dict[str, int]


def evidence_identity(record: Mapping[str, Any]) -> str:
    value = {key: item for key, item in record.items() if key != "evidence_id"}
    return "native-evidence-" + hashlib.sha256(canonical_json(value)).hexdigest()


def candidate_identity(source_fingerprint: str, root_id: str, package_root: str, name: str) -> str:
    value = (source_fingerprint, root_id, package_root, name.casefold())
    return "native-dependency-" + hashlib.sha256(canonical_json(value)).hexdigest()[:32]
