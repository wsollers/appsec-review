"""Shared contracts for evidence-bound native SBOM inference stages."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
import hashlib
from typing import Any, Literal, Protocol, TypedDict

from appsec_review.storage import canonical_json

from .native_sbom_contracts import CoverageGap, DiscoveryResult


CURATION_SCHEMA = "appsec-review/native-component-curation/1"
PLAN_SCHEMA = "appsec-review/native-metadata-plan/1"
METADATA_SCHEMA = "appsec-review/native-metadata-proposal/1"
INVESTIGATION_SCHEMA = "appsec-review/native-metadata-investigation/1"
INFERENCE_METRICS_SCHEMA = "appsec-review/native-inference-metrics/1"
INFERENCE_COUNTERS = (
    "input_candidates", "curated_components", "sdk_groups", "excluded_candidates",
    "uncertain_candidates", "roots_investigated", "files_read", "bytes_read",
    "version_claims", "versions_corroborated", "purl_claims", "purls_corroborated",
    "conflicts", "model_calls", "model_failures", "input_tokens", "output_tokens",
    "cache_tokens", "unknown_usage_calls", "omitted_candidates", "omitted_files",
)


class NativeInferenceError(RuntimeError):
    """A bounded inference request failed; its disposition must remain visible."""

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


@dataclass(frozen=True)
class NativeInferenceBounds:
    batch_candidates: int = 32
    max_payload_bytes: int = 98304
    max_calls: int = 256
    component_limit: int = 10000
    group_limit: int = 2048
    files_per_root: int = 128
    bytes_per_file: int = 262144
    source_bytes_limit: int = 8388608
    field_bytes: int = 4096

    def __post_init__(self) -> None:
        for field in fields(self):
            if type(getattr(self, field.name)) is not int or getattr(self, field.name) < 1:
                raise ValueError(f"{field.name} must be a positive integer")


class Propose(Protocol):
    def __call__(self, stage: Literal["curate", "plan", "metadata"],
                 payload: Mapping[str, Any]) -> Mapping[str, Any]: ...


class CuratedComponent(TypedDict):
    component_id: str
    name: str
    kind: Literal["library", "sdk-component"]
    candidate_ids: list[str]
    source_candidate_ids: list[str]
    supporting_paths: list[str]
    basis: str


class SdkGroup(TypedDict):
    group_id: str
    name: str
    component_ids: list[str]
    supporting_paths: list[str]
    basis: str


class CurationResult(TypedDict):
    schema: str
    discovery: DiscoveryResult
    components: list[CuratedComponent]
    sdk_groups: list[SdkGroup]
    decisions: list[dict[str, Any]]
    gaps: list[CoverageGap]
    metrics: dict[str, int]


class InvestigationResult(TypedDict):
    schema: str
    discovery: DiscoveryResult
    findings: list[dict[str, Any]]
    gaps: list[CoverageGap]
    metrics: dict[str, int]


def inference_identity(kind: str, value: Mapping[str, Any]) -> str:
    return f"native-{kind}-" + hashlib.sha256(canonical_json(value)).hexdigest()[:32]
