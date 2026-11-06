"""Pure deployment records. Caller-owned admission is separate from target declarations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any, Literal, TypeAlias

from appsec_review.retrieval.model import normalize_relative_path
from appsec_review.storage import canonical_json


Outcome: TypeAlias = Literal["complete", "partial", "unsupported", "malformed"]
Scope: TypeAlias = Literal["target", "analysis_platform"]
Authority: TypeAlias = Literal["target_declaration", "imported_observation"]
EvidenceClass: TypeAlias = Literal[
    "dependency_installed", "product_hint", "configured_listener", "selected_deployment",
    "observed_listener", "proven_reachability", "deployment_declaration",
]
SCHEMA = "appsec-review/deployment-inventory/1"
EVIDENCE_SCHEMA = "appsec-review/deployment-evidence/1"
OBSERVATION_SCHEMA = "appsec-review/deployment-observations/1"
CATALOG_SCHEMA = "appsec-review/deployment-signatures/1"


def identity(kind: str, value: object) -> str:
    return f"deployment:{kind}:" + hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class Limits:
    max_documents: int = 64
    max_document_bytes: int = 524_288
    max_total_bytes: int = 4_194_304
    max_depth: int = 32
    max_nodes: int = 20_000
    max_records: int = 10_000

    def __post_init__(self) -> None:
        ceilings = (256, 2_097_152, 16_777_216, 64, 100_000, 50_000)
        if any(type(value) is not int or not 1 <= value <= ceiling
               for value, ceiling in zip(asdict(self).values(), ceilings, strict=True)):
            raise ValueError("deployment parser limits must be positive bounded integers")


@dataclass(frozen=True)
class SourceDocument:
    """Exact admitted bytes, never a path to open or instructions to execute.

    Scope, deployment and variant are supplied by the trusted adapter, not inferred from
    target labels. A config's service names a descriptor service key in that deployment.
    """

    path: str
    data: bytes
    sha256: str
    format: str
    deployment: str
    scope: Scope = "target"
    variant: str | None = None
    service: str | None = None

    def __post_init__(self) -> None:
        if (normalize_relative_path(self.path) != self.path or "\\" in self.path
                or len(self.path) > 1024):
            raise ValueError("source path must be canonical and target-relative")
        if not isinstance(self.data, bytes):
            raise ValueError("source data must be exact bytes")
        for value in (self.format, self.deployment):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError("source requires bounded format and deployment identifiers")
        if self.scope not in {"target", "analysis_platform"}:
            raise ValueError("source scope must be assigned by the admission adapter")
        for optional_value in (self.variant, self.service):
            if optional_value is not None and (
                not isinstance(optional_value, str) or not optional_value or len(optional_value) > 256
            ):
                raise ValueError("invalid variant or service binding")

    def reference(self, target_snapshot: str) -> Source:
        payload = {
            "target_snapshot": target_snapshot, "path": self.path, "sha256": self.sha256,
            "format": self.format, "deployment": self.deployment, "scope": self.scope,
            "variant": self.variant, "service": self.service, "size_bytes": len(self.data),
        }
        return Source(identity("source", payload), target_snapshot, self.path, self.sha256,
                      self.format, self.deployment, self.scope, self.variant, self.service, len(self.data))


@dataclass(frozen=True)
class Selection:
    """An adapter's selected, already-rendered variant, not proof of a running deployment."""

    deployment: str
    variant: str
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if (not isinstance(self.deployment, str) or not self.deployment or len(self.deployment) > 256
                or not isinstance(self.variant, str) or not self.variant or len(self.variant) > 256
                or not isinstance(self.paths, tuple) or not self.paths
                or len(self.paths) > 256 or len(set(self.paths)) != len(self.paths)
                or any(normalize_relative_path(path) != path for path in self.paths)):
            raise ValueError("selection requires a variant and unique admitted paths")


@dataclass(frozen=True)
class Source:
    id: str
    target_snapshot: str
    path: str
    sha256: str
    format: str
    deployment: str
    scope: Scope
    variant: str | None
    service: str | None
    size_bytes: int


@dataclass(frozen=True)
class Evidence:
    id: str
    source_id: str
    path: str
    sha256: str
    start_line: int
    end_line: int
    start_byte: int
    end_byte: int
    rule: str
    authority: Authority = "target_declaration"
    schema: str = EVIDENCE_SCHEMA


@dataclass(frozen=True)
class Gap:
    code: str
    message: str
    source_id: str | None = None
    service_id: str | None = None
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Coverage:
    source_id: str
    outcome: Outcome
    disposition: Literal["analyzed", "excluded"]
    rules: tuple[str, ...]
    gaps: tuple[Gap, ...]


@dataclass
class Service:
    id: str
    key: str
    name: str
    deployment: str
    variant: str | None
    kind: Literal["compose", "kubernetes_workload", "kubernetes_service", "configuration"]
    namespace: str | None
    product: str | None = None
    declared_version: str | None = None
    version_precision: Literal["major", "minor", "patch"] | None = None
    image: str | None = None
    identity: str | None = None
    selection: Literal["selected", "not_selected", "unknown"] = "unknown"
    selected_variant: str | None = None
    evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=lambda: [
        "effective_configuration", "running_version", "observed_listeners", "reachability",
    ])


@dataclass(frozen=True)
class Listener:
    id: str
    service_id: str
    address: str | None
    port: int | None
    transport: Literal["tcp", "udp", "sctp"]
    role: Literal["container", "published", "service", "node", "configuration"]
    name: str | None
    tls: bool | None
    evidence_class: EvidenceClass
    evidence: tuple[str, ...]
    # Static descriptors never establish an effective bind or network reachability.
    effective: Literal["unknown"] = "unknown"


@dataclass
class Relationship:
    id: str
    source_service_id: str
    target_service_id: str | None
    target: str
    target_port: int | None
    kind: Literal["depends_on", "proxy_backend", "selects", "routes_to"]
    evidence: list[str]
    resolution: Literal["resolved", "unresolved", "ambiguous"] = "unresolved"
    route: str | None = None


@dataclass(frozen=True)
class Fact:
    service_id: str
    evidence_class: EvidenceClass
    detail: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Conflict:
    service_id: str
    field: str
    values: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass
class Inventory:
    target_snapshot: str
    outcome: Outcome = "complete"
    schema: str = SCHEMA
    catalog_schema: str = CATALOG_SCHEMA
    catalog_sha256: str = ""
    sources: list[Source] = field(default_factory=list)
    selections: list[Selection] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        # Round-trip to JSON primitives: tuples at the typed boundary become JSON arrays.
        import json

        value = json.loads(canonical_json(asdict(self)))
        assert isinstance(value, dict)
        return value


def resolve_evidence(evidence: Evidence, source: SourceDocument) -> bytes:
    """Resolve the exact original span; no filesystem reads or newline normalization."""
    if (source.path != evidence.path or source.sha256 != evidence.sha256
            or hashlib.sha256(source.data).hexdigest() != evidence.sha256):
        raise ValueError("deployment evidence source identity differs")
    if not 0 <= evidence.start_byte < evidence.end_byte <= len(source.data):
        raise ValueError("deployment evidence byte span is invalid")
    prefix = source.data[:evidence.start_byte]
    span = source.data[evidence.start_byte:evidence.end_byte]
    if (prefix.count(b"\n") + 1 != evidence.start_line
            or evidence.start_line + span.rstrip(b"\r\n").count(b"\n") != evidence.end_line):
        raise ValueError("deployment evidence line span differs")
    return span
