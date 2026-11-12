"""Shared contract of the generated DFD and threat model (T-107).

Closed vocabularies, immutable records, stable identities and canonical bytes. Every chunk imports
this module and none edits it; see docs/architecture/dfd-and-threat-model-generation.md. A record
here is a claim about the *generated model*, never the target owner's statement: ``Origin`` cannot
be built as target-supplied, and an element, flow, boundary or threat cannot exist without at least
one evidence reference.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from enum import StrEnum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Mapping

JOB_ID = "job_threat_model_generation"
DFD_SCHEMA = "appsec-review/generated-dfd/1"
THREAT_MODEL_SCHEMA = "appsec-review/generated-threat-model/1"
EVIDENCE_SCHEMA = "appsec-review/generated-model-evidence/1"
RESULT_SCHEMA = "appsec-review/threat-model-generation/1"
INTERACTION_CATALOG_SCHEMA = "appsec-review/interaction-catalog/1"
THREAT_TEMPLATES_SCHEMA = "appsec-review/threat-templates/1"
CROSSWALK_SCHEMA = "appsec-review/threat-crosswalk/1"
AUTHORITY = "routing_context"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[a-z]+:[0-9a-f]{16}")


class ElementKind(StrEnum):
    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"


class Interaction(StrEnum):
    NETWORK_LISTEN = "network_listen"
    NETWORK_RECEIVE = "network_receive"
    NETWORK_CONNECT = "network_connect"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    DATASTORE_QUERY = "datastore_query"
    CODE_LOAD = "code_load"
    PROCESS_SPAWN = "process_spawn"
    ENVIRONMENT_READ = "environment_read"
    ARGUMENT_READ = "argument_read"
    LOCAL_IPC = "local_ipc"
    PRIVILEGE_CHANGE = "privilege_change"


class Basis(StrEnum):
    """How an element is known. The order is the precedence when two facts describe one thing."""
    VERIFIED_SEMANTIC = "verified_semantic"
    DECLARED = "declared"
    OBSERVED_SYNTAX = "observed_syntax"
    DERIVED = "derived"


BASIS_PRECEDENCE = tuple(Basis)


class BoundaryKind(StrEnum):
    NETWORK = "network"
    FILE_CONTENT = "file_content"
    LOCAL_USER = "local_user"
    LAUNCH_ENVIRONMENT = "launch_environment"
    PROCESS = "process"
    DEPLOYMENT_EXPOSURE = "deployment_exposure"
    PRIVILEGE = "privilege"
    LOADED_CODE = "loaded_code"


class Stride(StrEnum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ThreatState(StrEnum):
    CANDIDATE = "candidate"
    ELABORATED = "elaborated"


class MitigationState(StrEnum):
    EVIDENCE_FOUND = "evidence_found"
    NOT_FOUND_IN_EVIDENCE = "not_found_in_evidence"
    NOT_EXAMINED = "not_examined"


class UnknownKind(StrEnum):
    RUNTIME_ROLE_UNKNOWN = "runtime_role_unknown"
    PEER_UNIDENTIFIED = "peer_unidentified"
    FLOW_ENDPOINT_UNRESOLVED = "flow_endpoint_unresolved"
    PROTOCOL_UNKNOWN = "protocol_unknown"
    DATASTORE_UNIDENTIFIED = "datastore_unidentified"
    BOUNDARY_NOT_ESTABLISHED = "boundary_not_established"
    DEPLOYMENT_NOT_DESCRIBED = "deployment_not_described"
    AUTHENTICATION_NOT_LOCATED = "authentication_not_located"
    ASSET_SENSITIVITY_UNKNOWN = "asset_sensitivity_unknown"
    UNCITED_MODEL_INFERENCE = "uncited_model_inference"
    EVIDENCE_REQUEST_UNSERVED = "evidence_request_unserved"
    NO_ELEMENT_ESTABLISHED = "no_element_established"
    CITATION_UNRESOLVED = "citation_unresolved"


class InputState(StrEnum):
    READ = "read"
    ABSENT = "absent"
    DISABLED = "disabled"
    NOT_REGISTERED = "not_registered"
    PARTIAL = "partial"
    EMPTY = "empty"


class FactKind(StrEnum):
    """What a lane reports. Attribute keys per kind are fixed (see ``Fact``)."""
    PROCESS = "process"
    LIBRARY = "library"
    LINK = "link"
    INTERACTION = "interaction"


class NameBasis(StrEnum):
    ARTIFACT_NAME = "artifact_name"
    DECLARED_NAME = "declared_name"
    DERIVED = "derived"
    MODEL_LABEL = "model_label"


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in sorted(value.items())})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        # Producer payloads carry confidences; they are read, never used in an identity.
        return value
    raise ValueError(f"unsupported contract value: {type(value).__name__}")


def _plain(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _plain(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def canonical(document: Any) -> bytes:
    """The one serialization of every published document: sorted keys, no insignificant space."""
    return (json.dumps(_plain(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            + "\n").encode("utf-8")


def canonical_sha256(document: Any) -> str:
    return hashlib.sha256(canonical(document)).hexdigest()


def element_id(prefix: str, native_identity: Any) -> str:
    """``<prefix>:<16 hex>`` over the canonical native identity, never over content hashes or order.

    Prefixes: ``proc``, ``store``, ``ext``, ``flow``, ``tb``, ``ep``, ``actor``, ``asset``,
    ``threat``, ``unk``, ``ev``.
    """
    if not re.fullmatch(r"[a-z]+", prefix):
        raise ValueError("invalid identity prefix")
    return f"{prefix}:{canonical_sha256({'prefix': prefix, 'identity': native_identity})[:16]}"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _text(value: Any, label: str) -> None:
    _require(isinstance(value, str) and bool(value.strip()) and "\x00" not in value, f"{label} must be nonempty text")


def _each_id(values: tuple[Any, ...], label: str) -> None:
    _require(all(isinstance(item, str) and _ID.fullmatch(item) for item in values), f"{label} must be identities")


def _ids(values: Any, label: str) -> None:
    _require(isinstance(values, tuple) and all(isinstance(item, str) and _ID.fullmatch(item) for item in values),
             f"{label} must be a tuple of identities")
    _require(len(values) == len(set(values)), f"{label} repeats an identity")


@dataclass(frozen=True, slots=True)
class Publication:
    """The accepted shard or artifact a record was read from."""
    job: str
    output_kind: str
    index: str | None
    shard_id: str | None
    sha256: str

    def __post_init__(self) -> None:
        _text(self.job, "publication job")
        _text(self.output_kind, "publication output kind")
        _require(bool(_SHA256.fullmatch(self.sha256)), "publication digest must be a SHA-256")


@dataclass(frozen=True, slots=True)
class SourceSpan:
    path: str
    file_sha256: str
    start_line: int
    end_line: int
    start_byte: int | None = None
    end_byte: int | None = None

    def __post_init__(self) -> None:
        _text(self.path, "span path")
        _require(not self.path.startswith("/") and ".." not in self.path.split("/"), "span path must be target-relative")
        _require(bool(_SHA256.fullmatch(self.file_sha256)), "span file digest must be a SHA-256")
        _require(1 <= self.start_line <= self.end_line, "span lines must be ordered and 1-based")

    @property
    def locator(self) -> str:
        """The review's locator form: ``path:start-end#bstart-end@file_sha256``."""
        byte_part = f"#b{self.start_byte}-{self.end_byte}" if self.start_byte is not None and self.end_byte is not None else ""
        return f"{self.path}:{self.start_line}-{self.end_line}{byte_part}@{self.file_sha256}"


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One record an ``EvidenceView`` returns: an index entity with its producer payload."""
    entity_id: str
    entity_kind: str
    name: str
    payload: Mapping[str, Any]
    publication: Publication
    span: SourceSpan | None = None
    content_sha256: str | None = None

    def __post_init__(self) -> None:
        _text(self.entity_id, "entity identity")
        _text(self.entity_kind, "entity kind")
        object.__setattr__(self, "payload", _freeze(self.payload))


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A citation. ``ref`` is derived, so equal citations are equal everywhere."""
    ref: str
    kind: str  # index_entity | run_artifact
    entity_id: str
    entity_kind: str
    publication: Publication
    locator: str | None
    content_sha256: str | None
    basis: Basis
    rule: str

    def __post_init__(self) -> None:
        _require(self.kind in {"index_entity", "run_artifact"}, "unknown evidence kind")
        _require(isinstance(self.basis, Basis), "unknown evidence basis")
        _text(self.rule, "evidence rule")
        _require(self.ref == element_id("ev", [self.entity_id, self.publication.sha256, self.locator]),
                 "evidence reference identity does not match its content")


def cite(record: EvidenceRecord, basis: Basis, rule: str) -> EvidenceRef:
    locator = record.span.locator if record.span is not None else None
    return EvidenceRef(element_id("ev", [record.entity_id, record.publication.sha256, locator]), "index_entity",
                       record.entity_id, record.entity_kind, record.publication, locator, record.content_sha256,
                       basis, rule)


def _evidence(values: Any, label: str) -> None:
    _require(isinstance(values, tuple) and values and all(isinstance(item, EvidenceRef) for item in values),
             f"{label} requires at least one evidence reference")


@dataclass(frozen=True, slots=True)
class Fact:
    """One lane observation.

    ``native_identity`` is the stable identity of the thing (JSON-compatible). ``attributes`` keys:

    - process, library: ``build_unit_id`` (``None`` when only a compiled-graph project identifies the
      artifact), ``artifact_path``, ``test_only`` (present and ``True`` only when the producer says
      so), ``component_ids`` (tuple),
      ``source_paths`` (tuple, target-relative, may be empty), ``source_roots`` (tuple of directory
      prefixes ending in ``/`` or ``""`` for the target root), ``built`` (bool).
    - link: ``input`` and ``output`` (native identities of a library and of the process or library
      it links into); the link's own ``native_identity`` is ``{"input": ..., "output": ...}``.
    - interaction: ``interaction`` (an ``Interaction`` value), ``path``, ``source_class``,
      ``sink_class``, ``callee``, ``enclosing_symbol``, ``build_unit_id``, ``component_id`` (each
      ``None`` when the evidence does not say).
    """
    kind: FactKind
    native_identity: Any
    name: str
    basis: Basis
    evidence: tuple[EvidenceRef, ...]
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require(isinstance(self.kind, FactKind) and isinstance(self.basis, Basis), "unknown fact kind or basis")
        _text(self.name, "fact name")
        _evidence(self.evidence, "fact")
        object.__setattr__(self, "native_identity", _freeze(self.native_identity))
        object.__setattr__(self, "attributes", _freeze(self.attributes))
        if self.kind is FactKind.INTERACTION:
            Interaction(self.attributes.get("interaction"))


@dataclass(frozen=True, slots=True)
class Unknown:
    id: str
    kind: UnknownKind
    subject_ids: tuple[str, ...]
    statement: str
    would_resolve: tuple[str, ...]

    def __post_init__(self) -> None:
        _require(isinstance(self.kind, UnknownKind), "unknown kind is not in the closed vocabulary")
        _text(self.statement, "unknown statement")
        _require(isinstance(self.subject_ids, tuple) and isinstance(self.would_resolve, tuple), "invalid unknown lists")
        _require(self.id == element_id("unk", [self.kind.value, list(self.subject_ids), self.statement]),
                 "unknown identity does not match its content")


def unknown(kind: UnknownKind, statement: str, *, subject_ids: tuple[str, ...] = (),
            would_resolve: tuple[str, ...] = ()) -> Unknown:
    subjects, resolve = tuple(sorted(set(subject_ids))), tuple(sorted(set(would_resolve)))
    return Unknown(element_id("unk", [kind.value, list(subjects), statement]), kind, subjects, statement, resolve)


@dataclass(frozen=True, slots=True)
class Element:
    id: str
    kind: ElementKind
    name: str
    name_basis: NameBasis
    basis: Basis
    evidence: tuple[EvidenceRef, ...]
    attributes: Mapping[str, Any] = field(default_factory=dict)
    component_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require(isinstance(self.kind, ElementKind) and isinstance(self.basis, Basis)
                 and isinstance(self.name_basis, NameBasis), "unknown element vocabulary value")
        _require(bool(_ID.fullmatch(self.id)), "invalid element identity")
        _text(self.name, "element name")
        _evidence(self.evidence, "element")
        object.__setattr__(self, "attributes", _freeze(self.attributes))


@dataclass(frozen=True, slots=True)
class Flow:
    id: str
    source: str
    target: str
    interaction: Interaction
    basis: Basis
    evidence: tuple[EvidenceRef, ...]
    crosses: tuple[str, ...] = ()
    data: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require(isinstance(self.interaction, Interaction) and isinstance(self.basis, Basis), "unknown flow vocabulary value")
        _each_id((self.id, self.source, self.target), "flow identities")
        _ids(self.crosses, "flow crossings")
        _evidence(self.evidence, "flow")
        object.__setattr__(self, "attributes", _freeze(self.attributes))


@dataclass(frozen=True, slots=True)
class Boundary:
    id: str
    kind: BoundaryKind
    inside: tuple[str, ...]
    basis: Basis
    evidence: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        _require(isinstance(self.kind, BoundaryKind) and isinstance(self.basis, Basis), "unknown boundary vocabulary value")
        _each_id((self.id,), "boundary identity")
        _ids(self.inside, "boundary members")
        _evidence(self.evidence, "boundary")


@dataclass(frozen=True, slots=True)
class EntryPoint:
    id: str
    process: str
    interaction: Interaction
    source_class: str | None
    enclosing_symbol: str | None
    basis: Basis
    evidence: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        _require(isinstance(self.interaction, Interaction) and isinstance(self.basis, Basis), "unknown entry-point vocabulary value")
        _each_id((self.id, self.process), "entry-point identities")
        _evidence(self.evidence, "entry point")


@dataclass(frozen=True, slots=True)
class Actor:
    id: str
    external_entity: str
    attacker_position_candidates: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        _each_id((self.id, self.external_entity), "actor identities")
        _evidence(self.evidence, "actor")


@dataclass(frozen=True, slots=True)
class Asset:
    id: str
    name: str
    held_by: tuple[str, ...]
    basis: Basis
    evidence: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        _each_id((self.id,), "asset identity")
        _ids(self.held_by, "asset holders")
        _text(self.name, "asset name")
        _evidence(self.evidence, "asset")


@dataclass(frozen=True, slots=True)
class Mitigation:
    state: MitigationState
    evidence: tuple[EvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _require(isinstance(self.state, MitigationState), "unknown mitigation state")
        _require((self.state is MitigationState.EVIDENCE_FOUND) == bool(self.evidence),
                 "mitigation evidence is required exactly when evidence was found")


@dataclass(frozen=True, slots=True)
class Threat:
    id: str
    state: ThreatState
    stride: Stride
    template_id: str | None
    title: str
    question: str
    element_ids: tuple[str, ...]
    flow_ids: tuple[str, ...]
    boundary_ids: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    obligations: tuple[str, ...]
    mitigation: Mitigation
    related_controls: tuple[Mapping[str, Any], ...] = ()
    crosswalk: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require(isinstance(self.state, ThreatState) and isinstance(self.stride, Stride)
                 and isinstance(self.mitigation, Mitigation), "unknown threat vocabulary value")
        _require(self.state is not ThreatState.CANDIDATE or bool(self.template_id), "a candidate threat names its template")
        _each_id((self.id,), "threat identity")
        for values, label in ((self.element_ids, "threat elements"), (self.flow_ids, "threat flows"),
                              (self.boundary_ids, "threat boundaries")):
            _ids(values, label)
        _text(self.title, "threat title")
        _text(self.question, "threat question")
        _evidence(self.evidence, "threat")
        object.__setattr__(self, "related_controls", _freeze(self.related_controls))
        object.__setattr__(self, "crosswalk", _freeze(self.crosswalk))


@dataclass(frozen=True, slots=True)
class InputLedgerRow:
    producer: str
    output_kind: str
    state: InputState
    handoff_sha256: str | None = None
    coverage_disposition: str | None = None
    upstream_gap_count: int = 0
    records_read: int = 0

    def __post_init__(self) -> None:
        _require(isinstance(self.state, InputState), "unknown input state")
        _text(self.producer, "ledger producer")
        _text(self.output_kind, "ledger output kind")


@dataclass(frozen=True, slots=True)
class Origin:
    """The provenance block every published document starts with. It cannot say "supplied"."""
    run_id: str
    attempt_id: str
    target_snapshot: str
    reference_data: Mapping[str, str]
    model: Mapping[str, str] | None = None
    kind: str = "generated"
    target_supplied: bool = False
    producer: str = JOB_ID
    authority: str = AUTHORITY

    def __post_init__(self) -> None:
        _require(self.kind == "generated" and self.target_supplied is False and self.producer == JOB_ID
                 and self.authority == AUTHORITY, "a generated model is never target-supplied or authoritative")
        object.__setattr__(self, "reference_data", _freeze(self.reference_data))
        if self.model is not None:
            object.__setattr__(self, "model", _freeze(self.model))


@dataclass(frozen=True, slots=True)
class Limits:
    max_processes: int = 200
    max_entry_points: int = 4000
    max_flows: int = 8000
    max_threats: int = 4000
    max_query_rows: int = 2000
    max_evidence_refs_per_element: int = 8
    max_render_nodes: int = 120

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            _require(type(value) is int and 1 <= value <= 100_000, f"{item.name} must be an integer from 1 to 100000")


@dataclass(frozen=True, slots=True)
class LaneResult:
    """What a lane returns. ``gaps`` are ``producer-gap/1`` records (``interchange.producer_gap``)."""
    facts: tuple[Fact, ...] = ()
    gaps: tuple[Mapping[str, Any], ...] = ()
    ledger: tuple[InputLedgerRow, ...] = ()
    unknowns: tuple[Unknown, ...] = ()


def merge_evidence(*groups: tuple[EvidenceRef, ...], limit: int) -> tuple[EvidenceRef, ...]:
    """Deduplicate citations, strongest basis first, then by reference id, bounded by ``limit``."""
    unique = {item.ref: item for group in groups for item in group}
    ordered = sorted(unique.values(), key=lambda item: (BASIS_PRECEDENCE.index(item.basis), item.ref))
    return tuple(ordered[:limit])


def strongest(*bases: Basis) -> Basis:
    return min(bases, key=BASIS_PRECEDENCE.index)


def sorted_records(records: Any) -> list[Any]:
    """Published arrays are sorted by ``id`` (or ``ref`` for evidence), never by arrival order."""
    return sorted(records, key=lambda item: getattr(item, "id", None) or getattr(item, "ref"))
