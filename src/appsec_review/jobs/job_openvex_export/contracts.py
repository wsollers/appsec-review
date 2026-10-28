"""Frozen boundaries for the model-free OpenVEX exporter.

Wire paths are run-relative POSIX names, never host filesystem paths. JSON projections are
defensively frozen; use ``json_body`` before passing them to the existing canonical serializer.
Constructing verified records does not replace the input verifier's accepted-artifact checks.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any
import unicodedata
from urllib.parse import unquote, urlsplit

from appsec_review.jobs.engineering_contracts import (
    OPENVEX_EXPORT_HANDOFF_SCHEMA,
    OPENVEX_EXPORT_MANIFEST_SCHEMA,
    OPENVEX_EXPORT_RESULT_SCHEMA,
)
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json

JOB_ID = "job_openvex_export"
CONSUMES = ("job_final_publication_gate", "job_inference_security_review")
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
UPSTREAM_COMMIT = "61b5f885d0f481f48683c93345e49ef1a6e9fdff"
UPSTREAM_SCHEMA_ID = "https://github.com/openvex/spec/openvex_json_schema_0.2.0.json"
UPSTREAM_SCHEMA_SHA256 = "9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238"
UPSTREAM_LICENSE_SHA256 = "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"
UPSTREAM_LOCK_SHA256 = "04eb3fc522af8389422666dfa20732a666b8a4cac57cdecb06051a2df2e6322d"
SCHEMA_BASE = "https://appsec-review.local/schemas/openvex-export/"
EXPORTER_COMPONENT = "openvex_export"
VALIDATION_PROFILE = "appsec-review/openvex-export-validation/1"
METRICS_SCHEMA = "appsec-review/openvex-metrics/1"
MAX_JSON_DEPTH = 32
MAX_PACKAGES = 10000
MAX_BINDINGS = 30000
MAX_ARTIFACT_BYTES = 67108864
MAX_TOTAL_INPUT_BYTES = 536870912
MAX_DOCUMENT_BYTES = 33554432
MAX_MANIFEST_BYTES = 134217728
MAX_ACTION_BYTES = 8192
MAX_IDENTIFIER_BYTES = 2048
MAX_TIMEOUT_SECONDS = 120
MAX_RESULT_BYTES = 1048576
DOCUMENT_NAME = "openvex.json"
MANIFEST_NAME = "openvex-manifest.json"
RESULT_NAME = "openvex-result.json"
VERIFIED_INPUTS_NAME = "verified-inputs.json"
VERIFIED_INPUTS_SCHEMA = "appsec-review/openvex-verified-inputs/1"
TIMESTAMP_SOURCE = "gate_handoff.completed_at"
DISCLOSURE = "internal"
STATUS_NOTES = (
    "Applies only to the reviewed source snapshot and observed configuration, not an inferred "
    "released artifact or version range. Review confirmation is not proof of exploit execution. "
    "Review limitations and resolving evidence are retained in the companion manifest."
)
NO_STATEMENTS_GAP = "openvex_no_publishable_confirmed_findings"
EVENT_NAMES = (
    "OPENVEX_EXPORT_STARTED", "OPENVEX_INPUTS_VERIFIED", "OPENVEX_EXPORT_ACCOUNTED",
    "OPENVEX_EXPORT_COMPLETED", "OPENVEX_EXPORT_FAILED",
)
DURATION_BUCKETS = (0.01, 0.05, 0.1, 0.5, 1, 5, 15, 30, 60, 120)
SIZE_BUCKETS = (1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 33554432)

JsonObject = Mapping[str, Any]
_SHA256 = re.compile(r"[0-9a-f]{64}")
_RUN_PATH = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
_RFC3339 = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
)
_CREDENTIAL = re.compile(
    r"(?:[a-z][a-z0-9+.-]*://[^\s/]*@|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*\S+|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[A-Z0-9]{16}))", re.IGNORECASE,
)
_TEMPLATE = re.compile(r"\{\{|\}\}|\$\{|<%|%>|\{%|%\}|\{[A-Za-z_][A-Za-z0-9_.-]*\}|%[A-Z_][A-Z0-9_]*%")
_MARKUP = re.compile(r"<[/!A-Za-z][^>]*>|```|`")


class AuthorKind(StrEnum):
    INDIVIDUAL = "individual"
    ORGANIZATION = "organization"


class ExportOutcome(StrEnum):
    EXPORTED = "exported"
    EXPORTED_WITH_GAPS = "exported_with_gaps"
    NO_STATEMENTS = "no_statements"


class ExportReportState(StrEnum):
    DISABLED = "disabled"
    NOT_RUN = "not_run"
    AVAILABLE = "available"
    NO_STATEMENTS = "no_statements"
    STALE = "stale"


class VexStatus(StrEnum):
    AFFECTED = "affected"


class GateBucket(StrEnum):
    PUBLISHABLE = "publishable"
    VERIFICATION_BACKLOG = "verification_backlog"
    WITHHELD = "withheld"


class FindingState(StrEnum):
    CONFIRMED = "confirmed"
    SUPPORTED = "supported"


class Disposition(StrEnum):
    INCLUDED = "included"
    EXCLUDED = "excluded"


class DispositionReason(StrEnum):
    INCLUDED = "included"
    GATE_VERIFICATION_BACKLOG = "gate_verification_backlog"
    GATE_WITHHELD = "gate_withheld"


class RepositoryIdentityBasis(StrEnum):
    OPERATOR_DECLARED = "operator_declared"
    ACCEPTED_ACQUISITION = "accepted_acquisition"


class ExportPhase(StrEnum):
    LOAD = "load"
    ASSEMBLE = "assemble"
    VALIDATE = "validate"
    ACCEPT = "accept"


class ExportFailureReason(StrEnum):
    CONFIGURATION_INVALID = "configuration_invalid"
    INPUT_MISSING = "input_missing"
    INPUT_STALE = "input_stale"
    INPUT_TAMPERED = "input_tampered"
    IDENTITY_CONFLICT = "identity_conflict"
    SCHEMA_INVALID = "schema_invalid"
    SEMANTIC_INVALID = "semantic_invalid"
    BOUND_EXCEEDED = "bound_exceeded"
    TIMED_OUT = "timed_out"
    IO_ERROR = "io_error"
    INTERNAL_ERROR = "internal_error"


class ExportError(IntegrityError):
    """Fail-closed domain error; only ``reason``/``phase`` are safe metric labels.

    The diagnostic message is protected log data, never a metric label. Wrapping existing
    exceptions must preserve their cause and re-raise; this class does not catch anything.
    """

    def __init__(self, message: str, *, reason: ExportFailureReason, phase: ExportPhase) -> None:
        self.reason = ExportFailureReason(reason)
        self.phase = ExportPhase(phase)
        super().__init__(message)


def require_sha256(value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("expected a full lowercase SHA-256")
    return value


def require_run_path(value: str) -> str:
    if (not isinstance(value, str) or len(value) > 512 or not _RUN_PATH.fullmatch(value)
            or any(part in {".", ".."} for part in value.split("/"))):
        raise ValueError("expected a bounded run-relative POSIX artifact path")
    return value


def validate_text(value: str, *, max_bytes: int, field: str, empty: bool = False,
                  multiline: bool = False) -> str:
    """Reject unsafe input without normalizing, redacting or truncating accepted text."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if value == "" and empty:
        return value
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
           and not (multiline and char in "\n\t") for char in value):
        raise ValueError(f"{field} contains unsafe controls")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field} exceeds its UTF-8 byte limit")
    if _CREDENTIAL.search(value) or _TEMPLATE.search(value) or _MARKUP.search(value):
        raise ValueError(f"{field} contains credentials, template markers or executable markup")
    return value


def validate_repository_iri(value: str, *, max_bytes: int = MAX_IDENTIFIER_BYTES) -> str:
    """Restricted ASCII absolute HTTPS/URN system identity, not a local/branch URL."""
    validate_text(value, max_bytes=max_bytes, field="repository_iri")
    if (not value.isascii() or any(ord(char) <= 32 or char in '<>"\\^`{|}' for char in value)
            or re.search(r"%(?![0-9A-Fa-f]{2})", value)):
        raise ValueError("repository_iri must be a restricted ASCII absolute URI")
    decoded = unquote(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
        raise ValueError("repository_iri contains encoded controls")
    parts = urlsplit(value)
    if parts.query or parts.fragment or "?" in value or "#" in value:
        raise ValueError("repository_iri must not contain a query or fragment")
    if parts.scheme == "https":
        if (not value.startswith("https://") or not parts.hostname or parts.username is not None
                or parts.password is not None or not parts.netloc):
            raise ValueError("repository_iri must identify an HTTPS repository without credentials")
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError("repository_iri has an invalid port")
        if not re.fullmatch(r"[A-Za-z0-9.:\[\]-]+(?::[0-9]+)?", parts.netloc):
            raise ValueError("repository_iri has an invalid authority")
        if re.search(r"/(?:tree|blob|commit|commits)(?:/|$)", decoded, re.IGNORECASE):
            raise ValueError("repository_iri must not identify a branch or commit")
    elif parts.scheme == "urn":
        if not re.fullmatch(r"urn:[A-Za-z0-9][A-Za-z0-9-]{0,30}[A-Za-z0-9]:[A-Za-z0-9._~!$&'()*+,;=:@%/-]+",
                            value):
            raise ValueError("repository_iri must have a valid URN namespace and identifier")
    else:
        raise ValueError("repository_iri must use https: or urn:")
    return value


def freeze_json(value: Any, *, _depth: int = 0) -> Any:
    """Copy JSON into mapping proxies/tuples, rejecting cycles/depth and non-JSON values."""
    if _depth > MAX_JSON_DEPTH or (_depth == MAX_JSON_DEPTH and isinstance(value, (Mapping, list, tuple))):
        raise ValueError("OpenVEX JSON exceeds the depth limit")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        return MappingProxyType({key: freeze_json(item, _depth=_depth + 1) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item, _depth=_depth + 1) for item in value)
    if value is None or type(value) in {str, int, bool}:
        if isinstance(value, str):
            value.encode("utf-8")
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("OpenVEX JSON must contain only finite JSON values")


def json_body(value: Any) -> Any:
    """Return a detached mutable JSON projection; mutations never change verified authority."""
    if isinstance(value, Mapping):
        return {key: json_body(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [json_body(item) for item in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(json_body(freeze_json(value)))


def parse_json_bytes(payload: bytes, *, max_bytes: int) -> dict[str, Any]:
    """Bound new local JSON before recursive parsing; reject duplicate keys and nonfinite numbers."""
    if type(payload) is not bytes or type(max_bytes) is not int or max_bytes <= 0 or len(payload) > max_bytes:
        raise ValueError("JSON payload exceeds its byte bound or has an invalid bound")
    text = payload.decode("utf-8")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("OpenVEX JSON exceeds the depth limit")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    def nonfinite(_value: str) -> None:
        raise ValueError("nonfinite JSON value")

    value = json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)
    if not isinstance(value, dict):
        raise ValueError("OpenVEX JSON artifact must be an object")
    freeze_json(value)
    return value


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def domain_sha256(domain: str, value: Any) -> str:
    return json_sha256([domain, value])


def normalize_timestamp(value: str) -> str:
    """Require RFC3339 with explicit offset and at most microsecond precision, never a clock."""
    if not isinstance(value, str) or not _RFC3339.fullmatch(value) or value.endswith("-00:00"):
        raise ValueError("gate acceptance requires an aware RFC3339 timestamp with known offset")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


def source_product_id(repository_iri: str, target_snapshot: str, resolved_config_sha256: str) -> str:
    validate_repository_iri(repository_iri)
    return (f"urn:appsec-review:source-snapshot:{json_sha256(repository_iri)}:"
            f"{require_sha256(target_snapshot)}:{require_sha256(resolved_config_sha256)}")


def vulnerability_id(repository_iri: str, target_snapshot: str, claim_id: str) -> str:
    validate_repository_iri(repository_iri)
    require_sha256(target_snapshot)
    if not isinstance(claim_id, str) or not re.fullmatch(r"claim-[0-9a-f]{64}", claim_id):
        raise ValueError("expected an accepted claim identity")
    digest = json_sha256(["openvex-vulnerability/1", repository_iri, target_snapshot, claim_id])
    return f"urn:appsec-review:vulnerability:{digest}"


def statement_id(author: str, statement_without_id: JsonObject) -> str:
    if "@id" in statement_without_id:
        raise ValueError("statement identity must not hash its own @id")
    validate_text(author, max_bytes=MAX_IDENTIFIER_BYTES, field="author")
    return "urn:appsec-review:statement:" + json_sha256(["openvex-statement/1", author, statement_without_id])


def document_id(document_without_id: JsonObject) -> str:
    if "@id" in document_without_id:
        raise ValueError("document identity must not hash its own @id")
    return "urn:appsec-review:openvex:" + domain_sha256("openvex-document/1", document_without_id)


def exporter_tooling(exporter_release: str) -> str:
    validate_text(exporter_release, max_bytes=200, field="exporter_release")
    return f"appsec-review/openvex-export {exporter_release}"


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        require_run_path(self.path)
        require_sha256(self.sha256)

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256}

    @classmethod
    def from_mapping(cls, value: JsonObject) -> ArtifactRef:
        if not isinstance(value, Mapping) or set(value) != {"path", "sha256"}:
            raise ValueError("artifact reference must contain exactly path and sha256")
        return cls(value["path"], value["sha256"])


@dataclass(frozen=True, slots=True)
class SizedArtifactRef(ArtifactRef):
    """A measured input inventory entry or a new output reference."""

    size_bytes: int

    def __post_init__(self) -> None:
        super(SizedArtifactRef, self).__post_init__()
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= MAX_TOTAL_INPUT_BYTES:
            raise ValueError("artifact size must be a bounded nonnegative integer")

    @property
    def reference(self) -> ArtifactRef:
        return ArtifactRef(self.path, self.sha256)

    def to_json(self) -> dict[str, Any]:
        return {**super(SizedArtifactRef, self).to_json(), "size_bytes": self.size_bytes}

    @classmethod
    def from_mapping(cls, value: JsonObject) -> SizedArtifactRef:
        if not isinstance(value, Mapping) or set(value) != {"path", "sha256", "size_bytes"}:
            raise ValueError("sized reference must contain exactly path, sha256 and size_bytes")
        return cls(value["path"], value["sha256"], value["size_bytes"])


@dataclass(frozen=True, slots=True)
class ExportProvenance:
    gate_handoff: ArtifactRef
    gate: ArtifactRef
    review_handoff: ArtifactRef
    review: ArtifactRef
    accepted_scope: ArtifactRef
    accepted_manifest: ArtifactRef
    configuration_manifest: ArtifactRef
    resolved_configuration: ArtifactRef
    review_settings_sha256: str
    lead_package_manifest_sha256: str
    hunt_package_manifest_sha256: str
    ledger_head_sha256: str
    projection_sha256: str
    ship_block_policy_sha256: str

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            if name.endswith("_sha256"):
                require_sha256(value)
            elif type(value) is not ArtifactRef:
                raise ValueError(f"{name} must be a path/sha256 artifact reference")

    @property
    def resolved_config_sha256(self) -> str:
        return self.resolved_configuration.sha256

    @property
    def references(self) -> tuple[ArtifactRef, ...]:
        return tuple(getattr(self, name) for name in self.__dataclass_fields__ if not name.endswith("_sha256"))

    def to_json(self) -> dict[str, Any]:
        return {**{name: value.to_json() if isinstance(value, ArtifactRef) else value
                   for name in self.__dataclass_fields__ for value in (getattr(self, name),)},
                "resolved_config_sha256": self.resolved_config_sha256}

    @classmethod
    def from_mapping(cls, value: JsonObject) -> ExportProvenance:
        if not isinstance(value, Mapping) or set(value) != {*cls.__dataclass_fields__, "resolved_config_sha256"}:
            raise ValueError("export provenance must define exactly its documented keys")
        result = cls(**{name: value[name] if name.endswith("_sha256") else ArtifactRef.from_mapping(value[name])
                        for name in cls.__dataclass_fields__})
        if result.resolved_config_sha256 != value["resolved_config_sha256"]:
            raise ValueError("full resolved configuration hash disagrees with its reference")
        return result


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    repository_iri: str
    repository_identity_basis: RepositoryIdentityBasis
    target_snapshot: str
    acquisition: ArtifactRef | None
    qualifications: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_repository_iri(self.repository_iri)
        require_sha256(self.target_snapshot)
        object.__setattr__(self, "repository_identity_basis", RepositoryIdentityBasis(self.repository_identity_basis))
        if (self.repository_identity_basis == RepositoryIdentityBasis.ACCEPTED_ACQUISITION) != (
                self.acquisition is not None):
            raise ValueError("accepted acquisition basis requires its exact artifact reference")
        if self.acquisition is not None and type(self.acquisition) is not ArtifactRef:
            raise ValueError("acquisition must be a path/sha256 reference")
        if isinstance(self.qualifications, str) or len(self.qualifications) > 64:
            raise ValueError("source qualifications must be a bounded sequence")
        for value in self.qualifications:
            validate_text(value, max_bytes=2000, field="source qualification", multiline=True)
        object.__setattr__(self, "qualifications", tuple(self.qualifications))

    def to_json(self) -> dict[str, Any]:
        return {"repository_iri": self.repository_iri,
                "repository_identity_basis": self.repository_identity_basis.value,
                "target_snapshot": self.target_snapshot,
                "acquisition": None if self.acquisition is None else self.acquisition.to_json(),
                "qualifications": list(self.qualifications)}

    @classmethod
    def from_mapping(cls, value: JsonObject) -> SourceIdentity:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("source identity must define exactly its documented keys")
        return cls(value["repository_iri"], RepositoryIdentityBasis(value["repository_identity_basis"]),
                   value["target_snapshot"], None if value["acquisition"] is None
                   else ArtifactRef.from_mapping(value["acquisition"]), value["qualifications"])


@dataclass(frozen=True, slots=True)
class VerifiedFinding:
    """Exact gate finding projection, plus resolving score/evidence artifact references."""

    projection: JsonObject
    score_refs: tuple[ArtifactRef, ...]
    evidence_refs: tuple[ArtifactRef, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.projection, Mapping):
            raise ValueError("verified finding requires a gate finding object")
        for key, prefix in (("finding_package_id", "finding"), ("claim_id", "claim")):
            if not re.fullmatch(rf"{prefix}-[0-9a-f]{{64}}", self.projection.get(key, "")):
                raise ValueError(f"invalid {key}")
        ArtifactRef(self.projection["path"], self.projection["sha256"])
        state = FindingState(self.projection["state"])
        bucket = GateBucket(self.projection["bucket"])
        if ((bucket == GateBucket.PUBLISHABLE and state != FindingState.CONFIRMED)
                or (bucket == GateBucket.VERIFICATION_BACKLOG and state != FindingState.SUPPORTED)):
            raise ValueError("gate package state contradicts its bucket")
        object.__setattr__(self, "projection", freeze_json(self.projection))
        for name in ("score_refs", "evidence_refs"):
            values = tuple(getattr(self, name))
            if len(values) > MAX_BINDINGS or any(type(value) is not ArtifactRef for value in values):
                raise ValueError("finding references must be bounded artifact references")
            object.__setattr__(self, name, tuple(sorted(set(values), key=lambda ref: (ref.path, ref.sha256))))

    @property
    def finding_package_id(self) -> str:
        return self.projection["finding_package_id"]

    @property
    def claim_id(self) -> str:
        return self.projection["claim_id"]

    @property
    def bucket(self) -> GateBucket:
        return GateBucket(self.projection["bucket"])

    @property
    def reference(self) -> ArtifactRef:
        return ArtifactRef(self.projection["path"], self.projection["sha256"])

    def to_json(self) -> dict[str, Any]:
        return {"projection": json_body(self.projection), "score_refs": [ref.to_json() for ref in self.score_refs],
                "evidence_refs": [ref.to_json() for ref in self.evidence_refs]}

    @classmethod
    def from_mapping(cls, value: JsonObject) -> VerifiedFinding:
        if not isinstance(value, Mapping) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("verified finding must define exactly its documented keys")
        return cls(value["projection"], tuple(ArtifactRef.from_mapping(ref) for ref in value["score_refs"]),
                   tuple(ArtifactRef.from_mapping(ref) for ref in value["evidence_refs"]))


@dataclass(frozen=True, slots=True)
class VerifiedInputs:
    run_id: str
    provenance: ExportProvenance
    source: SourceIdentity
    gate_completed_at: str
    settings_sha256: str
    gate: JsonObject
    findings: tuple[VerifiedFinding, ...]
    input_inventory: tuple[SizedArtifactRef, ...]

    def __post_init__(self) -> None:
        if type(self.provenance) is not ExportProvenance or type(self.source) is not SourceIdentity:
            raise ValueError("verified inputs require frozen provenance and source identity records")
        if not isinstance(self.gate, Mapping):
            raise ValueError("verified inputs require the exact gate object")
        validate_text(self.run_id, max_bytes=200, field="run_id")
        require_sha256(self.settings_sha256)
        object.__setattr__(self, "gate_completed_at", normalize_timestamp(self.gate_completed_at))
        if (self.gate.get("schema") != "appsec-review/final-publication-gate/1"
                or self.gate.get("run_id") != self.run_id):
            raise ValueError("verified gate must have the expected schema and run")
        if json_sha256(self.gate) != self.provenance.gate.sha256:
            raise ValueError("verified gate projection does not match its canonical artifact hash")
        if any(type(finding) is not VerifiedFinding for finding in self.findings):
            raise ValueError("verified findings must be frozen finding records")
        findings = tuple(sorted(self.findings, key=lambda finding: finding.finding_package_id))
        if (len(findings) > MAX_PACKAGES
                or len({finding.finding_package_id for finding in findings}) != len(findings)
                or len({finding.claim_id for finding in findings}) != len(findings)):
            raise ValueError("verified findings exceed bounds or repeat package/claim identities")
        gate_packages = sorted(self.gate["packages"], key=lambda item: item["finding_package_id"])
        if canonical_bytes(gate_packages) != canonical_bytes([finding.projection for finding in findings]):
            raise ValueError("verified findings must exactly cover every gate package")
        if any(type(reference) is not SizedArtifactRef for reference in self.input_inventory):
            raise ValueError("verified inventory must contain measured immutable references")
        inventory = tuple(sorted(self.input_inventory, key=lambda ref: (ref.path, ref.sha256)))
        if (not inventory or len(inventory) > MAX_BINDINGS
                or len({item.path for item in inventory}) != len(inventory)
                or any(item.size_bytes > MAX_ARTIFACT_BYTES for item in inventory)
                or sum(item.size_bytes for item in inventory) > MAX_TOTAL_INPUT_BYTES):
            raise ValueError("verified input inventory exceeds bounds or repeats paths")
        bound = {item.reference for item in inventory}
        required = set(self.provenance.references)
        required.update(ArtifactRef.from_mapping(item) for item in self.gate["bindings"])
        if self.source.acquisition is not None:
            required.add(self.source.acquisition)
        for finding in findings:
            required.update((finding.reference, *finding.score_refs, *finding.evidence_refs))
        if not required <= bound:
            raise ValueError("verified inventory omits a required input reference")
        object.__setattr__(self, "gate", freeze_json(self.gate))
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "input_inventory", inventory)

    @property
    def total_input_bytes(self) -> int:
        return sum(item.size_bytes for item in self.input_inventory)

    def to_json(self) -> dict[str, Any]:
        return {"schema": VERIFIED_INPUTS_SCHEMA, "run_id": self.run_id,
                "provenance": self.provenance.to_json(), "source": self.source.to_json(),
                "gate_completed_at": self.gate_completed_at, "settings_sha256": self.settings_sha256,
                "gate": json_body(self.gate), "findings": [finding.to_json() for finding in self.findings],
                "input_inventory": [reference.to_json() for reference in self.input_inventory]}

    @classmethod
    def from_mapping(cls, value: JsonObject) -> VerifiedInputs:
        if (not isinstance(value, Mapping) or set(value) != {*cls.__dataclass_fields__, "schema"}
                or value["schema"] != VERIFIED_INPUTS_SCHEMA):
            raise ValueError("verified inputs must define exactly its documented schema and keys")
        return cls(value["run_id"], ExportProvenance.from_mapping(value["provenance"]),
                   SourceIdentity.from_mapping(value["source"]), value["gate_completed_at"],
                   value["settings_sha256"], value["gate"],
                   tuple(VerifiedFinding.from_mapping(item) for item in value["findings"]),
                   tuple(SizedArtifactRef.from_mapping(item) for item in value["input_inventory"]))


@dataclass(frozen=True, slots=True)
class ExportBundle:
    """Pure assembly output, with no self hash or manifest/result hash cycle.

    ``assemble_export(inputs, settings, exporter_release, *, output_prefix: str)`` must
    receive the run-relative output directory explicitly. It builds document -> manifest ->
    result in that order. This record never finds a directory or touches the filesystem.
    """

    document: JsonObject | None
    manifest: JsonObject
    result: JsonObject
    document_bytes: bytes | None
    manifest_bytes: bytes
    result_bytes: bytes
    document_ref: SizedArtifactRef | None
    manifest_ref: SizedArtifactRef
    result_ref: SizedArtifactRef

    def __post_init__(self) -> None:
        for name in ("document", "manifest", "result"):
            body, payload, reference = getattr(self, name), getattr(self, f"{name}_bytes"), getattr(self, f"{name}_ref")
            if body is None:
                if name != "document" or payload is not None or reference is not None:
                    raise ValueError("only a no-statements document may be absent")
                continue
            if not isinstance(body, Mapping) or type(payload) is not bytes or type(reference) is not SizedArtifactRef:
                raise ValueError("export bodies require canonical bytes and sized references")
            if len(payload) > {"document": MAX_DOCUMENT_BYTES, "manifest": MAX_MANIFEST_BYTES,
                               "result": MAX_RESULT_BYTES}[name]:
                raise ValueError("export output exceeds its hard byte bound")
            if (canonical_bytes(body) != payload or reference.sha256 != hashlib.sha256(payload).hexdigest()
                    or reference.size_bytes != len(payload)):
                raise ValueError("export body, bytes and reference disagree")
            object.__setattr__(self, name, freeze_json(body))
        outcome = ExportOutcome(self.result["outcome"])
        if (self.document is None) != (outcome == ExportOutcome.NO_STATEMENTS):
            raise ValueError("document absence is reserved for genuine no_statements")
        if self.document is None and (self.result["statement_count"] != 0 or self.result["included_findings"] != 0):
            raise ValueError("no_statements must have zero eligible findings")
        if self.document is None and (
                self.manifest["accounting"]["gate_publishable"] != 0
                or self.manifest["accounting"]["included_findings"] != 0
                or self.manifest["accounting"]["statement_count"] != 0
                or self.manifest["statement_mappings"]):
            raise ValueError("no_statements must reflect genuine zero eligible gate findings")


@dataclass(frozen=True, slots=True)
class ExportReportView:
    """Consumer state, not an accepted outcome; stale/missing states expose no output links."""

    state: ExportReportState
    outcome: ExportOutcome | None
    handoff: ArtifactRef | None
    result: SizedArtifactRef | None
    manifest: SizedArtifactRef | None
    document: SizedArtifactRef | None
    statement_count: int | None
    included_findings: int | None
    excluded_findings: int | None
    gaps: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", ExportReportState(self.state))
        if self.outcome is not None:
            object.__setattr__(self, "outcome", ExportOutcome(self.outcome))
        available = self.state in {ExportReportState.AVAILABLE, ExportReportState.NO_STATEMENTS}
        refs = (self.handoff, self.result, self.manifest)
        counts = (self.statement_count, self.included_findings, self.excluded_findings)
        if available:
            if any(ref is None for ref in refs) or self.outcome is None:
                raise ValueError("available export requires accepted references and outcome")
            if any(type(count) is not int or not 0 <= count <= MAX_PACKAGES for count in counts):
                raise ValueError("available export requires bounded counts, not unknown/zero fallbacks")
            if self.state == ExportReportState.NO_STATEMENTS:
                if (self.outcome != ExportOutcome.NO_STATEMENTS or self.document is not None
                        or self.statement_count != 0 or self.included_findings != 0):
                    raise ValueError("empty report view requires genuine no_statements")
            elif self.document is None or self.outcome == ExportOutcome.NO_STATEMENTS or self.statement_count == 0:
                raise ValueError("available report view requires a nonempty document")
        elif any(value is not None for value in (*refs, self.document, self.outcome, *counts)):
            raise ValueError("disabled/missing/stale export must not expose output links or accepted counts")
        if isinstance(self.gaps, str) or len(self.gaps) > 65:
            raise ValueError("report gaps must be a bounded sequence of tokens")
        for gap in self.gaps:
            if not isinstance(gap, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.:/-]{0,127}", gap):
                raise ValueError("invalid report gap token")
        object.__setattr__(self, "gaps", tuple(self.gaps))


def output_reference(output_prefix: str, filename: str, payload: bytes) -> SizedArtifactRef:
    require_run_path(output_prefix)
    if filename not in {DOCUMENT_NAME, MANIFEST_NAME, RESULT_NAME}:
        raise ValueError("unsupported OpenVEX output filename")
    if type(payload) is not bytes:
        raise ValueError("output payload must be canonical bytes")
    if len(payload) > {DOCUMENT_NAME: MAX_DOCUMENT_BYTES, MANIFEST_NAME: MAX_MANIFEST_BYTES,
                       RESULT_NAME: MAX_RESULT_BYTES}[filename]:
        raise ValueError("export output exceeds its hard byte bound")
    return SizedArtifactRef(require_run_path(f"{output_prefix}/{filename}"),
                            hashlib.sha256(payload).hexdigest(), len(payload))


# Exact resources consumed by the offline validator, including transitive accepted-gate definitions.
SCHEMA_SHA256: Mapping[str, str] = MappingProxyType({
    "common.schema.json": "3f0c492583a0180f569b56246437315bbe1653e3b8654ee6afb42ae226ce7891",
    "manifest.schema.json": "64aed63dd5cc0df74d8d0b332c8a9a532d3764fcb7f100594174fa3f0f7dbfd9",
    "result.schema.json": "b5321b7f4e736e55149ca3fce67b073c460e1f3473fc9b45eb40c0db0ace018a",
    "../final-report/common.schema.json": "4e6d69c2da3ab6aaa508a8bd50389a8fd8ad1321f6b1cf075d87f0c13e1c5dad",
    "../final-report/final-publication-gate.schema.json":
        "607a270c370bb497849f3ecd68a3d5072dfdfad2f25cace802a9bef715dd292e",
    "upstream/openvex-v0.2.0.schema.json": UPSTREAM_SCHEMA_SHA256,
})
VALIDATION_PROFILE_SHA256 = domain_sha256("openvex-validation-profile/1", {
    "profile": VALIDATION_PROFILE, "schemas": SCHEMA_SHA256, "max_json_depth": MAX_JSON_DEPTH,
    "upstream_lock_sha256": UPSTREAM_LOCK_SHA256, "upstream_license_sha256": UPSTREAM_LICENSE_SHA256,
    "context": OPENVEX_CONTEXT, "statuses": [VexStatus.AFFECTED.value],
    "status_notes": STATUS_NOTES, "timestamp_source": TIMESTAMP_SOURCE,
    "identity_versions": ["openvex-vulnerability/1", "openvex-statement/1", "openvex-document/1"],
})
