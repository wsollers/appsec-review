"""Pure wire contracts for job handoffs and auditable scanner observations.

Filesystem admission remains in storage and runtime. A valid document is not proof
that its referenced bytes exist or that a reported vulnerability is confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
import hashlib
import json
import re
from typing import AbstractSet, Any, Iterable, Mapping, Sequence


HANDOFF_SCHEMA = "appsec-review/job-handoff/2"
OUTCOMES_SCHEMA = "appsec-review/job-outcomes/1"
OBSERVATION_SCHEMA = "appsec-review/observation/1"
NATIVE_RESULT_SCHEMA = "appsec-review/native-result-reference/1"
GAP_SCHEMA = "appsec-review/producer-gap/1"
INPUTS_SCHEMA = "appsec-review/job-inputs/1"
INTERCHANGE_METRICS_SCHEMA = "appsec-review/interchange-metrics/1"
_HASH = re.compile(r"[0-9a-f]{64}")
_CLASSES = frozenset({
    "source_sast", "secret", "dependency", "configuration", "inventory", "binary", "diagnostic", "other",
})
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})


class AdmissionStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class ExecutionStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class CoverageDisposition(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED_POLICY = "skipped_policy"


class RecordKind(StrEnum):
    FINDING = "finding"
    SCAN_SUMMARY = "scan_summary"
    OBSERVATION = "observation"


class SelectorKind(StrEnum):
    DOCUMENT = "document"
    JSON_POINTER = "json_pointer"
    XML_ORDINAL = "xml_ordinal"
    BYTE_RANGE = "byte_range"


class ProducerStatus(StrEnum):
    """The closed ``terminal_status`` vocabulary of a unit result or a per-scope disposition.

    Anything a job wants to say about an item that is not one of these is a payload fact (a
    ``mode``, ``availability`` or ``probe_disposition`` field), not a terminal status.
    """
    SUCCEEDED = "SUCCEEDED"
    COMPLETE = "COMPLETE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    GAP = "GAP"
    BLOCKED = "BLOCKED"
    BLOCKED_BY_COMPILE = "BLOCKED_BY_COMPILE"
    INVALID_COMPILE_DATABASE = "INVALID_COMPILE_DATABASE"
    UNAVAILABLE = "UNAVAILABLE"
    TIMED_OUT = "TIMED_OUT"
    TIMEOUT = "TIMEOUT"
    OOM_KILLED = "OOM_KILLED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED_NA = "SKIPPED_NA"
    SKIPPED_POLICY = "SKIPPED_POLICY"
    CONFIGURED_DISABLED = "CONFIGURED_DISABLED"
    PARTIAL = "PARTIAL"
    COMPLETED_WITH_GAPS = "COMPLETED_WITH_GAPS"
    DEGRADED = "DEGRADED"


# Upper-case spellings a unit may use for coverage_disposition; the runtime maps them onto
# CoverageDisposition (runtime/handoff.py keeps the same table).
COVERAGE_ALIASES = {
    "COMPLETE": "complete", "PARTIAL": "partial", "UNAVAILABLE": "unavailable",
    "NOT_APPLICABLE": "not_applicable", "SKIPPED_NA": "not_applicable",
    "SKIPPED_POLICY": "skipped_policy", "CONFIGURED_DISABLED": "skipped_policy",
}
UNIT_OUTPUT_SCHEMA = "appsec-review/unit-output/1"
TASK_RECEIPT_SCHEMA = "appsec-review/task-receipt/1"
ATTEMPT_STATUS_SCHEMA = "appsec-review/attempt-status/1"
UNIT_EXECUTION_SCHEMA = "appsec-review/unit-execution/2"
# The keys of a unit result that the runner projects into the handoff's ``outputs`` (the control
# layer every consumer reads). Everything else a unit returns stays in its result.json payload.
UNIT_OUTPUT_KEYS = (
    "schema", "artifact", "graph_export_artifact", "identity", "pointer", "metadata_path", "item_count",
    "gaps", "index_manifest", "index_identity", "terminal_status",
)


class GapCode(StrEnum):
    PRODUCER_FAILED = "producer_failed"
    PRODUCER_BLOCKED = "producer_blocked"
    INPUT_UNAVAILABLE = "input_unavailable"
    OUTPUT_MISSING = "output_missing"
    PARSER_ERROR = "parser_error"
    TRUNCATED = "truncated"
    LOCATION_UNRESOLVED = "location_unresolved"
    EMPTY_RESULT = "empty_result"
    PROVENANCE_UNAVAILABLE = "provenance_unavailable"
    UNKNOWN_PRODUCER_STATUS = "unknown_producer_status"
    PRODUCER_REPORTED_GAP = "producer_reported_gap"


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be nonempty text")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def _path(value: Any) -> str:
    path = _text(value, "artifact path")
    if ("\\" in path or ":" in path or path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise ValueError("artifact path must be canonical and run-relative")
    return path


def _fields(value: Mapping[str, Any], required: AbstractSet[str], optional: AbstractSet[str] = frozenset()) -> None:
    if not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("wire record fields do not match its contract")


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{label} must be a list")
    result = tuple(_text(item, label) for item in value)
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must contain unique values")
    return result


def _wire(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _wire(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        return {key: _wire(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_wire(child) for child in value]
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(_wire(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


class _Record:
    def as_dict(self) -> dict[str, Any]:
        # JSON round-tripping also rejects accidental non-wire values.
        value = json.loads(_canonical(self))
        if not isinstance(value, dict):
            raise ValueError("wire record must serialize as an object")
        return value


@dataclass(frozen=True, slots=True)
class ArtifactReference(_Record):
    path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _path(self.path)
        _hash(self.sha256, "artifact sha256")
        _integer(self.size_bytes, "artifact size")


def artifact_reference_from_mapping(value: Any) -> ArtifactReference:
    value = _mapping(value, "artifact reference")
    _fields(value, {"path", "sha256", "size_bytes"})
    return ArtifactReference(**value)


@dataclass(frozen=True, slots=True)
class ResultSelector(_Record):
    kind: str
    value: Any = None

    def __post_init__(self) -> None:
        kind = SelectorKind(self.kind)
        if kind is SelectorKind.DOCUMENT:
            if self.value is not None:
                raise ValueError("document selector cannot name a subresult")
        elif kind is SelectorKind.JSON_POINTER:
            if (not isinstance(self.value, str) or (self.value and not self.value.startswith("/"))
                    or re.search(r"~(?![01])", self.value)):
                raise ValueError("invalid RFC 6901 result pointer")
        elif kind is SelectorKind.XML_ORDINAL:
            value = _mapping(self.value, "XML selector")
            _fields(value, {"element", "ordinal"})
            _text(value["element"], "XML element")
            _integer(value["ordinal"], "XML ordinal")
        else:
            value = _mapping(self.value, "byte range")
            _fields(value, {"start", "end"})
            if _integer(value["end"], "range end") < _integer(value["start"], "range start"):
                raise ValueError("byte range is reversed")


def result_selector_from_mapping(value: Any) -> ResultSelector:
    value = _mapping(value, "result selector")
    _fields(value, {"kind", "value"})
    return ResultSelector(**value)


@dataclass(frozen=True, slots=True)
class NativeResultReference(_Record):
    artifact: ArtifactReference
    selector: ResultSelector
    parser_identity: str
    execution_reference: ArtifactReference | None = None
    retention_receipt: ArtifactReference | None = None
    complete: bool = True
    schema: str = NATIVE_RESULT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != NATIVE_RESULT_SCHEMA or not isinstance(self.artifact, ArtifactReference):
            raise ValueError("invalid native-result schema or artifact")
        if not isinstance(self.selector, ResultSelector):
            raise ValueError("invalid native-result selector")
        _text(self.parser_identity, "parser identity")
        _boolean(self.complete, "native completeness")
        for reference in (self.execution_reference, self.retention_receipt):
            if reference is not None and not isinstance(reference, ArtifactReference):
                raise ValueError("invalid native-result receipt")
        if self.selector.kind == SelectorKind.BYTE_RANGE and self.selector.value["end"] > self.artifact.size_bytes:
            raise ValueError("native-result byte range exceeds artifact")


def native_result_reference_from_mapping(value: Any) -> NativeResultReference:
    value = _mapping(value, "native-result reference")
    _fields(value, {"schema", "artifact", "selector", "parser_identity", "execution_reference",
                    "retention_receipt", "complete"})
    return NativeResultReference(
        artifact_reference_from_mapping(value["artifact"]), result_selector_from_mapping(value["selector"]),
        value["parser_identity"],
        artifact_reference_from_mapping(value["execution_reference"]) if value["execution_reference"] is not None else None,
        artifact_reference_from_mapping(value["retention_receipt"]) if value["retention_receipt"] is not None else None,
        value["complete"], value["schema"],
    )


@dataclass(frozen=True, slots=True)
class ProducerGap(_Record):
    gap_id: str
    code: str
    unit_id: str | None
    scope_id: str | None
    reason: str
    retryable: bool
    evidence_refs: tuple[ArtifactReference, ...] = ()
    schema: str = GAP_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != GAP_SCHEMA:
            raise ValueError("unsupported producer-gap schema")
        _hash(self.gap_id, "gap identity")
        GapCode(self.code)
        _text(self.reason, "gap reason")
        _boolean(self.retryable, "gap retryability")
        for value in (self.unit_id, self.scope_id):
            if value is not None:
                _text(value, "gap scope")
        if any(not isinstance(ref, ArtifactReference) for ref in self.evidence_refs):
            raise ValueError("invalid gap evidence reference")


@dataclass(frozen=True, slots=True)
class UnitOutcome(_Record):
    unit_id: str
    execution_status: str
    producer_status: str | None
    coverage_disposition: str
    result_reference: ArtifactReference | None
    status_reference: ArtifactReference | None
    gap_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.unit_id, "unit identity")
        ExecutionStatus(self.execution_status)
        CoverageDisposition(self.coverage_disposition)
        if self.producer_status is not None:
            _text(self.producer_status, "producer status")
        for value in (self.result_reference, self.status_reference):
            if value is not None and not isinstance(value, ArtifactReference):
                raise ValueError("invalid outcome reference")
        for identity in _strings(self.gap_ids, "gap identities"):
            _hash(identity, "gap identity")


@dataclass(frozen=True, slots=True)
class CoverageSummary(_Record):
    disposition: str
    gap_count: int
    retry_required: bool

    def __post_init__(self) -> None:
        CoverageDisposition(self.disposition)
        _integer(self.gap_count, "gap count")
        _boolean(self.retry_required, "retry required")
        if self.disposition == CoverageDisposition.COMPLETE and (self.gap_count or self.retry_required):
            raise ValueError("complete coverage cannot contain gaps or require retry")


@dataclass(frozen=True, slots=True)
class ObservationMetadata(_Record):
    observation_class: str
    record_kind: str
    scanner: str
    rule_id: str
    reported_severity: Mapping[str, str]
    evidence_refs: tuple[NativeResultReference, ...]
    gap_ids: tuple[str, ...]
    payload_schema: str
    schema: str = OBSERVATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != OBSERVATION_SCHEMA or self.observation_class not in _CLASSES:
            raise ValueError("invalid common observation schema or class")
        RecordKind(self.record_kind)
        for value in (self.scanner, self.rule_id, self.payload_schema):
            _text(value, "observation identity")
        severity = _mapping(self.reported_severity, "reported severity")
        _fields(severity, {"value", "native", "basis", "rule"})
        if severity["value"] not in _SEVERITIES:
            raise ValueError("unknown reported severity")
        for value in severity.values():
            _text(value, "reported severity")
        if any(not isinstance(ref, NativeResultReference) for ref in self.evidence_refs):
            raise ValueError("invalid observation evidence references")
        for identity in _strings(self.gap_ids, "observation gap identities"):
            _hash(identity, "observation gap identity")


def observation_metadata_from_mapping(value: Any) -> ObservationMetadata:
    value = _mapping(value, "common observation metadata")
    _fields(value, {"schema", "observation_class", "record_kind", "scanner", "rule_id",
                    "reported_severity", "evidence_refs", "gap_ids", "payload_schema"})
    if not isinstance(value["evidence_refs"], list):
        raise ValueError("observation evidence references must be a list")
    return ObservationMetadata(
        value["observation_class"], value["record_kind"], value["scanner"], value["rule_id"],
        value["reported_severity"],
        tuple(native_result_reference_from_mapping(item) for item in value["evidence_refs"]),
        _strings(value["gap_ids"], "observation gap identities"), value["payload_schema"], value["schema"],
    )


def gap_id(identity_projection: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical({"schema": GAP_SCHEMA,
                                     "identity": _mapping(identity_projection, "gap identity")})).hexdigest()


def input_set_sha256(identity_projection: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical({"schema": INPUTS_SCHEMA,
                                     "identity": _mapping(identity_projection, "input identity")})).hexdigest()


def handoff_input_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = ("resolved_config_sha256", "job_config_sha256", "source_fingerprint", "target_snapshot",
            "input_identity", "dataset_contract_sha256", "upstream_handoff_sha256",
            "implementation_identity", "schema_identity", "validation_identity", "tool_identity")
    projection = {key: value[key] for key in keys}
    manifest = value["input_manifest"]
    projection["input_manifest_sha256"] = manifest["sha256"] if manifest is not None else None
    return projection


def classify_producer_status(status: str | None, *, coverage_disposition: str | None = None,
                             has_gaps: bool = False) -> CoverageSummary:
    """Classify coverage, never vulnerability impact; unknown statuses fail closed."""
    _boolean(has_gaps, "has gaps")
    if status is not None:
        _text(status, "producer status")
    failed = {"FAILED", "GAP", "BLOCKED", "BLOCKED_BY_COMPILE", "INVALID_COMPILE_DATABASE",
              "UNAVAILABLE", "TIMED_OUT", "TIMEOUT", "OOM_KILLED"}
    if status in failed:
        disposition, retry = CoverageDisposition.UNAVAILABLE, True
    elif status in {"NOT_APPLICABLE", "SKIPPED_NA"}:
        disposition, retry = CoverageDisposition.NOT_APPLICABLE, False
    elif status in {"SKIPPED_POLICY", "CONFIGURED_DISABLED"}:
        disposition, retry = CoverageDisposition.SKIPPED_POLICY, False
    elif status in {"SUCCEEDED", "COMPLETE", "COMPLETED", None}:
        disposition, retry = CoverageDisposition.PARTIAL if has_gaps else CoverageDisposition.COMPLETE, False
    elif status in {"PARTIAL", "COMPLETED_WITH_GAPS", "DEGRADED"}:
        disposition, retry = CoverageDisposition.PARTIAL, False
    else:
        disposition, retry = CoverageDisposition.UNAVAILABLE, False
    if coverage_disposition is not None:
        explicit = CoverageDisposition(coverage_disposition)
        if disposition == CoverageDisposition.UNAVAILABLE and explicit != disposition:
            raise ValueError("coverage disposition contradicts unavailable producer")
        if explicit == CoverageDisposition.COMPLETE and (has_gaps or disposition != explicit):
            raise ValueError("complete coverage contradicts producer status")
        disposition = explicit
    if has_gaps and disposition == CoverageDisposition.COMPLETE:
        disposition = CoverageDisposition.PARTIAL
    return CoverageSummary(disposition, int(has_gaps), retry)


def decode_handoff(value: Any, *, run_id: str | None = None, job_id: str | None = None,
                   accepted_only: bool = True) -> dict[str, Any]:
    """Validate the common envelope structurally; byte admission is a separate step."""
    value = _mapping(value, "job handoff")
    required = {
        "schema", "run_id", "job_id", "attempt_id", "status", "completion_status", "execution_status",
        "outputs", "artifacts", "upstream_handoff_sha256", "resolved_config_sha256", "job_config_sha256",
        "source_fingerprint", "target_snapshot", "implementation_identity", "schema_identity",
        "validation_identity", "tool_identity", "input_identity", "input_manifest",
        "dataset_contract_sha256", "input_set_sha256", "coverage", "outcomes", "resolving_paths",
        "started_at", "completed_at",
    }
    if value.get("schema") != HANDOFF_SCHEMA or not required <= value.keys():
        raise ValueError("unsupported or incomplete job handoff")
    status = AdmissionStatus(value["status"])
    execution = ExecutionStatus(value["execution_status"])
    if accepted_only and status is not AdmissionStatus.ACCEPTED:
        raise ValueError("job handoff is not accepted")
    if status is AdmissionStatus.ACCEPTED and execution is ExecutionStatus.FAILED:
        raise ValueError("failed execution cannot have an accepted handoff")
    for key in ("run_id", "job_id", "attempt_id", "source_fingerprint", "target_snapshot",
                "completion_status", "implementation_identity", "schema_identity", "validation_identity",
                "started_at", "completed_at"):
        _text(value[key], key)
    for key, expected in (("run_id", run_id), ("job_id", job_id)):
        if expected is not None and value[key] != expected:
            raise ValueError(f"handoff {key} mismatch")
    if ("evidence_target_snapshot" in value
            and value["evidence_target_snapshot"] != value["target_snapshot"]):
        raise ValueError("contradictory handoff target identities")
    for key in ("resolved_config_sha256", "job_config_sha256", "dataset_contract_sha256", "input_set_sha256"):
        _hash(value[key], key)
    for key, digest in _mapping(value["upstream_handoff_sha256"], "upstream handoffs").items():
        _text(key, "upstream job identity")
        _hash(digest, "upstream handoff hash")
    _mapping(value["outputs"], "handoff outputs")
    _mapping(value["tool_identity"], "tool identity")
    paths = _mapping(value["resolving_paths"], "resolving paths")
    for path in paths.values():
        _path(path)
    coverage = _mapping(value["coverage"], "coverage summary")
    _fields(coverage, {"disposition", "gap_count", "retry_required"})
    CoverageSummary(**coverage)
    if not isinstance(value["artifacts"], list):
        raise ValueError("handoff artifacts must be a list")
    artifacts = [artifact_reference_from_mapping(item) for item in value["artifacts"]]
    by_path: dict[str, ArtifactReference] = {}
    for artifact in artifacts:
        if artifact.path in by_path:
            raise ValueError("duplicate handoff artifact path")
        by_path[artifact.path] = artifact
    for key in ("input_manifest", "outcomes"):
        if value[key] is None:
            if key == "outcomes" and status is AdmissionStatus.ACCEPTED:
                raise ValueError("accepted handoff requires outcome accounting")
            continue
        reference = artifact_reference_from_mapping(value[key])
        if by_path.get(reference.path) != reference:
            raise ValueError(f"handoff {key} is not bound in artifacts")
    if value["input_set_sha256"] != input_set_sha256(handoff_input_projection(value)):
        raise ValueError("handoff input set hash mismatch")
    return dict(value)


class UnitOutputContractError(ValueError):
    """A unit result violates the control-layer contract and must not be published."""


def validate_unit_output(result: Any, *, unit_id: str, strict_gaps: bool = False) -> None:
    """Check the control fields of one unit result before the runtime records it.

    ``terminal_status`` and every ``dispositions[].terminal_status`` must be a :class:`ProducerStatus`;
    ``coverage_disposition`` a :class:`CoverageDisposition` (or its upper-case alias); ``gaps`` an
    array whose members are nonempty text, structured records or ``producer-gap/1`` records, and only
    ``producer-gap/1`` records when ``strict_gaps`` is set. Payload keys are not inspected.
    """
    if not isinstance(result, Mapping):
        raise UnitOutputContractError(f"{unit_id}: unit result must be an object")
    status = result.get("terminal_status")
    if status is not None and (not isinstance(status, str) or status not in set(ProducerStatus)):
        raise UnitOutputContractError(
            f"{unit_id}: terminal_status {status!r} is not a ProducerStatus; "
            "record non-status facts in a payload field such as mode or availability")
    explicit = result.get("coverage_disposition")
    if explicit is not None and (not isinstance(explicit, str)
                                 or COVERAGE_ALIASES.get(explicit, explicit) not in set(CoverageDisposition)):
        raise UnitOutputContractError(f"{unit_id}: coverage_disposition {explicit!r} is not a CoverageDisposition")
    dispositions = result.get("dispositions", [])
    if not isinstance(dispositions, list):
        raise UnitOutputContractError(f"{unit_id}: dispositions must be an array")
    for index, disposition in enumerate(dispositions):
        if not isinstance(disposition, Mapping):
            raise UnitOutputContractError(f"{unit_id}: dispositions[{index}] must be a record")
        producer = disposition.get("terminal_status", disposition.get("disposition"))
        if producer is not None and (not isinstance(producer, str) or producer not in set(ProducerStatus)):
            raise UnitOutputContractError(
                f"{unit_id}: dispositions[{index}].terminal_status {producer!r} is not a ProducerStatus")
        scope = disposition.get("scope_id")
        if scope is not None and (not isinstance(scope, str) or not scope.strip()):
            raise UnitOutputContractError(f"{unit_id}: dispositions[{index}].scope_id must be nonempty text")
    gaps = result.get("gaps", [])
    if not isinstance(gaps, list):
        raise UnitOutputContractError(f"{unit_id}: gaps must be an array")
    for index, gap in enumerate(gaps):
        if isinstance(gap, Mapping) and gap.get("schema") == GAP_SCHEMA:
            try:
                ProducerGap(**{**gap, "evidence_refs": tuple(
                    artifact_reference_from_mapping(ref) for ref in gap.get("evidence_refs", ()))})
            except (TypeError, ValueError) as exc:
                raise UnitOutputContractError(f"{unit_id}: gaps[{index}] is not a valid producer-gap/1: {exc}") from exc
            continue
        if strict_gaps:
            raise UnitOutputContractError(
                f"{unit_id}: gaps[{index}] must be a producer-gap/1 record (appsec_review.interchange.producer_gap)")
        if isinstance(gap, str):
            if not gap.strip():
                raise UnitOutputContractError(f"{unit_id}: gaps[{index}] is empty text")
        elif not isinstance(gap, Mapping) or not gap:
            raise UnitOutputContractError(f"{unit_id}: gaps[{index}] must be nonempty text or a record")


def producer_gap(code: GapCode | str, reason: str, *, unit_id: str | None = None, scope_id: str | None = None,
                 retryable: bool = False, evidence_refs: Sequence[Mapping[str, Any]] = ()) -> dict[str, Any]:
    """Build one ``producer-gap/1`` record for a unit result's ``gaps`` array.

    The gap identity is derived from the unit, scope, code and reason, exactly as the runtime derives
    it for a free-text gap, so a job that migrates keeps stable gap ids.
    """
    code = GapCode(code)
    refs = tuple(artifact_reference_from_mapping(ref) for ref in evidence_refs)
    identity = {"unit_id": unit_id, "scope_id": scope_id, "code": str(code), "reason": reason}
    return ProducerGap(gap_id(identity), str(code), unit_id, scope_id, reason, bool(retryable), refs).as_dict()


def path_gap_records(unit_id: str, gaps: Iterable[Mapping[str, Any]], *,
                     failed_reasons: Iterable[str] = (), retryable_reasons: Iterable[str] = ()) -> list[dict[str, Any]]:
    """``{path, reason[, detail]}`` gaps (inventory, acquisition) as ``producer-gap/1`` records.

    A reason in ``failed_reasons`` is a ``producer_failed`` record, any other a
    ``producer_reported_gap``; ``retryable_reasons`` marks the ones an operator action resolves. The
    ``scope_id`` is the path, so a consumer can line records up with the files they concern.
    """
    failed, retryable = set(failed_reasons), set(retryable_reasons)
    records = []
    for gap in gaps:
        if not isinstance(gap, Mapping):
            raise ValueError("path gap must be a mapping with path and reason")
        reason = str(gap.get("reason") or "gap")
        path = str(gap.get("path") or ".")
        detail = str(gap.get("detail") or "").strip()
        code = GapCode.PRODUCER_FAILED if reason in failed else GapCode.PRODUCER_REPORTED_GAP
        records.append(producer_gap(code, f"{path}: {reason}" + (f": {detail}" if detail else ""),
                                    unit_id=unit_id, scope_id=path, retryable=reason in retryable))
    return records
