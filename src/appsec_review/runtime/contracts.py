"""Closed job input and dispatch contracts; declarations are not consumption evidence."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import StrEnum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from appsec_review.runtime.datasets import DatasetDeclaration, EvidenceAuthority as EvidenceAuthority

CONTRACT_SCHEMA = "appsec-review/job-contract/1"
_NAME = re.compile(r"[a-z][a-z0-9_]{0,127}")


class DispatchClass(StrEnum):
    REVIEW_GRAPH = "review_graph"
    INTERNAL_TRANSACTION = "internal_transaction"
    MAINTENANCE = "maintenance"


class TargetAccess(StrEnum):
    CHECKOUT = "checkout"
    ACCEPTED_EVIDENCE = "accepted_evidence"
    NONE = "none"


class InputChannel(StrEnum):
    HANDOFF = "handoff"
    EXTERNAL = "external"
    TRANSACTION = "transaction"


class Availability(StrEnum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    WHEN_ENABLED = "when_producer_enabled"
    WHEN_DECLARED = "when_output_declared"


class MissingPolicy(StrEnum):
    REJECT = "reject"
    GAP = "gap"
    NOT_APPLICABLE = "not_applicable"


class CoveragePolicy(StrEnum):
    ALLOW_PARTIAL = "allow_partial"
    REQUIRE_COMPLETE = "require_complete"
    REQUIRE_NONRETRIABLE = "require_nonretriable"


@dataclass(frozen=True, slots=True)
class InputRequirement:
    producer: str
    output_kind: str
    schema: str
    authority: EvidenceAuthority = EvidenceAuthority.PRODUCER_EVIDENCE
    availability: Availability = Availability.OPTIONAL
    missing: MissingPolicy = MissingPolicy.GAP
    coverage: CoveragePolicy = CoveragePolicy.ALLOW_PARTIAL
    channel: InputChannel = InputChannel.HANDOFF

    def __post_init__(self) -> None:
        for name in ("producer", "output_kind"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _NAME.fullmatch(value):
                raise ValueError(f"invalid input {name}")
        if not isinstance(self.schema, str) or not self.schema.strip():
            raise ValueError("input requires an exact schema")
        for name, enum in (("authority", EvidenceAuthority), ("availability", Availability),
                           ("missing", MissingPolicy), ("coverage", CoveragePolicy), ("channel", InputChannel)):
            if not isinstance(getattr(self, name), enum):
                raise ValueError(f"invalid input {name}")
        if self.availability is Availability.REQUIRED and self.missing is not MissingPolicy.REJECT:
            raise ValueError("required inputs must reject absence")
        if self.availability is Availability.WHEN_DECLARED and (
                self.channel is not InputChannel.HANDOFF or self.output_kind == "handoff"):
            raise ValueError("when_output_declared requires a non-envelope handoff dataset")
        if self.channel is not InputChannel.HANDOFF and self.coverage is not CoveragePolicy.ALLOW_PARTIAL:
            raise ValueError("coverage guarantees require an accepted producer coverage contract")

    @property
    def key(self) -> tuple[str, str, str]:
        return self.channel.value, self.producer, self.output_kind

    def required(self, enabled: set[str]) -> bool:
        return self.availability is Availability.REQUIRED or (
            self.availability is Availability.WHEN_ENABLED and self.producer in enabled)


@dataclass(frozen=True, slots=True)
class JobContract:
    inputs: tuple[InputRequirement, ...] = ()
    schedule_after: tuple[str, ...] = ()
    dispatch: DispatchClass = DispatchClass.REVIEW_GRAPH
    target_access: TargetAccess = TargetAccess.CHECKOUT
    always_execute: bool = False
    propagate_handoff: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.dispatch, DispatchClass) or not isinstance(self.target_access, TargetAccess):
            raise ValueError("invalid dispatch class or target access")
        if type(self.always_execute) is not bool or type(self.propagate_handoff) is not bool:
            raise ValueError("invalid dispatch flags")
        if not isinstance(self.inputs, tuple) or any(not isinstance(item, InputRequirement) for item in self.inputs):
            raise ValueError("inputs must be typed immutable requirements")
        keys = [item.key for item in self.inputs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate input requirement")
        if (not isinstance(self.schedule_after, tuple)
                or any(not isinstance(item, str) or not _NAME.fullmatch(item) for item in self.schedule_after)
                or len(self.schedule_after) != len(set(self.schedule_after))):
            raise ValueError("invalid scheduling dependencies")
        if self.dispatch is not DispatchClass.REVIEW_GRAPH and self.schedule_after:
            raise ValueError("non-graph dispatch cannot declare scheduling edges")
        if self.dispatch is DispatchClass.INTERNAL_TRANSACTION and self.propagate_handoff:
            raise ValueError("internal transactions cannot propagate graph handoffs")

    @property
    def consumes(self) -> tuple[str, ...]:
        return tuple(sorted({item.producer for item in self.inputs if item.channel is InputChannel.HANDOFF}))

    def validate(self, job_id: str) -> None:
        if job_id in self.consumes or job_id in self.schedule_after:
            raise ValueError(f"job cannot depend on itself: {job_id}")

    def document(self) -> dict[str, Any]:
        body = {"schema": CONTRACT_SCHEMA, **asdict(self)}
        # JSON shape (arrays, enum strings) is identical in memory and on disk.
        body = json.loads(json.dumps(body))
        return {**body, "sha256": _digest(body)}


def _digest(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_job_contract(document: object) -> JobContract:
    """Read only this version, rejecting unknown fields and tampered historical bytes."""
    if not isinstance(document, Mapping):
        raise ValueError("job contract must be an object")
    body = {key: value for key, value in document.items() if key != "sha256"}
    if (set(body) != {"schema", *(field.name for field in fields(JobContract))}
            or body.get("schema") != CONTRACT_SCHEMA or document.get("sha256") != _digest(body)):
        raise ValueError("invalid job contract identity")
    if not isinstance(body["inputs"], list) or not isinstance(body["schedule_after"], list):
        raise ValueError("invalid job contract input or scheduling list")
    requirements = []
    for record in body["inputs"]:
        if not isinstance(record, dict) or set(record) != {field.name for field in fields(InputRequirement)}:
            raise ValueError("invalid input requirement fields")
        values = dict(record)
        for key, enum in (("authority", EvidenceAuthority), ("availability", Availability),
                          ("missing", MissingPolicy), ("coverage", CoveragePolicy), ("channel", InputChannel)):
            values[key] = enum(values[key])
        requirements.append(InputRequirement(**values))
    return JobContract(
        inputs=tuple(requirements), schedule_after=tuple(body["schedule_after"]),
        dispatch=DispatchClass(body["dispatch"]), target_access=TargetAccess(body["target_access"]),
        always_execute=body["always_execute"], propagate_handoff=body["propagate_handoff"])


def accepted_inputs(producer: str, datasets: Sequence[DatasetDeclaration], *,
                    availability: Availability = Availability.OPTIONAL,
                    missing: MissingPolicy = MissingPolicy.GAP,
                    authority: EvidenceAuthority = EvidenceAuthority.PRODUCER_EVIDENCE,
                    output_kinds: Sequence[str] | None = None) -> tuple[InputRequirement, ...]:
    """Bind the producer envelope and explicitly selected output declarations, never ancestry.

    Optional per-scope outputs remain optional even when the envelope is required. Their observed
    absence/partial/retriable coverage is preserved, not promoted to complete producer coverage.
    """
    from appsec_review.interchange import HANDOFF_SCHEMA
    selected = tuple(datasets) if output_kinds is None else tuple(
        item for item in datasets if item.output_kind in output_kinds)
    if output_kinds is not None and {item.output_kind for item in selected} != set(output_kinds):
        raise ValueError(f"unknown input output kind for {producer}")
    return (
        InputRequirement(producer, "handoff", HANDOFF_SCHEMA, authority, availability, missing),
        *(InputRequirement(producer, item.output_kind, item.schema,
                           item.authority if item.authority is not None else authority) for item in selected),
    )
