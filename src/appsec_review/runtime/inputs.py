"""Admission and observed reads at accepted evidence boundaries.

Verification walks are not semantic reads. Observations are made only by consumer readers,
never by manifest validators, and never assert model use or citation.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
import json
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Iterator, Mapping, ParamSpec, TypeVar

from appsec_review.runtime.contracts import (
    CoveragePolicy, InputChannel, InputRequirement, JobContract, MissingPolicy,
)
from appsec_review.runtime.datasets import DatasetDeclaration, read_dataset_contract, shard_owner
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import safe_path, verify_handoff

INPUT_ADMISSION_SCHEMA = "appsec-review/input-admission/1"
INPUT_READS_SCHEMA = "appsec-review/input-reads/1"
EXTERNAL_SELECTION_SCHEMA = "appsec-review/external-input-selection/1"


def external_selection(rows: list[dict[str, Any]]) -> str:
    return json.dumps({"schema": EXTERNAL_SELECTION_SCHEMA, "inputs": rows},
                      sort_keys=True, separators=(",", ":"))


def read_external_selection(document: object, contract: JobContract | None) -> dict[str, Any]:
    if (not isinstance(document, dict) or set(document) != {"schema", "inputs"}
            or document["schema"] != EXTERNAL_SELECTION_SCHEMA or not isinstance(document["inputs"], list)
            or contract is None):
        raise ValueError("external input selection requires fresh typed admission")
    declared = {(item.producer, item.output_kind, item.schema) for item in contract.inputs
                if item.channel is InputChannel.EXTERNAL}
    seen = set()
    for row in document["inputs"]:
        if not isinstance(row, dict) or set(row) != {
                "producer", "output_kind", "schema", "selector", "status", "identity", "reason"}:
            raise ValueError("invalid external input selection fields")
        if not all(isinstance(row[key], str) for key in ("producer", "output_kind", "schema", "selector", "status")):
            raise ValueError("invalid external input selection identity")
        key = row["producer"], row["output_kind"], row["schema"]
        if key not in declared or not row["selector"] or (*key, row["selector"]) in seen:
            raise ValueError("undeclared or duplicate external input selection")
        seen.add((*key, row["selector"]))
        if row["status"] == "available":
            if (not isinstance(row["identity"], dict) or not row["identity"] or row["reason"] is not None
                    or not all(isinstance(key, str) and isinstance(value, str)
                               for key, value in row["identity"].items())):
                raise ValueError("invalid supplied external identity")
        elif row["status"] in {"unavailable", "not_applicable"}:
            if row["identity"] is not None or not isinstance(row["reason"], str) or not row["reason"]:
                raise ValueError("external absence requires a named reason")
        else:
            raise ValueError("invalid external input selection status")
    if {key[:3] for key in seen} != declared:
        raise ValueError("external selection omits a declared source")
    return document


def selected_handoffs(job: Any, root: Path, supplied: Mapping[str, str] | None, *,
                      enabled: set[str] | None = None) -> dict[str, str]:
    """An untagged single-job launch selects only its declared currently accepted inputs."""
    if job.contract is None:
        return dict(supplied or {})
    if supplied is not None:
        unknown = set(supplied) - set(job.consumes)
        if unknown:
            raise ValueError(f"undeclared supplied handoffs for {job.job_id}: {sorted(unknown)}")
        for producer, digest in supplied.items():
            pointer = safe_path(root, f"data/jobs/{producer}/latest.json")
            if not pointer.is_file() or json.loads(pointer.read_bytes()).get("handoff_sha256") != digest:
                raise ValueError(f"supplied handoff is stale or unavailable: {producer}")
        from appsec_review.retrieval.core import _accepted_handoff
        result = dict(supplied)
        pending = list(result.items())
        visited = set()
        while pending:
            producer, digest = pending.pop()
            if producer in visited:
                continue
            visited.add(producer)
            handoff, _ = _accepted_handoff(root, producer, digest)
            verify_handoff(root, handoff)
            for name, value in handoff["upstream_handoff_sha256"].items():
                if name not in job.consumes:
                    continue
                if name in result and result[name] != value:
                    raise ValueError(f"conflicting supplied input lineages: {name}")
                if name not in result:
                    result[name] = value
                    pending.append((name, value))
        return result
    result = {}
    for producer in job.consumes:
        if enabled is not None and producer not in enabled:
            continue
        pointer = safe_path(root, f"data/jobs/{producer}/latest.json")
        if pointer.is_file():
            value = json.loads(pointer.read_bytes())
            result[producer] = value["handoff_sha256"]
    return result


def producer_contract(root: Path, handoff: Mapping[str, Any]) -> tuple[DatasetDeclaration, ...]:
    claim = json.loads(safe_path(root, handoff["resolving_paths"]["attempt"] + "/claim.json").read_bytes())
    document = claim["dataset_contract"]
    if document["sha256"] != handoff["dataset_contract_sha256"]:
        raise ValueError("producer dataset contract differs from accepted handoff")
    return read_dataset_contract(document, handoff["job_id"])[1]


def admit_inputs(context: Any, enabled: set[str]) -> dict[str, Any]:
    """Pin supply, absence and coverage separately from subsequent observed reads."""
    from appsec_review.retrieval.core import _accepted_handoff
    contract = context.contract
    if contract is None:
        return {"schema": INPUT_ADMISSION_SCHEMA, "requirements": []}
    handoffs = {}
    declarations = {}
    handoff: Mapping[str, Any] | None
    for producer, digest in sorted(context.upstream_handoffs.items()):
        if producer not in contract.consumes:
            raise ValueError(f"undeclared supplied producer: {producer}")
        handoff, _ = _accepted_handoff(context.run_root, producer, digest)
        verify_handoff(context.run_root, handoff)
        if handoff["target_snapshot"] not in {"none", context.evidence_target_snapshot}:
            raise ValueError(f"foreign target input: {producer}")
        handoffs[producer] = handoff
        declarations[producer] = {item.output_kind: item for item in producer_contract(context.run_root, handoff)}
    rows = []
    for requirement in contract.inputs:
        row: dict[str, Any] = {
            "channel": requirement.channel.value, "producer": requirement.producer,
            "output_kind": requirement.output_kind, "schema": requirement.schema,
            "authority": requirement.authority.value, "available": None, "supplied": False,
            "read": False, "cited": None,
        }
        if requirement.channel is not InputChannel.HANDOFF:
            row["status"] = "requires_channel_reader"
            if requirement.channel is InputChannel.EXTERNAL and context.external_input_selection is not None:
                selections = [item for item in context.external_input_selection["inputs"]
                              if (item["producer"], item["output_kind"]) == (
                                  requirement.producer, requirement.output_kind)]
                supplied = any(item["status"] == "available" for item in selections)
                missing = any(item["status"] == "unavailable" for item in selections)
                row.update(available=supplied, supplied=supplied, selections=selections,
                           status="partial" if supplied and missing else "supplied" if supplied else
                           "gap" if missing else "not_applicable")
                if not supplied and requirement.required(enabled) and requirement.missing is MissingPolicy.REJECT:
                    raise ValueError(f"required external input unavailable: {requirement.producer}/{requirement.output_kind}")
            rows.append(row)
            continue
        handoff = handoffs.get(requirement.producer)
        available = False
        if handoff is not None:
            if requirement.output_kind == "handoff":
                if handoff["schema"] != requirement.schema:
                    raise ValueError(f"input envelope schema mismatch: {requirement.producer}")
                available = True
            else:
                declaration = declarations[requirement.producer].get(requirement.output_kind)
                if declaration is None or declaration.schema != requirement.schema:
                    raise ValueError(f"producer output contract mismatch: {requirement.producer}/{requirement.output_kind}")
                if declaration.authority is None or declaration.authority != requirement.authority:
                    raise ValueError(f"producer evidence authority mismatch: {requirement.producer}/{requirement.output_kind}")
                # Declaration compatibility is distinct from produced availability. The accepted
                # producer's artifacts/shards, not graph ancestry, establish an emitted dataset.
                available = _has_output(context.run_root, handoff, declaration,
                                        tuple(declarations[requirement.producer].values()))
            row.update(handoff_sha256=context.upstream_handoffs[requirement.producer],
                       attempt_id=handoff["attempt_id"], target_snapshot=handoff["target_snapshot"],
                       coverage=dict(handoff["coverage"]))
            coverage = handoff["coverage"]
            if requirement.coverage is CoveragePolicy.REQUIRE_COMPLETE and coverage["disposition"] != "complete":
                raise ValueError(f"input coverage is not complete: {requirement.producer}")
            if requirement.coverage is CoveragePolicy.REQUIRE_NONRETRIABLE and coverage["retry_required"]:
                raise ValueError(f"input coverage requires retry: {requirement.producer}")
        row.update(available=available if handoff is not None else None, supplied=available)
        if not available:
            if requirement.required(enabled) and requirement.missing is MissingPolicy.REJECT:
                raise ValueError(f"required input unavailable: {requirement.producer}/{requirement.output_kind}")
            row["status"] = "not_applicable" if requirement.missing is MissingPolicy.NOT_APPLICABLE else "gap"
        else:
            row["status"] = "supplied"
        rows.append(row)
    return {"schema": INPUT_ADMISSION_SCHEMA, "contract_sha256": contract.document()["sha256"],
            "requirements": rows}


def _has_output(root: Path, handoff: Mapping[str, Any], declaration: DatasetDeclaration,
                declarations: tuple[DatasetDeclaration, ...]) -> bool:
    from appsec_review.indexing.inventory import compile_glob
    for ref in handoff["artifacts"]:
        if any(compile_glob(pattern).fullmatch(ref["path"]) for pattern in declaration.artifacts):
            return True
    if declaration.indexes:
        from appsec_review.indexing.store import handoff_manifests
        return any(shard.get("producer", {}).get("job") == handoff["job_id"]
                   and shard_owner(declarations, shard["name"], shard.get("shard_id", "default")) == declaration
                   for manifest in handoff_manifests(root, handoff)
                   for shard in manifest["document"]["indexes"])
    return False


@dataclass
class InputReads:
    context: Any
    records: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    lock: RLock = field(default_factory=RLock)
    producers: dict[str, tuple[Mapping[str, Any], tuple[DatasetDeclaration, ...]]] = field(default_factory=dict)
    violation: str | None = None

    def check(self) -> None:
        if self.violation is not None:
            raise ValueError(f"input contract violation: {self.violation}")

    def producer(self, producer: str) -> tuple[Mapping[str, Any], tuple[DatasetDeclaration, ...]]:
        from appsec_review.retrieval.core import _accepted_handoff
        with self.lock:
            if producer not in self.producers:
                digest = self.context.upstream_handoffs.get(producer)
                if digest is None:
                    raise ValueError(f"undeclared or unsupplied shard producer: {producer}")
                handoff, _ = _accepted_handoff(self.context.run_root, producer, digest)
                self.producers[producer] = handoff, producer_contract(self.context.run_root, handoff)
            return self.producers[producer]

    def requirement(self, producer: str, output_kind: str, channel: InputChannel) -> InputRequirement:
        contract = self.context.contract
        if not isinstance(contract, JobContract):
            raise ValueError("input reader has no typed contract")
        for item in contract.inputs:
            if (item.producer, item.output_kind, item.channel) == (producer, output_kind, channel):
                return item
        raise ValueError(f"undeclared consumption by {self.context.config.job_id}: {producer}/{output_kind}")

    def record(self, requirement: InputRequirement, identity: Mapping[str, Any]) -> None:
        if {"producer", "output_kind", "schema", "channel", "authority", "read", "cited"} & identity.keys():
            raise ValueError("input identity cannot override observation authority")
        value = {"producer": requirement.producer, "output_kind": requirement.output_kind,
                 "schema": requirement.schema, "channel": requirement.channel.value,
                 "authority": requirement.authority.value, "read": True, "cited": None, **identity}
        key = json.dumps(value, sort_keys=True)
        with self.lock:
            self.records[key] = value

    def document(self) -> dict[str, Any]:
        with self.lock:
            return {"schema": INPUT_READS_SCHEMA, "reads": [self.records[key] for key in sorted(self.records)],
                    "citation_observation": "not_observed"}


_READS: ContextVar[InputReads | None] = ContextVar("job_input_reads", default=None)


@contextmanager
def input_read_scope(context: Any) -> Iterator[InputReads | None]:
    if getattr(context, "contract", None) is None:
        yield None
        return
    current = _READS.get()
    if current is not None and current.context is context:
        yield current
        return
    reads = InputReads(context)
    token = _READS.set(reads)
    try:
        yield reads
        reads.check()
    finally:
        _READS.reset(token)


P = ParamSpec("P")
T = TypeVar("T")


def _read_boundary(function: Callable[P, T]) -> Callable[P, T]:
    @wraps(function)
    def checked(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return function(*args, **kwargs)
        except (ValueError, OSError, KeyError, TypeError) as error:
            reads = _READS.get()
            if reads is not None:
                with reads.lock:
                    if reads.violation is None:
                        reads.violation = str(error)
            raise
    return checked


def check_input_reads() -> None:
    reads = _READS.get()
    if reads is not None:
        reads.check()


@_read_boundary
def input_shard_owner(root: Path, shard: Mapping[str, Any]) -> DatasetDeclaration:
    """Resolve source-view ownership against the same pinned producer used by observed reads."""
    producer = shard.get("producer", {}).get("job")
    reads = _READS.get()
    if reads is not None:
        if Path(root).resolve() != reads.context.run_root.resolve():
            raise ValueError("input producer contract belongs to a foreign run")
        declarations = reads.producer(producer)[1]
    else:
        from appsec_review.indexing.store import accepted_handoff
        accepted = accepted_handoff(root, producer)
        if accepted is None:
            raise ValueError(f"source shard producer has no accepted contract: {producer}")
        declarations = producer_contract(root, accepted.handoff)
    return shard_owner(declarations, shard["name"], shard.get("shard_id", "default"))


@_read_boundary
def observe_handoff(root: Path, handoff: Mapping[str, Any]) -> None:
    reads = _READS.get()
    if reads is None or handoff["job_id"] == reads.context.config.job_id:
        return
    context = reads.context
    if Path(root).resolve() != context.run_root.resolve():
        raise ValueError("consumed handoff belongs to a foreign run")
    producer = handoff["job_id"]
    requirement = reads.requirement(producer, "handoff", InputChannel.HANDOFF)
    expected = context.upstream_handoffs.get(producer)
    path = safe_path(root, handoff["resolving_paths"]["attempt"] + "/handoff.json")
    if expected is None or file_sha256(path) != expected:
        raise ValueError(f"consumed handoff is not the supplied immutable input: {producer}")
    reads.record(requirement, {"handoff_sha256": expected, "attempt_id": handoff["attempt_id"],
                               "target_snapshot": handoff["target_snapshot"], "coverage": dict(handoff["coverage"])})


@_read_boundary
def observe_shard(root: Path, shard: Mapping[str, Any]) -> None:
    reads = _READS.get()
    if reads is None:
        return
    producer = shard.get("producer", {}).get("job")
    if producer == reads.context.config.job_id:
        return
    context = reads.context
    if Path(root).resolve() != context.run_root.resolve():
        raise ValueError("consumed shard belongs to a foreign run")
    digest = context.upstream_handoffs.get(producer)
    if digest is None:
        raise ValueError(f"undeclared or unsupplied shard producer: {producer}")
    handoff, _declarations = reads.producer(producer)
    owned = input_shard_owner(root, shard)
    requirement = reads.requirement(producer, owned.output_kind, InputChannel.HANDOFF)
    if requirement.schema != owned.schema or requirement.authority != owned.authority:
        raise ValueError("consumed dataset schema or authority differs from input contract")
    relative, sha = shard["relative_path"], shard["sha256"]
    if not any(ref["path"] == relative and ref["sha256"] == sha for ref in handoff["artifacts"]):
        raise ValueError("consumed shard is not bound to supplied producer output")
    from appsec_review.storage.validation import observed_digest
    if observed_digest(root, safe_path(root, relative)) != sha:
        raise ValueError("consumed shard bytes changed")
    reads.record(requirement, {"path": relative, "sha256": sha, "handoff_sha256": digest,
                               "attempt_id": handoff["attempt_id"], "target_snapshot": handoff["target_snapshot"]})


@_read_boundary
def observe_external(root: Path, producer: str, output_kind: str, schema: str,
                     identity: Mapping[str, Any], *, channel: InputChannel = InputChannel.EXTERNAL) -> None:
    reads = _READS.get()
    if reads is None:
        return
    if root.resolve() != reads.context.run_root.resolve():
        raise ValueError("external input observation belongs to a foreign run")
    requirement = reads.requirement(producer, output_kind, channel)
    if schema != requirement.schema:
        raise ValueError("external input schema differs from contract")
    if channel is InputChannel.EXTERNAL:
        selected = reads.context.external_input_selection
        if selected is None:
            if not reads.context.contract.always_execute:
                raise ValueError("external reads require a claimed immutable selection")
        elif not any(
                (row["producer"], row["output_kind"], row["schema"]) == (producer, output_kind, schema)
                and row["status"] == "available"
                and all(identity.get(key) == value for key, value in row["identity"].items())
                for row in selected["inputs"]):
            raise ValueError("external input differs from its claimed immutable selection")
    reads.record(requirement, identity)


@_read_boundary
def observe_output(root: Path, producer: str, output_kind: str, reference: Mapping[str, Any]) -> None:
    reads = _READS.get()
    if reads is None:
        return
    if root.resolve() != reads.context.run_root.resolve():
        raise ValueError("consumed output belongs to a foreign run")
    requirement = reads.requirement(producer, output_kind, InputChannel.HANDOFF)
    handoff, declarations = reads.producer(producer)
    if not any(item.output_kind == output_kind and item.schema == requirement.schema
               and item.authority == requirement.authority for item in declarations):
        raise ValueError("consumed output schema differs from input contract")
    path, sha = reference["path"], reference["sha256"]
    if not any(item["path"] == path and item["sha256"] == sha for item in handoff["artifacts"]):
        raise ValueError("consumed output is not bound to supplied producer")
    if file_sha256(safe_path(root, path)) != sha:
        raise ValueError("consumed output bytes changed")
    reads.record(requirement, {"path": path, "sha256": sha,
                               "handoff_sha256": reads.context.upstream_handoffs[producer],
                               "attempt_id": handoff["attempt_id"], "target_snapshot": handoff["target_snapshot"]})


@_read_boundary
def decode_consumed_handoff(value: Any, **expected: Any) -> dict[str, Any]:
    """Compatibility wiring for job-specific readers pending the shared artifact API."""
    from appsec_review.interchange import decode_handoff
    handoff = decode_handoff(value, **expected)
    reads = _READS.get()
    if reads is not None:
        observe_handoff(reads.context.run_root, handoff)
    return handoff


def read_input_observations(root: Path, handoff: Mapping[str, Any]) -> dict[str, Any] | None:
    """Hash-bound unit receipts attest reader access; old attempts stay unknown."""
    from appsec_review.storage.shared import verify_reference
    prefix = handoff["resolving_paths"]["attempt"] + "/steps/"
    records = []
    observed = False
    for ref in handoff["artifacts"]:
        if not ref["path"].startswith(prefix) or not ref["path"].endswith("/status.json"):
            continue
        document = json.loads(verify_reference(root, ref).read_bytes()).get("input_consumption")
        if document is None:
            continue
        if (set(document) != {"schema", "reads", "citation_observation"}
                or document["schema"] != INPUT_READS_SCHEMA or not isinstance(document["reads"], list)
                or document["citation_observation"] != "not_observed"):
            raise ValueError("invalid input read observation receipt")
        observed = True
        records.extend(document["reads"])
    return {"schema": INPUT_READS_SCHEMA, "reads": records,
            "citation_observation": "not_observed"} if observed else None


def verify_external_inputs(context: Any, artifacts: list[dict[str, Any]]) -> None:
    """A required channel cannot be accepted without its validated reader receipt."""
    contract = context.contract
    if contract is None:
        return
    from appsec_review.runtime.selection import resolved_job_is_enabled
    document = json.loads(safe_path(context.run_root, "data/configuration/resolved.json").read_bytes())
    enabled = {name for name, value in document["jobs"].items() if resolved_job_is_enabled(name, value)}
    required = [item for item in contract.inputs if item.channel is not InputChannel.HANDOFF
                and item.required(enabled) and item.missing is MissingPolicy.REJECT]
    if not required:
        return
    observations = read_input_observations(context.run_root, {
        "resolving_paths": {"attempt": context.attempt_root.relative_to(context.run_root).as_posix()},
        "artifacts": artifacts})
    supplied = {(item["channel"], item["producer"], item["output_kind"])
                for item in observations["reads"]} if observations is not None else set()
    for requirement in required:
        if requirement.key not in supplied:
            raise ValueError(f"required external input was not validated: {requirement.producer}/{requirement.output_kind}")


def feed_input_identity(target: Path | None, run_root: Path, repository_root: Path) -> str:
    """Re-probe bounded local snapshot selections, without maintenance or network execution."""
    from appsec_review.jobs.job_review_data_indexing.job import _resolved_document
    from appsec_review.jobs.job_third_party_data_sync.publication import verify_current
    from appsec_review.storage.feed_provenance import STEPS
    document = _resolved_document(run_root)
    steps = document["jobs"].get("job_third_party_data_sync", {}).get("steps", {})
    rows: list[dict[str, Any]] = []
    for feed, step in sorted(STEPS.items()):
        row: dict[str, Any] = {"producer": "job_third_party_data_sync", "output_kind": "feed_snapshot",
               "schema": "appsec-review/public-feed-use/1", "selector": feed,
               "status": "unavailable", "identity": None, "reason": "feed root is not configured"}
        rows.append(row)
        configured = steps.get(step, {}).get("settings", {}).get("feed_root")
        if not configured:
            continue
        path = Path(configured)
        path = path if path.is_absolute() else repository_root / path
        try:
            relative = path.relative_to(repository_root).as_posix()
        except ValueError:
            raise ValueError("external feed selection is outside repository data") from None
        if not relative.startswith("data/"):
            raise ValueError("external feed selection is outside repository data")
        path = safe_path(repository_root, relative)
        try:
            value = verify_current(path, feed)
        except (OSError, ValueError, KeyError, TypeError) as error:
            row["reason"] = type(error).__name__
        else:
            row.update(status="available", identity={"feed_id": feed, "manifest_sha256": value["manifest_sha256"],
                                                    "snapshot_id": value["snapshot_id"]}, reason=None)
    return external_selection(rows)
